use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use ovpn_client::Session;
use ovpn_netstack::{IpVersion, Stack, StackError, StackOwner};
use tokio::sync::mpsc;
use tokio::time;

const PROBE_ADDRESS: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);
const PROBE_PORT: u16 = 443;
const PROBE_SAMPLES: usize = 3;
const MIN_SUCCESSFUL_SAMPLES: usize = 2;
const PROBE_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
// HTTPS endpoints operated independently of the latency target (Cloudflare).
const HEALTH_TARGETS: [Ipv4Addr; 2] = [Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(9, 9, 9, 9)];
const MAX_FAILED_HEALTH_CHECKS: u8 = 3;
const DNS_HEALTH_NAME: &str = "one.one.one.one";

pub(super) const PROBE_INTERVAL: Duration = Duration::from_secs(60);

pub(super) struct LatencyScore {
    pub median: Duration,
    pub elapsed: Duration,
    pub successful_samples: usize,
    pub measured_at: Instant,
}

pub(super) struct ProbeReport {
    pub score: Result<LatencyScore>,
    pub health: HealthAssessment,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Reachability {
    Reachable,
    Unreachable,
    Inconclusive,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct HealthAssessment {
    tcp: Reachability,
    dns: Reachability,
}

impl HealthAssessment {
    fn reachability(self) -> Reachability {
        use Reachability::{Inconclusive, Reachable, Unreachable};
        match (self.tcp, self.dns) {
            (Unreachable, _) | (_, Unreachable) => Unreachable,
            (Reachable, Reachable) => Reachable,
            _ => Inconclusive,
        }
    }
}

/// Lives with one host session. An error uses the worker's normal teardown,
/// standby selection, and retry path; routing owns no separate health protocol.
#[derive(Default)]
pub(super) struct SessionHealth {
    failed_checks: u8,
}

impl SessionHealth {
    pub(super) fn record(&mut self, health: HealthAssessment) -> Result<()> {
        match health.reachability() {
            Reachability::Reachable => {
                if self.failed_checks > 0 {
                    tracing::info!(
                        previous_failures = self.failed_checks,
                        "VPN TCP and DNS health recovered"
                    );
                }
                self.failed_checks = 0;
            }
            Reachability::Unreachable => {
                self.failed_checks += 1;
                tracing::warn!(tcp = ?health.tcp, dns = ?health.dns,
                    consecutive_failures = self.failed_checks, threshold = MAX_FAILED_HEALTH_CHECKS,
                    "VPN health assessment failed");
            }
            Reachability::Inconclusive => {
                tracing::debug!(tcp = ?health.tcp, dns = ?health.dns,
                    consecutive_failures = self.failed_checks, "VPN health assessment inconclusive");
                return Ok(());
            }
        }
        if self.failed_checks >= MAX_FAILED_HEALTH_CHECKS {
            bail!(
                "VPN health failed repeatedly (TCP: {:?}, DNS: {:?})",
                health.tcp,
                health.dns
            );
        }
        Ok(())
    }
}

/// A failed latency target alone must not evict a working VPN host.
pub(super) async fn check_health(stack: &Stack) -> ProbeReport {
    assess_health(check_tcp(stack), check_dns(stack)).await
}

async fn assess_health(
    tcp: impl Future<Output = (Result<LatencyScore>, Reachability)>,
    dns: impl Future<Output = Result<()>>,
) -> ProbeReport {
    let ((score, tcp), dns) = tokio::join!(tcp, dns);
    let dns = match dns {
        Ok(()) => Reachability::Reachable,
        Err(error) if local_capacity_error(&error) => Reachability::Inconclusive,
        Err(_) => Reachability::Unreachable,
    };
    ProbeReport {
        score,
        health: HealthAssessment { tcp, dns },
    }
}

async fn check_tcp(stack: &Stack) -> (Result<LatencyScore>, Reachability) {
    let score = measure(stack).await;
    let reachability = if score.is_ok() {
        Reachability::Reachable
    } else {
        let check = |address| async move {
            match time::timeout(
                PROBE_CONNECT_TIMEOUT,
                connect_once(stack, SocketAddr::new(IpAddr::V4(address), PROBE_PORT)),
            )
            .await
            {
                Ok(Ok(_)) => Reachability::Reachable,
                Ok(Err(error)) if local_capacity_error(&error) => Reachability::Inconclusive,
                _ => Reachability::Unreachable,
            }
        };
        let (first, second) = tokio::join!(check(HEALTH_TARGETS[0]), check(HEALTH_TARGETS[1]));
        match (first, second) {
            (Reachability::Reachable, _) | (_, Reachability::Reachable) => Reachability::Reachable,
            (Reachability::Unreachable, Reachability::Unreachable) => Reachability::Unreachable,
            _ => Reachability::Inconclusive,
        }
    };
    (score, reachability)
}

#[tracing::instrument(name = "vpn_dns_health", skip_all, fields(stack_id = stack.id(), host = DNS_HEALTH_NAME))]
async fn check_dns(stack: &Stack) -> Result<()> {
    stack
        .resolve(DNS_HEALTH_NAME, IpVersion::V4)
        .await
        .context("VPN DNS health lookup failed")?;
    Ok(())
}

fn local_capacity_error(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        matches!(
            cause.downcast_ref::<StackError>(),
            Some(StackError::ConnectionLimit)
        ) || cause.downcast_ref::<std::io::Error>().is_some_and(|error| {
            matches!(
                error
                    .get_ref()
                    .and_then(|error| error.downcast_ref::<StackError>()),
                Some(StackError::ConnectionLimit)
            )
        })
    })
}

pub(super) async fn measure(stack: &Stack) -> Result<LatencyScore> {
    let started = Instant::now();
    let destination = SocketAddr::new(IpAddr::V4(PROBE_ADDRESS), PROBE_PORT);
    let mut samples = Vec::with_capacity(PROBE_SAMPLES);
    for sample in 0..PROBE_SAMPLES {
        match time::timeout(PROBE_CONNECT_TIMEOUT, connect_once(stack, destination)).await {
            Ok(Ok(latency)) => {
                tracing::debug!(stack_id = stack.id(), %destination, sample, ?latency, "VPN latency probe sample");
                samples.push(latency);
            }
            Ok(Err(error)) => {
                if local_capacity_error(&error) {
                    return Err(error);
                }
                tracing::warn!(stack_id = stack.id(), %destination, sample, %error, "VPN latency probe sample failed");
            }
            Err(_) => {
                tracing::warn!(stack_id = stack.id(), %destination, sample, ?PROBE_CONNECT_TIMEOUT, "VPN latency probe sample timed out");
            }
        }
    }
    if samples.len() < MIN_SUCCESSFUL_SAMPLES {
        bail!("too few successful VPN latency probe samples");
    }
    samples.sort_unstable();
    let median = if samples.len() % 2 == 0 {
        samples[samples.len() / 2 - 1].saturating_add(samples[samples.len() / 2]) / 2
    } else {
        samples[samples.len() / 2]
    };
    Ok(LatencyScore {
        median,
        elapsed: started.elapsed(),
        successful_samples: samples.len(),
        measured_at: Instant::now(),
    })
}

pub(super) async fn assess_readiness_with_session(
    session: &mut Session,
    owner: &StackOwner,
    outbound: &mut mpsc::Receiver<Vec<u8>>,
) -> Result<LatencyScore> {
    let stack = owner.client();
    let probe = async {
        let (score, ()) = tokio::try_join!(measure(&stack), check_dns(&stack))?;
        Ok(score)
    };
    tokio::pin!(probe);
    loop {
        tokio::select! {
            result = &mut probe => return result,
            packet = outbound.recv() => {
                let packet = packet.context("VPN packet output channel closed during probe")?;
                session.send_packet(&packet).await?;
            }
            received = session.step() => {
                if let Some(packet) = received? {
                    owner.packet(packet)?;
                }
            }
        }
    }
}

async fn connect_once(stack: &Stack, destination: SocketAddr) -> Result<Duration> {
    let started = Instant::now();
    let _connection = stack
        .connect(destination)
        .await
        .context("cannot connect tunneled probe")?;
    Ok(started.elapsed())
}

#[cfg(test)]
mod tests;
