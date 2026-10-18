use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use ovpn_client::Session;
use ovpn_netstack::{Stack, StackError, StackOwner};
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

pub(super) const PROBE_INTERVAL: Duration = Duration::from_secs(60);

pub(super) struct LatencyScore {
    pub median: Duration,
    pub elapsed: Duration,
    pub successful_samples: usize,
    pub measured_at: Instant,
}

pub(super) struct ProbeReport {
    pub score: Result<LatencyScore>,
    pub reachability: Reachability,
}

#[derive(Clone, Copy)]
pub(super) enum Reachability {
    Reachable,
    Unreachable,
    Inconclusive,
}

/// Lives with one host session. An error uses the worker's normal teardown,
/// standby selection, and retry path; routing owns no separate health protocol.
#[derive(Default)]
pub(super) struct SessionHealth {
    failed_checks: u8,
}

impl SessionHealth {
    pub(super) fn record(&mut self, reachability: Reachability) -> Result<()> {
        match reachability {
            Reachability::Reachable => self.failed_checks = 0,
            Reachability::Unreachable => self.failed_checks += 1,
            Reachability::Inconclusive => return Ok(()),
        }
        if self.failed_checks >= MAX_FAILED_HEALTH_CHECKS {
            bail!("VPN internet reachability failed repeatedly");
        }
        Ok(())
    }
}

/// A failed latency target alone must not evict a working VPN host.
pub(super) async fn check_health(stack: &Stack) -> ProbeReport {
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
    ProbeReport {
        score,
        reachability,
    }
}

fn local_capacity_error(error: &anyhow::Error) -> bool {
    matches!(
        error.downcast_ref::<StackError>(),
        Some(StackError::ConnectionLimit)
    )
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

pub(super) async fn measure_with_session(
    session: &mut Session,
    owner: &StackOwner,
    outbound: &mut mpsc::Receiver<Vec<u8>>,
) -> Result<LatencyScore> {
    let stack = owner.client();
    let probe = measure(&stack);
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
mod tests {
    use super::*;

    #[test]
    fn only_repeated_confirmed_failures_end_a_session() {
        use Reachability::{Inconclusive, Reachable, Unreachable};
        let mut health = SessionHealth::default();
        assert!(health.record(Unreachable).is_ok());
        assert!(health.record(Inconclusive).is_ok());
        assert!(health.record(Reachable).is_ok());
        assert!(health.record(Unreachable).is_ok());
        assert!(health.record(Unreachable).is_ok());
        assert!(health.record(Unreachable).is_err());
        // A replacement session starts with a fresh failure history.
        assert!(SessionHealth::default().record(Unreachable).is_ok());
    }
}
