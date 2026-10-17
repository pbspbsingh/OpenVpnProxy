use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use ovpn_client::Session;
use ovpn_netstack::{Stack, StackOwner};
use tokio::sync::mpsc;
use tokio::time;

const PROBE_ADDRESS: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);
const PROBE_PORT: u16 = 443;
const PROBE_SAMPLES: usize = 3;
const MIN_SUCCESSFUL_SAMPLES: usize = 2;
const PROBE_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

pub(super) const PROBE_INTERVAL: Duration = Duration::from_secs(60);

pub(super) struct LatencyScore {
    pub median: Duration,
    pub elapsed: Duration,
    pub successful_samples: usize,
    pub measured_at: Instant,
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
