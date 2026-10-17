//! Deterministic local dashboard for browser checks; never connects to a VPN.
use std::future::Future;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::time::{SystemTime, UNIX_EPOCH};

use ovpn_ui::{
    DashboardSnapshot, GroupError, GroupPage, GroupSnapshot, HostPhase, HostSnapshot, LogEvent,
    LogHub, PoolPhase, PoolSnapshot, ProfileRemote, ProfileSummary, SnapshotSource,
};
use tokio::net::TcpListener;
use tokio::sync::watch;

struct Fixture;

impl SnapshotSource for Fixture {
    fn snapshot(&self) -> Pin<Box<dyn Future<Output = DashboardSnapshot> + Send + '_>> {
        Box::pin(async {
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
            let rx = now.as_secs() * 100_000;
            DashboardSnapshot {
                version: 1,
                sampled_at_ms: now.as_millis() as u64,
                message: None,
                pool: PoolSnapshot {
                    phase: PoolPhase::Ready,
                    candidate_hosts: 2,
                    selected_hosts: 2,
                    ready_hosts: 2,
                    max_active_hosts: 2,
                    active_routes: 3,
                    sticky_groups: 102,
                    idle_remaining_seconds: None,
                    tx_bytes: rx / 10,
                    rx_bytes: rx,
                },
                hosts: (0..2)
                    .map(|id| HostSnapshot {
                        id,
                        endpoint: format!("192.0.2.{}:1194", id + 1),
                        phase: HostPhase::Ready,
                        selected: true,
                        active_routes: id + 1,
                        sticky_groups: if id == 0 { 101 } else { 1 },
                        latency_ms: Some(20.0 + id as f64 * 10.0),
                        score_age_seconds: Some(5),
                        ipv6: id == 0,
                        tx_bytes: rx / 20,
                        rx_bytes: rx / 2,
                    })
                    .collect(),
            }
        })
    }

    fn group_page(
        &self,
        host_id: usize,
        offset: usize,
        limit: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Option<GroupPage>, GroupError>> + Send + '_>> {
        Box::pin(async move {
            if host_id > 1 {
                return Ok(None);
            }
            // A delayed first-host response exercises cancellation on host changes.
            if host_id == 0 {
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
            let total = if host_id == 0 { 101 } else { 1 };
            Ok(Some(GroupPage {
                total,
                offset,
                groups: (offset..total.min(offset.saturating_add(limit)))
                    .map(|index| GroupSnapshot {
                        source: format!("198.51.100.{}", host_id + 1),
                        destination: format!("host-{host_id}-group-{index}.example"),
                        active_connections: index % 2,
                        idle_remaining_seconds: Some(120),
                    })
                    .collect(),
            }))
        })
    }

    fn profile(&self) -> ProfileSummary {
        ProfileSummary {
            remotes: vec![ProfileRemote {
                host: "vpn.example".to_owned(),
                port: 1194,
            }],
            credentials_required: true,
            ipv6_blocked: false,
            server_certificate_purpose_required: true,
            renegotiate_after_seconds: Some(3600),
            handshake_window_seconds: 30,
            transition_window_seconds: 3600,
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    println!("http://{}", listener.local_addr()?);
    let (logs, input) = LogHub::start(NonZeroUsize::new(3000).unwrap());
    for index in 0..2105 {
        input.record(LogEvent {
            timestamp_ms: index * 1000,
            level: if index % 2 == 0 { "INFO" } else { "ERROR" }.to_owned(),
            target: "fixture".to_owned(),
            message: format!("event {index}: <img src=x onerror=\"window.injected=true\">"),
        });
        if index % 64 == 0 {
            tokio::task::yield_now().await;
        }
    }
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
        loop {
            tick.tick().await;
            input.record(LogEvent {
                timestamp_ms: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64,
                level: "WARN".to_owned(),
                target: "fixture".to_owned(),
                message: "Live event".to_owned(),
            });
        }
    });
    let (shutdown, receiver) = watch::channel(false);
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        let _ = shutdown.send(true);
    });
    ovpn_ui::serve(listener, Fixture, receiver, logs).await?;
    Ok(())
}
