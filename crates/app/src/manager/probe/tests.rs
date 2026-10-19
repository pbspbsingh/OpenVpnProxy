use super::*;
use Reachability::{Inconclusive, Reachable, Unreachable};

fn assessment(tcp: Reachability, dns: Reachability) -> HealthAssessment {
    HealthAssessment { tcp, dns }
}

fn score() -> LatencyScore {
    LatencyScore {
        median: Duration::from_millis(20),
        elapsed: Duration::from_millis(60),
        successful_samples: 3,
        measured_at: Instant::now(),
    }
}

#[test]
fn only_repeated_confirmed_failures_end_a_session() {
    let mut health = SessionHealth::default();
    assert!(health.record(assessment(Unreachable, Reachable)).is_ok());
    assert!(health.record(assessment(Inconclusive, Reachable)).is_ok());
    assert!(health.record(assessment(Reachable, Reachable)).is_ok());
    assert!(health.record(assessment(Unreachable, Reachable)).is_ok());
    assert!(health.record(assessment(Unreachable, Reachable)).is_ok());
    assert!(health.record(assessment(Unreachable, Reachable)).is_err());
    assert!(
        SessionHealth::default()
            .record(assessment(Unreachable, Reachable))
            .is_ok()
    );
}

#[tokio::test]
async fn successful_tcp_does_not_mask_repeated_dns_failures() {
    let mut health = SessionHealth::default();
    for attempt in 1..=MAX_FAILED_HEALTH_CHECKS {
        let report = assess_health(async { (Ok(score()), Reachable) }, async {
            Err(StackError::DnsTimeout.into())
        })
        .await;
        assert_eq!(report.score.unwrap().median, Duration::from_millis(20));
        let result = health.record(report.health);
        if attempt < MAX_FAILED_HEALTH_CHECKS {
            assert!(result.is_ok());
        } else {
            assert!(result.unwrap_err().to_string().contains("DNS: Unreachable"));
        }
    }
}

#[test]
fn only_joint_tcp_and_dns_recovery_resets_failures() {
    let mut health = SessionHealth::default();
    assert!(health.record(assessment(Reachable, Unreachable)).is_ok());
    assert!(health.record(assessment(Reachable, Unreachable)).is_ok());
    assert!(health.record(assessment(Reachable, Reachable)).is_ok());
    assert!(health.record(assessment(Reachable, Unreachable)).is_ok());
    assert!(health.record(assessment(Reachable, Unreachable)).is_ok());
    assert!(health.record(assessment(Inconclusive, Reachable)).is_ok());
    assert!(health.record(assessment(Reachable, Unreachable)).is_err());
}

#[tokio::test]
async fn nested_dns_capacity_errors_are_inconclusive_and_preserve_failure_history() {
    let error = anyhow::Error::new(StackError::DnsQuery(ovpn_dns::Error::Io(
        std::io::Error::other(StackError::ConnectionLimit),
    )))
    .context("VPN DNS health lookup failed");
    assert!(local_capacity_error(&error));
    let report = assess_health(async { (Ok(score()), Reachable) }, async { Err(error) }).await;
    assert_eq!(report.health.reachability(), Inconclusive);
    let mut health = SessionHealth::default();
    assert!(health.record(assessment(Reachable, Unreachable)).is_ok());
    assert!(health.record(assessment(Reachable, Unreachable)).is_ok());
    assert!(health.record(report.health).is_ok());
    assert!(health.record(assessment(Reachable, Unreachable)).is_err());
}

#[tokio::test]
async fn tcp_fallback_keeps_a_host_only_when_dns_also_works() {
    for (dns, expected) in [
        (Ok(()), Reachable),
        (Err(StackError::DnsTimeout.into()), Unreachable),
    ] {
        let report = assess_health(
            async {
                (
                    Err(anyhow::anyhow!(
                        "latency target unavailable; fallback TCP succeeded"
                    )),
                    Reachable,
                )
            },
            async { dns },
        )
        .await;
        assert!(report.score.is_err());
        assert_eq!(report.health.reachability(), expected);
    }
}

#[tokio::test]
async fn dns_protocol_and_transport_errors_count_as_health_failures() {
    for error in [
        StackError::DnsQuery(ovpn_dns::Error::Io(std::io::Error::from(
            std::io::ErrorKind::ConnectionReset,
        ))),
        StackError::DnsQuery(ovpn_dns::Error::Protocol("mismatched response".into())),
        StackError::NoDnsAddress,
    ] {
        let report = assess_health(async { (Ok(score()), Reachable) }, async {
            Err(error.into())
        })
        .await;
        assert_eq!(report.health.reachability(), Unreachable);
    }
}

#[tokio::test(start_paused = true)]
async fn tcp_and_dns_checks_run_concurrently() {
    let started = time::Instant::now();
    let duration = Duration::from_secs(8);
    let report = assess_health(
        async {
            time::sleep(duration).await;
            (Ok(score()), Reachable)
        },
        async {
            time::sleep(duration).await;
            Ok(())
        },
    )
    .await;
    assert_eq!(time::Instant::now() - started, duration);
    assert_eq!(report.health.reachability(), Reachable);
}

#[tokio::test]
async fn production_health_check_opens_tunneled_dns_alongside_tcp_probe() {
    let (output, mut packets) = mpsc::channel(16);
    let owner = StackOwner::start(
        ovpn_netstack::TunnelConfig::new(
            "10.8.0.2".parse().unwrap(),
            "10.8.0.1".parse().unwrap(),
            ovpn_dns::ResolverConfig::default(),
            1400,
            None,
        )
        .unwrap(),
        output,
    )
    .await
    .unwrap();
    let stack = owner.client();
    let mut probe = Box::pin(check_health(&stack));
    let mut tcp_seen = false;
    let mut dns_seen = false;
    time::timeout(Duration::from_secs(1), async {
        while !tcp_seen || !dns_seen {
            let packet = tokio::select! {
                _ = &mut probe => panic!("health check completed without peer responses"),
                packet = packets.recv() => packet.unwrap(),
            };
            assert!(packet.len() >= 40);
            assert_eq!(&packet[16..20], &[1, 1, 1, 1]);
            let tcp_header = usize::from(packet[0] & 0x0f) * 4;
            let port = u16::from_be_bytes([packet[tcp_header + 2], packet[tcp_header + 3]]);
            tcp_seen |= port == 443;
            dns_seen |= port == 853;
        }
    })
    .await
    .unwrap();
    drop(probe);
    owner.shutdown().await;
}
