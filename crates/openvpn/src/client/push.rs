use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use super::TunnelSettings;
use crate::control::Link;
use crate::error::{Error, Result, require};

pub(super) async fn read_push(link: &mut Link) -> Result<String> {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(index) = link.application_data().iter().position(|byte| *byte == 0) {
            require(index <= 16384, "server PUSH_REPLY too large")?;
            let bytes: Vec<_> = link.application_data().drain(..=index).collect();
            let message = String::from_utf8(bytes[..index].to_vec())?;
            if message.starts_with("AUTH_FAILED") {
                return Err(Error::AuthenticationFailed);
            }
            if message.starts_with("PUSH_REPLY,") {
                return Ok(message);
            }
        }
        if Instant::now() >= deadline {
            return Err(Error::Timeout("server PUSH_REPLY"));
        }
        link.step().await?;
    }
}

pub(super) fn parse_push(push: &str) -> Result<(TunnelSettings, u32, Duration, Duration)> {
    require(
        push.starts_with("PUSH_REPLY,"),
        "server did not send PUSH_REPLY",
    )?;
    let mut cipher = None;
    let mut peer_id = None;
    let mut ping = Duration::from_secs(10);
    let mut restart = Duration::from_secs(60);
    let mut local = None;
    let mut ifconfig_peer = None;
    let mut route_gateway = None;
    let mut subnet_topology = false;
    let mut dns = Vec::new();
    let mut mtu = 1400;
    for item in push.split(',').skip(1) {
        let words: Vec<_> = item.split_whitespace().collect();
        match words.as_slice() {
            ["cipher", value] => cipher = Some(*value),
            ["peer-id", value] => {
                peer_id = Some(
                    value
                        .parse::<u32>()
                        .map_err(|_| Error::Protocol("invalid peer ID"))?,
                )
            }
            ["ping", value] => {
                ping = Duration::from_secs(
                    value
                        .parse::<u64>()
                        .map_err(|_| Error::Protocol("invalid ping interval"))?,
                )
            }
            ["ping-restart", value] => {
                restart = Duration::from_secs(
                    value
                        .parse::<u64>()
                        .map_err(|_| Error::Protocol("invalid restart interval"))?,
                )
            }
            ["ifconfig", address, peer, ..] => {
                local = Some(
                    address
                        .parse::<Ipv4Addr>()
                        .map_err(|_| Error::PushInvalidAddress("ifconfig local"))?,
                );
                ifconfig_peer = Some(
                    peer.parse::<Ipv4Addr>()
                        .map_err(|_| Error::PushInvalidAddress("ifconfig peer"))?,
                );
            }
            ["route-gateway", address, ..] => {
                route_gateway = Some(
                    address
                        .parse::<Ipv4Addr>()
                        .map_err(|_| Error::PushInvalidAddress("route gateway"))?,
                )
            }
            ["topology", "subnet", ..] => subnet_topology = true,
            ["dhcp-option", "DNS", address, ..] => dns.push(
                address
                    .parse::<Ipv4Addr>()
                    .map_err(|_| Error::PushInvalidAddress("DNS server"))?,
            ),
            ["tun-mtu", value] => {
                mtu = value
                    .parse::<usize>()
                    .map_err(|_| Error::Protocol("invalid tunnel MTU"))?
            }
            _ => {}
        }
    }
    require(
        cipher == Some("AES-256-GCM"),
        "server did not select AES-256-GCM",
    )?;
    let peer_id = peer_id.ok_or(Error::Protocol("server did not assign peer ID"))?;
    require(peer_id < 1 << 24, "invalid server peer ID")?;
    let local = local.ok_or(Error::PushMissingAddress)?;
    let gateway = route_gateway
        .or(if subnet_topology { None } else { ifconfig_peer })
        .unwrap_or(local);
    let tunnel = TunnelSettings {
        local,
        gateway,
        dns,
        mtu: mtu.clamp(576, 1400),
    };
    Ok((tunnel, peer_id, ping, restart))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_reply_builds_tunnel_settings_and_rejects_bad_addresses() {
        let push = "PUSH_REPLY,topology subnet,ifconfig 10.8.0.2 255.255.255.0,route-gateway 10.8.0.1,dhcp-option DNS 10.8.0.53,cipher AES-256-GCM,peer-id 7,ping 10,ping-restart 60";
        let (tunnel, peer_id, _, _) = parse_push(push).unwrap();
        assert_eq!(tunnel.local, Ipv4Addr::new(10, 8, 0, 2));
        assert_eq!(tunnel.gateway, Ipv4Addr::new(10, 8, 0, 1));
        assert_eq!(tunnel.dns, vec![Ipv4Addr::new(10, 8, 0, 53)]);
        assert_eq!(peer_id, 7);
        assert!(parse_push(&push.replace("10.8.0.53", "bad-ip")).is_err());
    }
}
