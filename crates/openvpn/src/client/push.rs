use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use super::{Ipv6Route, Ipv6TunnelSettings, TunnelSettings};
use crate::control::Link;
use crate::error::{Error, Result, require};
use crate::protocol::{MAX_CONTROL_FIELD_BYTES, MAX_TUN_MTU, MIN_TUN_MTU, PEER_ID_BITS};

const PUSH_REPLY_TIMEOUT: Duration = Duration::from_secs(20);
const DEFAULT_PING_INTERVAL: Duration = Duration::from_secs(10);
const DEFAULT_RESTART_INTERVAL: Duration = Duration::from_secs(60);
const MAX_AUTH_TOKEN_BYTES: usize = 256;
const MAX_ENCODED_AUTH_USERNAME_BYTES: usize = 340;
const MAX_AUTH_USERNAME_BYTES: usize = 255;
const IPV6_MIN_MTU: usize = 1280;

pub(super) async fn read_push(link: &mut Link) -> Result<String> {
    let deadline = Instant::now() + PUSH_REPLY_TIMEOUT;
    loop {
        if let Some(index) = link.application_data().iter().position(|byte| *byte == 0) {
            require(
                index <= MAX_CONTROL_FIELD_BYTES,
                "server PUSH_REPLY too large",
            )?;
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
    let mut ping = DEFAULT_PING_INTERVAL;
    let mut restart = DEFAULT_RESTART_INTERVAL;
    let mut local = None;
    let mut ifconfig_peer = None;
    let mut route_gateway = None;
    let mut subnet_topology = false;
    let mut dns = Vec::new();
    let mut mtu = MAX_TUN_MTU;
    let mut ipv6_address = None;
    let mut ipv6_gateway = None;
    let mut ipv6_route_gateway = None;
    let mut ipv6_routes = Vec::new();
    let mut redirect_ipv6 = false;
    let mut block_ipv6 = false;
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
            ["dhcp-option", "DNS" | "DNS6", address, ..] => dns.push(
                address
                    .parse::<IpAddr>()
                    .map_err(|_| Error::PushInvalidAddress("DNS server"))?,
            ),
            ["tun-mtu", value] => {
                mtu = value
                    .parse::<usize>()
                    .map_err(|_| Error::Protocol("invalid tunnel MTU"))?
            }
            ["ifconfig-ipv6", address, gateway, ..] => {
                ipv6_address = Some(parse_ipv6_cidr(address)?);
                ipv6_gateway = Some(
                    gateway
                        .parse::<Ipv6Addr>()
                        .map_err(|_| Error::PushInvalidAddress("IPv6 tunnel peer"))?,
                );
            }
            ["route-ipv6", network] => {
                let (network, prefix_len) = parse_ipv6_cidr(network)?;
                ipv6_routes.push((network, prefix_len, None));
            }
            ["route-ipv6-gateway", gateway] => {
                ipv6_route_gateway = Some(
                    gateway
                        .parse::<Ipv6Addr>()
                        .map_err(|_| Error::PushInvalidAddress("IPv6 route gateway"))?,
                );
            }
            ["route-ipv6", network, gateway, ..] => {
                let (network, prefix_len) = parse_ipv6_cidr(network)?;
                let gateway = match *gateway {
                    "vpn_gateway" => None,
                    value if value.parse::<u32>().is_ok() => None,
                    value => Some(
                        value
                            .parse::<Ipv6Addr>()
                            .map_err(|_| Error::PushInvalidAddress("IPv6 route gateway"))?,
                    ),
                };
                ipv6_routes.push((network, prefix_len, gateway));
            }
            ["redirect-gateway", options @ ..] if options.contains(&"ipv6") => {
                redirect_ipv6 = true;
            }
            ["block-ipv6"] => block_ipv6 = true,
            _ => {}
        }
    }
    require(
        cipher == Some("AES-256-GCM"),
        "server did not select AES-256-GCM",
    )?;
    let peer_id = peer_id.ok_or(Error::Protocol("server did not assign peer ID"))?;
    require(peer_id < 1 << PEER_ID_BITS, "invalid server peer ID")?;
    let local = local.ok_or(Error::PushMissingAddress)?;
    let gateway = route_gateway
        .or(if subnet_topology { None } else { ifconfig_peer })
        .unwrap_or(local);
    let ipv6 = match (ipv6_address, ipv6_gateway) {
        _ if block_ipv6 => {
            tracing::info!("VPN server blocks IPv6; IPv6 destinations disabled");
            None
        }
        (Some((address, prefix_len)), Some(peer)) if mtu >= IPV6_MIN_MTU => {
            require(
                !address.is_unspecified() && !address.is_multicast(),
                "invalid IPv6 tunnel address",
            )?;
            require(
                !peer.is_unspecified() && !peer.is_multicast(),
                "invalid IPv6 tunnel peer",
            )?;
            if redirect_ipv6 {
                ipv6_routes.push((Ipv6Addr::UNSPECIFIED, 0, None));
            }
            let routes: Vec<_> = ipv6_routes
                .into_iter()
                .map(|(network, prefix_len, gateway)| Ipv6Route {
                    network,
                    prefix_len,
                    gateway: gateway.or(ipv6_route_gateway).unwrap_or(peer),
                })
                .collect();
            if routes.is_empty() {
                tracing::debug!("VPN assigned an IPv6 address without IPv6 routes");
            }
            Some(Ipv6TunnelSettings {
                local: address,
                prefix_len,
                routes,
            })
        }
        (Some(_), Some(_)) => {
            tracing::warn!(mtu, "VPN MTU is too small for IPv6; IPv6 disabled");
            None
        }
        _ => {
            if !ipv6_routes.is_empty() || redirect_ipv6 || ipv6_address.is_some() {
                tracing::warn!(
                    missing_ifconfig_ipv6 = ipv6_address.is_none(),
                    route_ipv6_count = ipv6_routes.len(),
                    redirect_ipv6,
                    "VPN provided incomplete IPv6 settings; IPv6 disabled"
                );
            }
            None
        }
    };
    let tunnel = TunnelSettings {
        local,
        gateway,
        dns,
        mtu: mtu.clamp(MIN_TUN_MTU, MAX_TUN_MTU),
        ipv6,
    };
    Ok((tunnel, peer_id, ping, restart))
}

pub(super) fn pushed_auth_token(push: &str) -> Result<Option<(String, Option<String>)>> {
    let mut token = None;
    let mut user = None;
    for item in push.split(',').skip(1).map(str::trim) {
        if let Some(value) = item.strip_prefix("auth-token ") {
            require(
                !value.is_empty() && value.len() <= MAX_AUTH_TOKEN_BYTES,
                "invalid auth token",
            )?;
            token = Some(value.to_owned());
        } else if let Some(value) = item.strip_prefix("auth-token-user ") {
            require(
                value.len() <= MAX_ENCODED_AUTH_USERNAME_BYTES,
                "auth token username too long",
            )?;
            let decoded = STANDARD
                .decode(value)
                .map_err(|_| Error::Protocol("invalid auth token username"))?;
            require(
                decoded.len() <= MAX_AUTH_USERNAME_BYTES,
                "auth token username too long",
            )?;
            let decoded = String::from_utf8(decoded)
                .map_err(|_| Error::Protocol("invalid auth token username"))?;
            require(
                !decoded.contains(['\0', '\r', '\n']),
                "invalid auth token username",
            )?;
            user = Some(decoded);
        }
    }
    require(
        user.is_none() || token.is_some(),
        "auth token username without token",
    )?;
    Ok(token.map(|token| (token, user)))
}

fn parse_ipv6_cidr(value: &str) -> Result<(Ipv6Addr, u8)> {
    let (address, prefix) = value
        .split_once('/')
        .ok_or(Error::PushInvalidAddress("IPv6 CIDR"))?;
    let address = address
        .parse::<Ipv6Addr>()
        .map_err(|_| Error::PushInvalidAddress("IPv6 CIDR address"))?;
    let prefix = prefix
        .parse::<u8>()
        .map_err(|_| Error::PushInvalidAddress("IPv6 CIDR prefix"))?;
    require(prefix <= 128, "IPv6 prefix length exceeds 128")?;
    Ok((address, prefix))
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
        assert_eq!(tunnel.dns, vec![IpAddr::V4(Ipv4Addr::new(10, 8, 0, 53))]);
        assert_eq!(peer_id, 7);
        assert!(parse_push(&push.replace("10.8.0.53", "bad-ip")).is_err());
    }

    #[test]
    fn ipv6_requires_a_valid_pushed_address_and_route() {
        let base = "PUSH_REPLY,ifconfig 10.8.0.2 10.8.0.1,cipher AES-256-GCM,peer-id 7";
        let routed = format!(
            "{base},ifconfig-ipv6 2001:db8:1::2/64 2001:db8:1::1,route-ipv6 2000::/3,dhcp-option DNS6 2001:db8::53"
        );
        let (settings, _, _, _) = parse_push(&routed).unwrap();
        assert_eq!(
            settings.dns,
            vec![IpAddr::V6("2001:db8::53".parse().unwrap())]
        );
        let ipv6 = settings.ipv6.unwrap();
        assert_eq!(ipv6.local, "2001:db8:1::2".parse::<Ipv6Addr>().unwrap());
        assert_eq!(ipv6.routes[0].prefix_len, 3);
        assert_eq!(
            ipv6.routes[0].gateway,
            "2001:db8:1::1".parse::<Ipv6Addr>().unwrap()
        );

        let unrouted = format!("{base},ifconfig-ipv6 2001:db8:1::2/64 2001:db8:1::1");
        assert!(
            parse_push(&unrouted)
                .unwrap()
                .0
                .ipv6
                .unwrap()
                .routes
                .is_empty()
        );
        assert!(parse_push(&routed.replace("/64", "/129")).is_err());
        assert!(
            parse_push(&format!("{routed},block-ipv6"))
                .unwrap()
                .0
                .ipv6
                .is_none()
        );
    }

    #[test]
    fn decodes_pushed_auth_username_without_exposing_token() {
        let push = "PUSH_REPLY,auth-token opaque,auth-token-user dXNlcg==";
        assert_eq!(
            pushed_auth_token(push).unwrap(),
            Some(("opaque".into(), Some("user".into())))
        );
        assert!(pushed_auth_token("PUSH_REPLY,auth-token-user dXNlcg==").is_err());
    }
}
