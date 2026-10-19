use ovpn_dns::{Client, IpVersion, ResolverConfig};
use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;

use anyhow::{Context, Result, bail};
use ovpn_profile::Profile;
use tokio::task::JoinSet;
use tokio::time;

const MAX_PROFILE_REMOTES: usize = 64;
pub(super) const MAX_ENDPOINTS: usize = 64;
const REMOTE_DNS_TIMEOUT: Duration = Duration::from_secs(8);

#[derive(Clone)]
pub(super) struct HostCandidate {
    pub address: Ipv4Addr,
    pub endpoints: Vec<SocketAddr>,
}

pub(super) async fn resolve_candidates(
    profile: &Profile,
    dns: ResolverConfig,
) -> Result<Vec<HostCandidate>> {
    if profile.remotes.len() > MAX_PROFILE_REMOTES {
        bail!("profile contains too many VPN remotes");
    }
    let resolver = Arc::new(Client::<TcpStream>::new(dns));
    let mut lookups = JoinSet::new();
    let distinct_remotes: BTreeSet<_> = profile.remotes.iter().cloned().collect();
    tracing::debug!(
        entries = profile.remotes.len(),
        distinct = distinct_remotes.len(),
        "deduplicated profile remotes"
    );
    for (host, port) in distinct_remotes {
        let resolver = Arc::clone(&resolver);
        lookups.spawn(async move {
            let result = time::timeout(REMOTE_DNS_TIMEOUT, async {
                // Literal endpoints require no DNS request.
                if let Ok(address) = host.parse::<std::net::IpAddr>() {
                    return Ok(if address.is_ipv4() {
                        vec![SocketAddr::new(address, port)]
                    } else {
                        vec![]
                    });
                }
                resolver
                    .resolve(&host, IpVersion::V4, TcpStream::connect)
                    .await
                    .map(|addresses| {
                        addresses
                            .into_iter()
                            .map(|address| SocketAddr::new(address, port))
                            .collect::<Vec<_>>()
                    })
            })
            .await;
            (host, port, result)
        });
    }
    let mut endpoints: BTreeMap<Ipv4Addr, Vec<SocketAddr>> = BTreeMap::new();
    while let Some(result) = lookups.join_next().await {
        let (host, port, lookup) = result.context("VPN remote lookup task failed")?;
        match lookup {
            Ok(Ok(addresses)) => {
                let count = addresses.len();
                for address in addresses {
                    if let SocketAddr::V4(address) = address {
                        let endpoints = endpoints.entry(*address.ip()).or_default();
                        if !endpoints.contains(&SocketAddr::V4(address)) {
                            endpoints.push(SocketAddr::V4(address));
                        }
                    }
                }
                tracing::debug!(%host, port, addresses = count, "VPN remote resolved");
            }
            Ok(Err(error)) => tracing::warn!(%host, port, %error, "VPN remote lookup failed"),
            Err(_) => tracing::warn!(%host, port, "VPN remote lookup timed out"),
        }
        if endpoints.values().map(Vec::len).sum::<usize>() > MAX_ENDPOINTS {
            bail!("profile resolves to too many VPN endpoints");
        }
    }
    if endpoints.is_empty() {
        bail!("no VPN remote has a usable IPv4 endpoint");
    }
    tracing::info!(
        hosts = endpoints.len(),
        endpoints = endpoints.values().map(Vec::len).sum::<usize>(),
        "VPN candidates discovered"
    );
    Ok(endpoints
        .into_iter()
        .map(|(address, endpoints)| HostCandidate { address, endpoints })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn literal_vpn_hosts_need_no_resolver_and_preserve_distinct_ports() {
        let profile = Profile::parse(&format!(
            "client\nproto udp\nremote 192.0.2.1 1194\nremote 192.0.2.1 443\nremote 192.0.2.1 443\nremote 2001:db8::1 1194\n<ca>\nCERT\n</ca>\n<tls-crypt>\n{}\n</tls-crypt>\n",
            "00".repeat(256)
        )).unwrap();
        // An unreachable resolver proves literal remotes do not need DNS.
        let dns = ResolverConfig::new(Some("192.0.2.53".parse().unwrap()), None).unwrap();
        let candidates = time::timeout(Duration::from_secs(1), resolve_candidates(&profile, dns))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(
            candidates[0].address,
            "192.0.2.1".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(
            candidates[0].endpoints,
            vec![
                "192.0.2.1:443".parse::<SocketAddr>().unwrap(),
                "192.0.2.1:1194".parse().unwrap()
            ]
        );
    }
}
