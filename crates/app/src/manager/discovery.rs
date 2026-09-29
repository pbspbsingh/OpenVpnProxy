use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use ovpn_profile::Profile;
use tokio::task::JoinSet;
use tokio::time;

const MAX_PROFILE_REMOTES: usize = 64;
pub(super) const MAX_ENDPOINTS: usize = 64;
const REMOTE_DNS_TIMEOUT: Duration = Duration::from_secs(8);

pub(super) struct HostCandidate {
    pub(super) address: Ipv4Addr,
    pub(super) endpoints: Vec<SocketAddr>,
}

pub(super) async fn resolve_candidates(profile: &Profile) -> Result<Vec<HostCandidate>> {
    if profile.remotes.len() > MAX_PROFILE_REMOTES {
        bail!("profile contains too many VPN remotes");
    }
    let mut lookups = JoinSet::new();
    let distinct_remotes: BTreeSet<_> = profile.remotes.iter().cloned().collect();
    tracing::debug!(
        entries = profile.remotes.len(),
        distinct = distinct_remotes.len(),
        "deduplicated profile remotes"
    );
    for (host, port) in distinct_remotes {
        lookups.spawn(async move {
            let result = time::timeout(
                REMOTE_DNS_TIMEOUT,
                tokio::net::lookup_host((host.as_str(), port)),
            )
            .await
            .map(|result| {
                result.map(|addresses| addresses.filter(SocketAddr::is_ipv4).collect::<Vec<_>>())
            });
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
