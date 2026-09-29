use std::env;
use std::net::{Ipv4Addr, SocketAddr};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AppConfig {
    pub(crate) profile_path: PathBuf,
    pub(crate) username: String,
    pub(crate) password: String,
    pub(crate) socks5_address: SocketAddr,
    pub(crate) dns_override: Option<Ipv4Addr>,
    pub(crate) max_active_vpn_hosts: Option<NonZeroUsize>,
}

pub(crate) fn config_path() -> Result<PathBuf> {
    let mut args = env::args_os().skip(1);
    let path = args
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("config.toml"));
    if args.next().is_some() {
        bail!("usage: openvpn-proxy-app [CONFIG.toml]");
    }
    Ok(path)
}

pub(crate) async fn load_config(path: &Path) -> Result<AppConfig> {
    let content = tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("cannot read config {}", path.display()))?;
    // TOML's full error display may include the source line, including a password.
    let mut config: AppConfig = toml::from_str(&content).map_err(|error: toml::de::Error| {
        anyhow::anyhow!("invalid config {}: {}", path.display(), error.message())
    })?;
    if !config.socks5_address.is_ipv4() {
        bail!("socks5_address must be an IPv4 address");
    }
    if config.profile_path.is_relative() {
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty());
        if let Some(parent) = parent {
            config.profile_path = parent.join(&config.profile_path);
        }
    }
    Ok(config)
}
