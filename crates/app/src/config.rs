use std::env;
use std::net::{Ipv4Addr, SocketAddr};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Deserialize;

const DEFAULT_DASHBOARD_LOG_CAPACITY: usize = 1000;
const MAX_DASHBOARD_LOG_CAPACITY: usize = 20_000;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AppConfig {
    pub socks5_address: SocketAddr,
    pub webui_address: Option<SocketAddr>,
    pub dashboard_log_capacity: Option<NonZeroUsize>,
    pub openvpn_config: Option<OpenVpnConfig>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OpenVpnConfig {
    pub profile_path: PathBuf,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    pub dns_override: Option<Ipv4Addr>,
    pub dns_tls_name: Option<String>,
    pub max_active_vpn_hosts: Option<NonZeroUsize>,
}

impl AppConfig {
    pub(crate) fn dashboard_log_capacity(&self) -> NonZeroUsize {
        self.dashboard_log_capacity
            .unwrap_or(NonZeroUsize::new(DEFAULT_DASHBOARD_LOG_CAPACITY).unwrap())
    }
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
    if config.dashboard_log_capacity().get() > MAX_DASHBOARD_LOG_CAPACITY {
        bail!("dashboard_log_capacity must be at most {MAX_DASHBOARD_LOG_CAPACITY}");
    }
    if let Some(vpn) = &mut config.openvpn_config {
        if vpn
            .max_active_vpn_hosts
            .is_some_and(|limit| limit.get() > 64)
        {
            bail!("max_active_vpn_hosts must be at most 64");
        }
        if vpn.profile_path.is_relative() {
            let parent = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty());
            if let Some(parent) = parent {
                vpn.profile_path = parent.join(&vpn.profile_path);
            }
        }
    }
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn application_settings_and_optional_openvpn_section_are_separate() {
        let config: AppConfig =
            toml::from_str("socks5_address = '127.0.0.1:1080'\nwebui_address = '127.0.0.1:8080'")
                .unwrap();
        assert!(config.openvpn_config.is_none());
        let config: AppConfig = toml::from_str("socks5_address = '127.0.0.1:1080'\n[openvpn_config]\nprofile_path = 'client.ovpn'\nusername = 'user'\npassword = 'secret'").unwrap();
        assert_eq!(config.openvpn_config.unwrap().username, "user");
        assert!(
            toml::from_str::<AppConfig>("socks5_address = '127.0.0.1:1080'\nusername = 'user'")
                .is_err()
        );
    }
}
