use anyhow::{Context, Result, bail};
use ovpn_profile::Profile;
use tokio::net::TcpListener;

use crate::config::{config_path, load_config};
use crate::manager::{ConnectionManager, RouterHandle};

pub(crate) async fn run() -> Result<()> {
    let config = load_config(&config_path()?).await?;
    let content = tokio::fs::read_to_string(&config.profile_path)
        .await
        .with_context(|| format!("cannot read profile {}", config.profile_path.display()))?;
    let profile = Profile::parse(&content).context("invalid OpenVPN profile")?;
    tracing::debug!(
        remotes = profile.remotes.len(),
        credentials_required = profile.needs_credentials,
        "OpenVPN profile loaded"
    );
    if profile.needs_credentials && (config.username.is_empty() || config.password.is_empty()) {
        bail!("username and password are required by this profile");
    }
    let manager = ConnectionManager::start(
        profile,
        config.username,
        config.password,
        config.dns_override,
        config.max_active_vpn_hosts,
    )
    .await?;
    let result = async {
        manager.wait_ready().await?;
        let listener = TcpListener::bind(config.socks5_address)
            .await
            .with_context(|| format!("cannot bind SOCKS5 listener on {}", config.socks5_address))?;
        serve_socks(listener, manager.router()).await
    }
    .await;
    manager.shutdown().await;
    result
}

async fn serve_socks(listener: TcpListener, router: RouterHandle) -> Result<()> {
    tracing::info!(address = %listener.local_addr()?, "SOCKS5 listening");
    loop {
        tokio::select! {
            signal = tokio::signal::ctrl_c() => {
                signal?;
                tracing::info!("shutdown requested");
                return Ok(());
            }
            accepted = listener.accept() => {
                let (stream, peer) = accepted?;
                tracing::debug!(%peer, "SOCKS5 client accepted");
                let router = router.clone();
                tokio::spawn(async move {
                    if let Err(error) = ovpn_socks5::handle(stream, router).await {
                        tracing::debug!(%peer, %error, "SOCKS5 client ended with error");
                    } else {
                        tracing::debug!(%peer, "SOCKS5 handler finished");
                    }
                });
            }
        }
    }
}
