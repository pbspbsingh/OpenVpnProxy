use std::net::SocketAddr;

use anyhow::{Context, Result, bail};
use ovpn_client::{ClientConfig, Session};
use ovpn_netstack::{Stack, TunnelConfig};
use ovpn_profile::Profile;
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use crate::config::{config_path, load_config};

async fn resolve_vpn_endpoint(profile: &Profile) -> Result<SocketAddr> {
    let mut last_error = None;
    for (host, port) in &profile.remotes {
        match tokio::net::lookup_host((host.as_str(), *port)).await {
            Ok(mut addresses) => {
                if let Some(address) = addresses.find(SocketAddr::is_ipv4) {
                    tracing::info!("VPN address host: {address:?}");
                    return Ok(address);
                }
            }
            Err(error) => last_error = Some(error),
        }
    }
    if let Some(error) = last_error {
        return Err(error).context("could not resolve a VPN server endpoint");
    }
    bail!("no VPN server has an IPv4 endpoint")
}

async fn serve_socks(
    listener: TcpListener,
    stack: Stack,
    mut session: Session,
    mut outbound: mpsc::Receiver<Vec<u8>>,
) -> Result<()> {
    stack.activate()?;
    tracing::info!(address = %listener.local_addr()?, "VPN ready; SOCKS5 listening");
    let result = async {
        loop {
            if !stack.is_ready() {
                bail!("packet stack stopped while VPN was active");
            }
            tokio::select! {
                signal = tokio::signal::ctrl_c() => {
                    signal?;
                    tracing::info!("shutdown requested");
                    return Ok(());
                }
                accepted = listener.accept() => {
                    let (stream, _) = accepted?;
                    let stack = stack.clone();
                    tokio::spawn(async move {
                        if let Err(error) = ovpn_socks5::handle(stream, stack).await {
                            tracing::debug!(%error, "SOCKS5 client ended with error");
                        }
                    });
                }
                packet = outbound.recv() => {
                    let packet = packet.context("tunnel packet output channel closed")?;
                    session.send_packet(&packet).await?;
                }
                received = session.step() => {
                    if let Some(packet) = received? {
                        stack.packet(&packet)?;
                    }
                }
            }
        }
    }
    .await;
    if let Err(error) = stack.reset().await {
        tracing::error!(%error, "packet stack reset failed");
    }
    result
}

pub(crate) async fn run() -> Result<()> {
    let config = load_config(&config_path()?).await?;
    let content = tokio::fs::read_to_string(&config.profile_path)
        .await
        .with_context(|| format!("cannot read profile {}", config.profile_path.display()))?;
    let profile = Profile::parse(&content).context("invalid OpenVPN profile")?;
    if profile.needs_credentials && (config.username.is_empty() || config.password.is_empty()) {
        bail!("username and password are required by this profile");
    }
    tracing::info!("connecting to VPN server");
    let client_config = ClientConfig {
        endpoint: resolve_vpn_endpoint(&profile).await?,
        ca_pem: &profile.ca_pem,
        tls_crypt_key: &profile.tls_crypt_key,
    };
    let session = Session::connect(&client_config, &config.username, &config.password)
        .await
        .context("OpenVPN connection failed")?;
    let settings = &session.config().tunnel;
    let dns = config
        .dns_override
        .map(|address| vec![address])
        .unwrap_or_else(|| settings.dns.clone());
    let tunnel = TunnelConfig::new(settings.local, settings.gateway, dns, settings.mtu)
        .context("invalid VPN tunnel settings")?;
    let stack = Stack::start();
    let (packet_tx, packet_rx) = mpsc::channel(1024);
    stack
        .configure(tunnel, packet_tx)
        .await
        .context("packet stack setup failed")?;
    let listener = TcpListener::bind(config.socks5_address)
        .await
        .with_context(|| format!("cannot bind SOCKS5 listener on {}", config.socks5_address))?;
    serve_socks(listener, stack, session, packet_rx).await
}
