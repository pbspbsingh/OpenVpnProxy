use std::net::SocketAddr;

use anyhow::{Context, Result, anyhow, bail};
use ovpn_profile::Profile;
use ovpn_ui::LogHub;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::{JoinError, JoinHandle};

use crate::config::AppConfig;
use crate::dashboard::DashboardSource;
use crate::manager::{ConnectionManager, RouterHandle, summarize_profile};

pub(crate) async fn run(config: AppConfig, logs: Option<LogHub>) -> Result<()> {
    match config.webui_address {
        Some(address) => {
            let logs = logs.ok_or_else(|| anyhow!("dashboard log buffer unavailable"))?;
            run_with_dashboard(config, address, logs).await
        }
        None => run_without_dashboard(config).await,
    }
}

async fn run_with_dashboard(config: AppConfig, address: SocketAddr, logs: LogHub) -> Result<()> {
    let webui_listener = TcpListener::bind(address)
        .await
        .with_context(|| format!("cannot bind dashboard on {address}"))?;
    let source = DashboardSource::new();
    let (shutdown, _) = watch::channel(false);
    let mut ui_task = tokio::spawn(ovpn_ui::serve(
        webui_listener,
        source.clone(),
        shutdown.subscribe(),
        logs,
    ));

    let startup = tokio::select! {
        result = initialize(config, Some(&source)) => result,
        result = &mut ui_task => return dashboard_ended(result),
        signal = tokio::signal::ctrl_c() => {
            shutdown.send_replace(true);
            ui_task.await.context("dashboard task failed")??;
            signal?;
            return Ok(());
        }
    };

    let (socks_listener, manager) = match startup {
        Ok(started) => started,
        Err(error) => return show_failure(error, &source, &shutdown, &mut ui_task).await,
    };
    source.running(manager.router());
    let mut ui_finished = false;
    let proxy_result = tokio::select! {
        result = serve_socks(socks_listener, manager.router()) => result,
        result = &mut ui_task => {
            ui_finished = true;
            dashboard_ended(result)
        }
        signal = tokio::signal::ctrl_c() => {
            signal?;
            tracing::info!("shutdown requested");
            Ok(())
        }
    };
    if let Err(error) = &proxy_result
        && !ui_finished
    {
        source.failed(format!("{error:#}"));
    }
    manager.shutdown().await;

    match proxy_result {
        Err(error) if !ui_finished => show_failure(error, &source, &shutdown, &mut ui_task).await,
        result => {
            shutdown.send_replace(true);
            if !ui_finished {
                ui_task.await.context("dashboard task failed")??;
            }
            result
        }
    }
}

async fn run_without_dashboard(config: AppConfig) -> Result<()> {
    tracing::info!("dashboard disabled; webui_address not configured");
    let (socks_listener, manager) = initialize(config, None).await?;
    let result = tokio::select! {
        result = serve_socks(socks_listener, manager.router()) => result,
        signal = tokio::signal::ctrl_c() => {
            signal?;
            tracing::info!("shutdown requested");
            Ok(())
        }
    };
    manager.shutdown().await;
    result
}

async fn initialize(
    config: AppConfig,
    dashboard: Option<&DashboardSource>,
) -> Result<(TcpListener, ConnectionManager)> {
    if let Some(dashboard) = dashboard {
        dashboard.starting("Loading OpenVPN profile");
    }
    let content = tokio::fs::read_to_string(&config.profile_path)
        .await
        .with_context(|| format!("cannot read profile {}", config.profile_path.display()))?;
    let profile = Profile::parse(&content).context("invalid OpenVPN profile")?;
    if let Some(dashboard) = dashboard {
        dashboard.profile_loaded(summarize_profile(&profile));
    }
    tracing::debug!(
        remotes = profile.remotes.len(),
        credentials_required = profile.needs_credentials,
        "OpenVPN profile loaded"
    );
    if profile.needs_credentials && (config.username.is_empty() || config.password.is_empty()) {
        bail!("username and password are required by this profile");
    }

    if let Some(dashboard) = dashboard {
        dashboard.starting("Binding SOCKS5 listener");
    }
    let socks_listener = TcpListener::bind(config.socks5_address)
        .await
        .with_context(|| format!("cannot bind SOCKS5 listener on {}", config.socks5_address))?;

    if let Some(dashboard) = dashboard {
        dashboard.starting("Probing OpenVPN hosts");
    }
    let manager = ConnectionManager::start(
        profile,
        config.username,
        config.password,
        config.dns_override,
        config.max_active_vpn_hosts,
        dashboard.is_some(),
    )
    .await?;
    Ok((socks_listener, manager))
}

async fn show_failure(
    error: anyhow::Error,
    source: &DashboardSource,
    shutdown: &watch::Sender<bool>,
    ui_task: &mut JoinHandle<std::result::Result<(), ovpn_ui::UiError>>,
) -> Result<()> {
    tracing::error!(%error, "proxy unavailable; dashboard remains active");
    source.failed(format!("{error:#}"));
    let signal = tokio::select! {
        signal = tokio::signal::ctrl_c() => signal,
        result = &mut *ui_task => return dashboard_ended(result),
    };
    shutdown.send_replace(true);
    ui_task.await.context("dashboard task failed")??;
    signal?;
    Err(error)
}

fn dashboard_ended(
    result: std::result::Result<std::result::Result<(), ovpn_ui::UiError>, JoinError>,
) -> Result<()> {
    match result.context("dashboard task failed")? {
        Ok(()) => Err(anyhow!("dashboard stopped unexpectedly")),
        Err(error) => Err(error.into()),
    }
}

async fn serve_socks(listener: TcpListener, router: RouterHandle) -> Result<()> {
    tracing::info!(address = %listener.local_addr()?, "SOCKS5 listening");
    loop {
        let (stream, peer) = listener.accept().await?;
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
