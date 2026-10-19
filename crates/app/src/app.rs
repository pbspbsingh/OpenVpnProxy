use std::net::SocketAddr;

use anyhow::{Context, Result, anyhow, bail};
use ovpn_ui::LogHub;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, watch};
use tokio::task::{JoinError, JoinSet};

use crate::config::AppConfig;
use crate::configurations::{Activation, Configurations, PreparedConfiguration};
use crate::dashboard::{Dashboard, DashboardHandle, summarize_profile};
use crate::manager::{ConnectionManager, RouterHandle};

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
    let listener = TcpListener::bind(address)
        .await
        .with_context(|| format!("cannot bind dashboard on {address}"))?;
    let dashboard = Dashboard::start()?;
    let storage = std::env::current_dir()
        .context("cannot locate configuration storage")?
        .join("configs");
    let (configurations, requests) = Configurations::new(config.openvpn_config.clone(), storage);
    let result = serve_with_dashboard(
        config,
        listener,
        dashboard.handle(),
        logs,
        configurations,
        requests,
    )
    .await;
    dashboard.shutdown().await;
    result
}

enum StartRequest {
    Startup,
    Prepared(Box<PreparedConfiguration>),
}

impl StartRequest {
    async fn prepare(
        self,
        configurations: &Configurations,
    ) -> Result<Option<PreparedConfiguration>> {
        match self {
            Self::Startup => Ok(configurations.prepare_startup().await?),
            Self::Prepared(prepared) => Ok(Some(*prepared)),
        }
    }
}

/// The HTTP server outlives each proxy generation. Only this loop owns activation.
async fn serve_with_dashboard(
    config: AppConfig,
    listener: TcpListener,
    source: DashboardHandle,
    logs: LogHub,
    configurations: Configurations,
    mut requests: mpsc::Receiver<Activation>,
) -> Result<()> {
    let (shutdown, _) = watch::channel(false);
    let (shutdown_request, mut requested) = watch::channel(false);
    // Reject activation until startup selection has been resolved.
    configurations.starting();
    let mut ui_task = tokio::spawn(ovpn_ui::serve(
        listener,
        source.clone(),
        shutdown.subscribe(),
        logs,
        shutdown_request,
        Some(std::sync::Arc::new(configurations.clone())),
        config.socks5_address,
    ));
    let mut next = Some(StartRequest::Startup);
    let mut selection_updates = configurations.subscribe();
    let mut proxy: Option<Proxy> = None;
    let mut failure = None;
    let mut ui_finished = false;
    source.configuration_changed(configurations.status());

    let result = 'serving: loop {
        if let Some(start) = next.take() {
            // Every previous producer has been joined before resetting observation state.
            if let Err(error) = source.reset().await {
                break Err(error.into());
            }
            configurations.starting();
            source.configuration_changed(configurations.status());
            source.starting("Loading OpenVPN configuration");
            let started = tokio::select! {
                result = async {
                    let prepared = start.prepare(&configurations).await?;
                    source.configuration_changed(configurations.status());
                    let Some(prepared) = prepared else { return Ok(None); };
                    let started = Proxy::start(&config, prepared, Some(&source), configurations.status().generation).await?;
                    if let Err(error) = configurations.ready().await {
                        started.shutdown().await;
                        return Err(error.into());
                    }
                    Ok(Some(started))
                } => result,
                signal = wait_for_stop(&mut requested) => break 'serving signal.map_err(Into::into),
                result = &mut ui_task => {
                    ui_finished = true;
                    break 'serving dashboard_ended(result);
                }
            };
            match started {
                Ok(Some(started)) => {
                    proxy = Some(started);
                    failure = None;
                    source.running();
                }
                Ok(None) => {
                    failure = None;
                    source.unconfigured();
                }
                Err(error) => {
                    tracing::error!(%error, "proxy unavailable; dashboard remains active");
                    configurations.failed(&error);
                    source.failed(format!("{error:#}"));
                    failure = Some(error);
                }
            }
            source.configuration_changed(configurations.status());
        }

        tokio::select! {
            signal = wait_for_stop(&mut requested) => {
                if let Err(error) = signal { break Err(error.into()); }
                break failure.map_or(Ok(()), Err);
            }
            result = &mut ui_task => {
                ui_finished = true;
                break dashboard_ended(result);
            }
            changed = selection_updates.changed() => {
                if changed.is_ok() {
                    let status = selection_updates.borrow_and_update().clone();
                    if status.phase == ovpn_ui::ConfigurationPhase::Unconfigured && proxy.is_none() {
                        failure = None;
                        if let Err(error) = source.reset().await { break Err(error.into()); }
                        source.unconfigured();
                    }
                    source.configuration_changed(status);
                }
            }
            Some(activation) = requests.recv() => {
                if let Some(running) = proxy.take() { running.shutdown().await; }
                next = Some(StartRequest::Prepared(Box::new(activation.prepared)));
            }
            result = async { proxy.as_mut().expect("guarded running proxy").wait_for_failure().await }, if proxy.is_some() => {
                let error = result.err().unwrap_or_else(|| anyhow!("proxy stopped unexpectedly"));
                let generation = proxy.as_ref().expect("running proxy").generation;
                if let Some(running) = proxy.take() { running.shutdown().await; }
                tracing::error!(%error, "proxy unavailable; dashboard remains active");
                // A concurrently accepted activation already describes the next
                // generation; an old failure must not make it editable/deletable.
                if configurations.failed_for(generation, &error) {
                    source.failed(format!("{error:#}"));
                    source.configuration_changed(configurations.status());
                }
                failure = Some(error);
            }
        }
    };
    if let Some(running) = proxy {
        running.shutdown().await;
    }
    shutdown.send_replace(true);
    if !ui_finished {
        ui_task.await.context("dashboard task failed")??;
    }
    result
}

async fn run_without_dashboard(config: AppConfig) -> Result<()> {
    let storage = std::env::current_dir()?.join("configs");
    let (configurations, _requests) = Configurations::new(config.openvpn_config.clone(), storage);
    let mut proxy = tokio::select! {
        result = async {
            let prepared = configurations.prepare_startup().await.map_err(|error| {
                tracing::error!(%error, "cannot restore startup VPN configuration");
                error
            })?.context(
                "no active VPN configuration; configure [openvpn_config] or enable webui_address to select one",
            )?;
            let proxy = Proxy::start(&config, prepared, None, configurations.status().generation).await?;
            if let Err(error) = configurations.ready().await {
                proxy.shutdown().await;
                return Err(error.into());
            }
            Ok::<_, anyhow::Error>(proxy)
        } => result?,
        signal = tokio::signal::ctrl_c() => { signal?; return Ok(()); }
    };
    let result = tokio::select! {
        result = proxy.wait_for_failure() => result,
        signal = tokio::signal::ctrl_c() => signal.map_err(Into::into),
    };
    proxy.shutdown().await;
    result
}

/// One running configuration owns its listener, clients, and complete VPN pool.
struct Proxy {
    generation: u64,
    socks: SocksServer,
    manager: ConnectionManager,
}

impl Proxy {
    async fn start(
        config: &AppConfig,
        prepared: PreparedConfiguration,
        dashboard: Option<&DashboardHandle>,
        generation: u64,
    ) -> Result<Self> {
        if let Some(dashboard) = dashboard {
            dashboard.profile_loaded(summarize_profile(&prepared.profile));
            dashboard.starting("Binding SOCKS5 listener");
        }
        let listener = TcpListener::bind(config.socks5_address)
            .await
            .with_context(|| format!("cannot bind SOCKS5 listener on {}", config.socks5_address))?;
        if let Some(dashboard) = dashboard {
            dashboard.starting("Probing OpenVPN hosts");
        }
        let manager = ConnectionManager::start(
            prepared.profile,
            prepared.username,
            prepared.password,
            prepared.dns_override,
            prepared.max_active_vpn_hosts,
            dashboard
                .map(DashboardHandle::telemetry)
                .unwrap_or_default(),
        )
        .await?;
        Ok(Self {
            generation,
            socks: SocksServer::new(listener, manager.router()),
            manager,
        })
    }

    async fn wait_for_failure(&mut self) -> Result<()> {
        tokio::select! {
            result = self.socks.run() => result,
            result = self.manager.wait_for_failure() => result,
        }
    }

    async fn shutdown(self) {
        self.socks.shutdown().await;
        self.manager.shutdown().await;
    }
}

async fn wait_for_stop(requested: &mut watch::Receiver<bool>) -> std::io::Result<()> {
    tokio::select! {
        signal = tokio::signal::ctrl_c() => signal,
        received = async { requested.wait_for(|requested| *requested).await.is_ok() } => {
            if received { Ok(()) } else { std::future::pending().await }
        }
    }
}

fn dashboard_ended(
    result: std::result::Result<std::result::Result<(), ovpn_ui::UiError>, JoinError>,
) -> Result<()> {
    match result.context("dashboard task failed")? {
        Ok(()) => bail!("dashboard stopped unexpectedly"),
        Err(error) => Err(error.into()),
    }
}

/// Owns every accepted client task across cancellation of the accept loop.
struct SocksServer {
    listener: TcpListener,
    router: RouterHandle,
    clients: JoinSet<()>,
}

impl SocksServer {
    fn new(listener: TcpListener, router: RouterHandle) -> Self {
        Self {
            listener,
            router,
            clients: JoinSet::new(),
        }
    }

    async fn run(&mut self) -> Result<()> {
        tracing::info!(address = %self.listener.local_addr()?, "SOCKS5 listening");
        loop {
            tokio::select! {
                accepted = self.listener.accept() => {
                    let (stream, peer) = accepted?;
                    let router = self.router.clone();
                    self.clients.spawn(async move {
                        if let Err(error) = ovpn_socks5::handle(stream, router).await {
                            tracing::debug!(%peer, %error, "SOCKS5 client ended with error");
                        }
                    });
                }
                Some(result) = self.clients.join_next(), if !self.clients.is_empty() => {
                    if let Err(error) = result { tracing::error!(%error, "SOCKS5 client task failed"); }
                }
            }
        }
    }

    async fn shutdown(mut self) {
        self.clients.abort_all();
        while self.clients.join_next().await.is_some() {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn dashboard_shutdown_is_received_after_a_lifecycle_transition() {
        let (request, mut requested) = watch::channel(false);
        request.send_replace(true);
        tokio::time::timeout(Duration::from_secs(1), wait_for_stop(&mut requested))
            .await
            .expect("pending shutdown request was lost")
            .unwrap();
    }

    #[tokio::test]
    async fn dashboard_shutdown_wakes_a_running_application() {
        let (request, mut requested) = watch::channel(false);
        let waiting = tokio::spawn(async move { wait_for_stop(&mut requested).await });
        tokio::task::yield_now().await;
        request.send_replace(true);
        tokio::time::timeout(Duration::from_secs(1), waiting)
            .await
            .expect("application did not observe shutdown")
            .unwrap()
            .unwrap();
    }
}
