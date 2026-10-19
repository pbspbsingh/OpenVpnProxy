mod app;
mod config;
mod configurations;
mod connector;
mod dashboard;
mod logging;
mod manager;

use std::env;
use std::io::IsTerminal;

use anyhow::{Context, Result};
use ovpn_ui::LogHub;
use tracing_subscriber::prelude::*;

#[tokio::main]
async fn main() -> Result<()> {
    let (filter, filter_error) = match tracing_subscriber::EnvFilter::try_from_default_env() {
        Ok(filter) => (filter, None),
        Err(error) if env::var_os("RUST_LOG").is_some() => {
            (tracing_subscriber::EnvFilter::new("info"), Some(error))
        }
        Err(_) => (tracing_subscriber::EnvFilter::new("info"), None),
    };
    let config_path = config::config_path()?;
    let config = config::load_config(&config_path).await?;
    let (logs, log_layer) = if config.webui_address.is_some() {
        let (hub, input) = LogHub::start(config.dashboard_log_capacity());
        (Some(hub), Some(logging::DashboardLogLayer::new(input)))
    } else {
        (None, None)
    };
    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().with_ansi(std::io::stdout().is_terminal()))
        .with(log_layer)
        .init();
    if let Some(error) = filter_error {
        return Err(error).context("invalid RUST_LOG filter");
    }
    tracing::info!(pid = std::process::id(), config = %config_path.display(),
        socks5_address = %config.socks5_address, webui_address = ?config.webui_address, "Application starting");
    let result = app::run(config, logs).await;
    match &result {
        Ok(()) => tracing::info!(pid = std::process::id(), "Application stopped"),
        Err(error) => {
            tracing::error!(pid = std::process::id(), error = %error, error_chain = ?error, "Application failed")
        }
    }
    result
}
