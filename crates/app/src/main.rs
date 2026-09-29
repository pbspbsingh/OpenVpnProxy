mod app;
mod config;
mod dashboard;
mod logging;
mod manager;

use std::env;

use anyhow::{Context, Result};
use ovpn_ui::LogHub;
use tracing_subscriber::prelude::*;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let (filter, filter_error) = match tracing_subscriber::EnvFilter::try_from_default_env() {
        Ok(filter) => (filter, None),
        Err(error) if env::var_os("RUST_LOG").is_some() => {
            (tracing_subscriber::EnvFilter::new("info"), Some(error))
        }
        Err(_) => (tracing_subscriber::EnvFilter::new("info"), None),
    };
    let config = config::load_config(&config::config_path()?).await?;
    let (logs, log_layer) = if config.webui_address.is_some() {
        let (hub, input) = LogHub::start(config.dashboard_log_capacity());
        (Some(hub), Some(logging::DashboardLogLayer::new(input)))
    } else {
        (None, None)
    };
    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer())
        .with(log_layer)
        .init();
    if let Some(error) = filter_error {
        return Err(error).context("invalid RUST_LOG filter");
    }
    app::run(config, logs).await
}
