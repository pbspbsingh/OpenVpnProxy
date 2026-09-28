mod app;
mod config;

use std::env;

use anyhow::{Context, Result};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let (filter, filter_error) = match tracing_subscriber::EnvFilter::try_from_default_env() {
        Ok(filter) => (filter, None),
        Err(error) if env::var_os("RUST_LOG").is_some() => {
            (tracing_subscriber::EnvFilter::new("info"), Some(error))
        }
        Err(_) => (tracing_subscriber::EnvFilter::new("info"), None),
    };
    tracing_subscriber::fmt().with_env_filter(filter).init();
    if let Some(error) = filter_error {
        return Err(error).context("invalid RUST_LOG filter");
    }
    app::run().await
}
