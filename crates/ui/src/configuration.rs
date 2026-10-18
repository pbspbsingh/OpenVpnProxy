//! Configuration API contracts. Persistence and proxy lifecycle belong to the app.
use std::future::Future;
use std::net::Ipv4Addr;
use std::num::NonZeroUsize;
use std::pin::Pin;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub type ConfigurationFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, ConfigurationError>> + Send + 'a>>;

pub trait ConfigurationControl: Send + Sync + 'static {
    fn list(&self) -> ConfigurationFuture<'_, ConfigurationList>;
    fn save(
        &self,
        id: Option<String>,
        input: ConfigurationInput,
    ) -> ConfigurationFuture<'_, ConfigurationSummary>;
    fn activate(&self, id: String, revision: u64) -> ConfigurationFuture<'_, ()>;
    fn delete(&self, id: String, revision: u64) -> ConfigurationFuture<'_, ()>;
}

#[derive(Clone, Serialize)]
pub struct ConfigurationList {
    pub configurations: Vec<ConfigurationSummary>,
    pub status: ConfigurationStatus,
}

/// Public metadata deliberately excludes passwords and profile contents.
#[derive(Clone, Serialize)]
pub struct ConfigurationSummary {
    pub id: String,
    pub name: String,
    pub read_only: bool,
    pub revision: u64,
    pub username: String,
    pub password_set: bool,
    pub profile_name: String,
    pub dns_override: Option<Ipv4Addr>,
    pub max_active_vpn_hosts: Option<NonZeroUsize>,
}

#[derive(Clone, Serialize)]
pub struct ConfigurationStatus {
    pub id: Option<String>,
    pub name: Option<String>,
    pub revision: Option<u64>,
    pub generation: u64,
    pub phase: ConfigurationPhase,
    pub message: Option<String>,
    pub file_missing: bool,
}

#[derive(Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigurationPhase {
    Unconfigured,
    Starting,
    Ready,
    Failed,
}

impl Default for ConfigurationStatus {
    fn default() -> Self {
        Self {
            id: None,
            name: None,
            revision: None,
            generation: 0,
            phase: ConfigurationPhase::Unconfigured,
            message: None,
            file_missing: false,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigurationInput {
    pub name: String,
    pub username: String,
    /// Omission retains the stored password. An empty string explicitly clears it.
    pub password: Option<String>,
    /// Omission retains the stored profile when editing.
    pub profile: Option<ProfileUpload>,
    pub revision: Option<u64>,
    pub dns_override: Option<Ipv4Addr>,
    pub max_active_vpn_hosts: Option<NonZeroUsize>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileUpload {
    pub name: String,
    pub content: String,
}

#[derive(Debug, Error)]
pub enum ConfigurationError {
    #[error("{0}")]
    MissingFile(String),
    #[error("{0}")]
    Invalid(String),
    #[error("configuration not found")]
    NotFound,
    #[error("the default configuration is read-only")]
    ReadOnly,
    #[error("configuration changed; refresh before saving or activating")]
    Conflict,
    #[error("a configuration is already starting")]
    Busy,
    #[error("switch away from this configuration before deleting it")]
    InUse,
    #[error("configuration storage unavailable")]
    Storage,
    #[error("configuration controls unavailable")]
    Unavailable,
}
