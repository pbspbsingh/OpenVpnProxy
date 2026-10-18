//! HTTP dashboard with live WebSocket snapshots and graceful shutdown control.

mod assets;
mod configuration;
mod history;
mod logs;
mod server;
mod types;

pub use configuration::{
    ConfigurationControl, ConfigurationError, ConfigurationFuture, ConfigurationInput,
    ConfigurationList, ConfigurationPhase, ConfigurationStatus, ConfigurationSummary,
    ProfileUpload,
};
pub use history::DashboardHistory;
pub use logs::{LogEvent, LogHub, LogInput};
pub use server::{DashboardSource, GroupError, UiError, serve};
pub use types::{
    DashboardSnapshot, GroupPage, GroupSnapshot, HostPhase, HostSnapshot, PoolPhase, PoolSnapshot,
    ProfileRemote, ProfileSummary,
};
