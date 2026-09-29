//! Read-only HTTP dashboard with live WebSocket snapshots.

mod history;
mod logs;
mod server;
mod types;

pub use logs::{LogEvent, LogHub, LogInput};
pub use server::{GroupError, SnapshotSource, UiError, serve};
pub use types::{
    DashboardSnapshot, GroupPage, GroupSnapshot, HostPhase, HostSnapshot, PoolPhase, PoolSnapshot,
    ProfileRemote, ProfileSummary,
};
