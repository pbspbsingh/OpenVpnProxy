use serde::Serialize;

/// One complete, versioned dashboard update.
#[derive(Clone, Serialize)]
pub struct DashboardSnapshot {
    pub version: u8,
    pub sampled_at_ms: u64,
    pub message: Option<String>,
    pub pool: PoolSnapshot,
    pub hosts: Vec<HostSnapshot>,
}

/// Current state of the selected VPN pool.
#[derive(Clone, Serialize)]
pub struct PoolSnapshot {
    pub phase: PoolPhase,
    pub candidate_hosts: usize,
    pub selected_hosts: usize,
    pub ready_hosts: usize,
    pub max_active_hosts: usize,
    pub active_routes: usize,
    pub sticky_groups: usize,
    pub idle_remaining_seconds: Option<u64>,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
}

/// Current state and counters for one OpenVPN server.
#[derive(Clone, Serialize)]
pub struct HostSnapshot {
    pub id: usize,
    pub endpoint: String,
    pub phase: HostPhase,
    pub selected: bool,
    pub active_routes: usize,
    pub sticky_groups: usize,
    pub latency_ms: Option<f64>,
    pub score_age_seconds: Option<u64>,
    pub ipv6: bool,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
}

/// One page of sticky assignments for a VPN host.
#[derive(Serialize)]
pub struct GroupPage {
    pub total: usize,
    pub offset: usize,
    pub groups: Vec<GroupSnapshot>,
}

/// A source IP and destination group assigned to one VPN host.
#[derive(Serialize)]
pub struct GroupSnapshot {
    pub source: String,
    pub destination: String,
    pub active_connections: usize,
    pub idle_remaining_seconds: Option<u64>,
}

/// Safe, operational settings from the loaded OpenVPN profile.
#[derive(Clone, Serialize)]
pub struct ProfileSummary {
    pub remotes: Vec<ProfileRemote>,
    pub credentials_required: bool,
    pub ipv6_blocked: bool,
    pub server_certificate_purpose_required: bool,
    pub renegotiate_after_seconds: Option<u64>,
    pub handshake_window_seconds: u64,
    pub transition_window_seconds: u64,
}

#[derive(Clone, Serialize)]
pub struct ProfileRemote {
    pub host: String,
    pub port: u16,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolPhase {
    Starting,
    Dormant,
    Waking,
    Ready,
    Degraded,
    Idle,
    Unavailable,
    Failed,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HostPhase {
    Dormant,
    Connecting,
    Ready,
    Backoff,
    Stopped,
}

/// One WebSocket message: current status plus one hour of minute buckets.
#[derive(Serialize)]
pub(crate) struct DashboardFrame {
    pub(crate) snapshot: DashboardSnapshot,
    pub(crate) history: Vec<MinuteSample>,
}

#[derive(Serialize)]
pub(crate) struct MinuteSample {
    pub(crate) minute_start_ms: u64,
    pub(crate) tx_bytes: u64,
    pub(crate) rx_bytes: u64,
    pub(crate) average_latency_ms: Option<f64>,
    pub(crate) hosts: Vec<HostMinuteSample>,
}

#[derive(Serialize)]
pub(crate) struct HostMinuteSample {
    pub(crate) host_id: usize,
    pub(crate) tx_bytes: u64,
    pub(crate) rx_bytes: u64,
    pub(crate) average_latency_ms: Option<f64>,
}
