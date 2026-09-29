use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use ovpn_ui::{
    DashboardSnapshot, GroupError, GroupPage, PoolPhase, PoolSnapshot, ProfileSummary,
    SnapshotSource,
};

use crate::manager::RouterHandle;

#[derive(Clone)]
pub(crate) struct DashboardSource {
    state: Arc<RwLock<DashboardState>>,
    profile: Arc<RwLock<Option<ProfileSummary>>>,
}

enum DashboardState {
    Starting(&'static str),
    Running(RouterHandle),
    Failed {
        error: String,
        router: Option<RouterHandle>,
    },
}

impl DashboardSource {
    pub(crate) fn new() -> Self {
        Self {
            state: Arc::new(RwLock::new(DashboardState::Starting("Starting proxy"))),
            profile: Arc::new(RwLock::new(None)),
        }
    }

    pub(crate) fn starting(&self, stage: &'static str) {
        self.replace(DashboardState::Starting(stage));
    }

    pub(crate) fn running(&self, router: RouterHandle) {
        self.replace(DashboardState::Running(router));
    }

    pub(crate) fn profile_loaded(&self, summary: ProfileSummary) {
        match self.profile.write() {
            Ok(mut profile) => *profile = Some(summary),
            Err(_) => tracing::error!("dashboard profile state lock poisoned"),
        }
    }

    pub(crate) fn failed(&self, error: String) {
        match self.state.write() {
            Ok(mut state) => {
                let router = match &*state {
                    DashboardState::Running(router) => Some(router.clone()),
                    DashboardState::Failed { router, .. } => router.clone(),
                    DashboardState::Starting(_) => None,
                };
                *state = DashboardState::Failed { error, router };
            }
            Err(_) => tracing::error!("dashboard lifecycle state lock poisoned"),
        }
    }

    fn replace(&self, next: DashboardState) {
        match self.state.write() {
            Ok(mut state) => *state = next,
            Err(_) => tracing::error!("dashboard lifecycle state lock poisoned"),
        }
    }

    fn router(&self) -> Option<RouterHandle> {
        self.state.read().ok().and_then(|state| match &*state {
            DashboardState::Running(router) => Some(router.clone()),
            DashboardState::Failed { router, .. } => router.clone(),
            DashboardState::Starting(_) => None,
        })
    }
}

impl SnapshotSource for DashboardSource {
    fn snapshot(&self) -> DashboardSnapshot {
        let (phase, message) = match self.state.read() {
            Ok(state) => match &*state {
                DashboardState::Running(router) => return router.snapshot(),
                DashboardState::Starting(stage) => (PoolPhase::Starting, (*stage).to_owned()),
                DashboardState::Failed { error, router } => {
                    if let Some(router) = router {
                        let mut snapshot = router.snapshot();
                        snapshot.pool.phase = PoolPhase::Failed;
                        snapshot.message = Some(error.clone());
                        return snapshot;
                    }
                    (PoolPhase::Failed, error.clone())
                }
            },
            Err(_) => (PoolPhase::Unavailable, "Dashboard state unavailable".into()),
        };
        let sampled_at_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
            .unwrap_or_default();
        DashboardSnapshot {
            version: 1,
            sampled_at_ms,
            message: Some(message),
            pool: PoolSnapshot {
                phase,
                candidate_hosts: 0,
                selected_hosts: 0,
                ready_hosts: 0,
                max_active_hosts: 0,
                active_routes: 0,
                sticky_groups: 0,
                idle_remaining_seconds: None,
                tx_bytes: 0,
                rx_bytes: 0,
            },
            hosts: Vec::new(),
        }
    }

    fn group_page(
        &self,
        host_id: usize,
        offset: usize,
        limit: usize,
    ) -> Result<Option<GroupPage>, GroupError> {
        match self.router() {
            Some(router) => router.group_page(host_id, offset, limit),
            None => Ok(None),
        }
    }

    fn profile(&self) -> ProfileSummary {
        if let Ok(profile) = self.profile.read()
            && let Some(profile) = &*profile
        {
            return profile.clone();
        }
        ProfileSummary {
            remotes: Vec::new(),
            credentials_required: false,
            ipv6_blocked: false,
            server_certificate_purpose_required: false,
            renegotiate_after_seconds: None,
            handshake_window_seconds: 0,
            transition_window_seconds: 0,
        }
    }
}
