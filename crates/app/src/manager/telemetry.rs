use std::sync::atomic::{AtomicU64, Ordering};

/// Monotonic tunnel byte counters shared with the dashboard sampler.
#[derive(Default)]
pub(super) struct HostTraffic {
    tx_bytes: AtomicU64,
    rx_bytes: AtomicU64,
}

impl HostTraffic {
    pub(super) fn add_tx(&self, bytes: usize) {
        self.tx_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub(super) fn add_rx(&self, bytes: usize) {
        self.rx_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub(super) fn snapshot(&self) -> (u64, u64) {
        (
            self.tx_bytes.load(Ordering::Relaxed),
            self.rx_bytes.load(Ordering::Relaxed),
        )
    }
}
