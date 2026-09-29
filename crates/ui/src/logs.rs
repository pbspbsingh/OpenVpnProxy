use std::collections::VecDeque;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use serde::Serialize;
use tokio::sync::{broadcast, mpsc};

const LOG_INPUT_QUEUE: usize = 2048;
const LOG_BROADCAST_QUEUE: usize = 256;
const LOG_WORKER_BATCH: usize = 64;

#[derive(Serialize)]
pub struct LogEvent {
    pub timestamp_ms: u64,
    pub level: String,
    pub target: String,
    pub message: String,
}

#[derive(Serialize)]
pub(crate) struct LogEntry {
    pub sequence: u64,
    #[serde(flatten)]
    pub event: LogEvent,
}

#[derive(Clone)]
pub struct LogInput {
    sender: mpsc::Sender<LogEvent>,
    dropped: Arc<AtomicU64>,
}

#[derive(Clone)]
pub struct LogHub {
    entries: Arc<Mutex<VecDeque<Arc<LogEntry>>>>,
    updates: broadcast::Sender<Arc<LogEntry>>,
    dropped: Arc<AtomicU64>,
    capacity: usize,
}

impl LogInput {
    pub fn record(&self, event: LogEvent) {
        if self.sender.try_send(event).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl LogHub {
    pub fn start(capacity: NonZeroUsize) -> (Self, LogInput) {
        let capacity = capacity.get();
        let (sender, mut receiver) = mpsc::channel(LOG_INPUT_QUEUE);
        let (updates, _) = broadcast::channel(LOG_BROADCAST_QUEUE);
        let dropped = Arc::new(AtomicU64::new(0));
        let hub = Self {
            entries: Arc::new(Mutex::new(VecDeque::with_capacity(capacity))),
            updates,
            dropped: Arc::clone(&dropped),
            capacity,
        };
        let worker = hub.clone();
        tokio::spawn(async move {
            let mut sequence = 0_u64;
            let mut processed = 0_usize;
            while let Some(event) = receiver.recv().await {
                sequence = sequence.wrapping_add(1);
                let entry = Arc::new(LogEntry { sequence, event });
                match worker.entries.lock() {
                    Ok(mut entries) => {
                        if entries.len() == worker.capacity {
                            entries.pop_front();
                        }
                        entries.push_back(Arc::clone(&entry));
                    }
                    Err(_) => {
                        worker.dropped.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                }
                let _ = worker.updates.send(entry);
                processed += 1;
                if processed == LOG_WORKER_BATCH {
                    processed = 0;
                    tokio::task::yield_now().await;
                }
            }
        });
        (hub, LogInput { sender, dropped })
    }

    pub(crate) fn subscribe(&self) -> broadcast::Receiver<Arc<LogEntry>> {
        self.updates.subscribe()
    }

    pub(crate) fn snapshot(&self) -> Option<Vec<Arc<LogEntry>>> {
        self.entries
            .lock()
            .ok()
            .map(|entries| entries.iter().cloned().collect())
    }

    pub(crate) fn capacity(&self) -> usize {
        self.capacity
    }

    pub(crate) fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}
