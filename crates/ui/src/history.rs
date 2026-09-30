use std::collections::{BTreeMap, VecDeque};

use crate::types::{DashboardFrame, DashboardSnapshot, HostMinuteSample, MinuteSample};

const MILLIS_PER_MINUTE: u64 = 60_000;
const HISTORY_MINUTES: usize = 60;

pub(crate) struct MinuteHistory {
    buckets: VecDeque<MinuteBucket>,
    previous_sample_ms: Option<u64>,
    previous_tx: Option<u64>,
    previous_rx: Option<u64>,
    previous_hosts: BTreeMap<usize, (u64, u64)>,
}

struct MinuteBucket {
    start_ms: u64,
    observed_ms: u64,
    tx_bytes: u64,
    rx_bytes: u64,
    latency_sum_ms: f64,
    latency_samples: u64,
    hosts: BTreeMap<usize, HostAggregate>,
}

#[derive(Default)]
struct HostAggregate {
    tx_bytes: u64,
    rx_bytes: u64,
    latency_sum_ms: f64,
    latency_samples: u64,
}

impl MinuteHistory {
    pub(crate) fn new() -> Self {
        Self {
            buckets: VecDeque::with_capacity(HISTORY_MINUTES),
            previous_sample_ms: None,
            previous_tx: None,
            previous_rx: None,
            previous_hosts: BTreeMap::new(),
        }
    }

    pub(crate) fn observe(&mut self, snapshot: DashboardSnapshot) -> DashboardFrame {
        let minute = snapshot.sampled_at_ms / MILLIS_PER_MINUTE * MILLIS_PER_MINUTE;
        let observed_ms = self.previous_sample_ms.map_or(0, |previous| {
            snapshot.sampled_at_ms.saturating_sub(previous)
        });
        self.previous_sample_ms = Some(snapshot.sampled_at_ms);
        let tx_delta = self.previous_tx.map_or(0, |previous| {
            snapshot.pool.tx_bytes.saturating_sub(previous)
        });
        let rx_delta = self.previous_rx.map_or(0, |previous| {
            snapshot.pool.rx_bytes.saturating_sub(previous)
        });
        self.previous_tx = Some(snapshot.pool.tx_bytes);
        self.previous_rx = Some(snapshot.pool.rx_bytes);

        if self
            .buckets
            .back()
            .is_none_or(|bucket| minute > bucket.start_ms)
        {
            self.buckets.push_back(MinuteBucket {
                start_ms: minute,
                observed_ms: 0,
                tx_bytes: 0,
                rx_bytes: 0,
                latency_sum_ms: 0.0,
                latency_samples: 0,
                hosts: BTreeMap::new(),
            });
        }
        let cutoff = minute.saturating_sub((HISTORY_MINUTES as u64 - 1) * MILLIS_PER_MINUTE);
        while self
            .buckets
            .front()
            .is_some_and(|bucket| bucket.start_ms < cutoff)
        {
            self.buckets.pop_front();
        }
        if let Some(bucket) = self
            .buckets
            .back_mut()
            .filter(|bucket| bucket.start_ms == minute)
        {
            bucket.observed_ms = bucket.observed_ms.saturating_add(observed_ms);
            bucket.tx_bytes = bucket.tx_bytes.saturating_add(tx_delta);
            bucket.rx_bytes = bucket.rx_bytes.saturating_add(rx_delta);
            for host in &snapshot.hosts {
                let previous = self
                    .previous_hosts
                    .insert(host.id, (host.tx_bytes, host.rx_bytes));
                let aggregate = bucket.hosts.entry(host.id).or_default();
                aggregate.tx_bytes = aggregate
                    .tx_bytes
                    .saturating_add(previous.map_or(0, |(tx, _)| host.tx_bytes.saturating_sub(tx)));
                aggregate.rx_bytes = aggregate
                    .rx_bytes
                    .saturating_add(previous.map_or(0, |(_, rx)| host.rx_bytes.saturating_sub(rx)));
                if let Some(latency_ms) = host.latency_ms {
                    aggregate.latency_sum_ms += latency_ms;
                    aggregate.latency_samples += 1;
                    if host.selected {
                        bucket.latency_sum_ms += latency_ms;
                        bucket.latency_samples += 1;
                    }
                }
            }
        }

        DashboardFrame {
            snapshot,
            history: self.buckets.iter().map(MinuteBucket::sample).collect(),
        }
    }
}

impl MinuteBucket {
    fn sample(&self) -> MinuteSample {
        MinuteSample {
            minute_start_ms: self.start_ms,
            observed_ms: self.observed_ms,
            tx_bytes: self.tx_bytes,
            rx_bytes: self.rx_bytes,
            average_latency_ms: (self.latency_samples > 0)
                .then_some(self.latency_sum_ms / self.latency_samples as f64),
            hosts: self
                .hosts
                .iter()
                .map(|(&host_id, aggregate)| HostMinuteSample {
                    host_id,
                    tx_bytes: aggregate.tx_bytes,
                    rx_bytes: aggregate.rx_bytes,
                    average_latency_ms: (aggregate.latency_samples > 0)
                        .then_some(aggregate.latency_sum_ms / aggregate.latency_samples as f64),
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{HostPhase, HostSnapshot, PoolPhase, PoolSnapshot};

    fn snapshot(
        at_ms: u64,
        tx: u64,
        rx: u64,
        latency_ms: f64,
        selected: bool,
    ) -> DashboardSnapshot {
        DashboardSnapshot {
            version: 1,
            sampled_at_ms: at_ms,
            message: None,
            pool: PoolSnapshot {
                phase: PoolPhase::Ready,
                candidate_hosts: 1,
                selected_hosts: usize::from(selected),
                ready_hosts: usize::from(selected),
                max_active_hosts: 1,
                active_routes: 0,
                sticky_groups: 0,
                idle_remaining_seconds: None,
                tx_bytes: tx,
                rx_bytes: rx,
            },
            hosts: vec![HostSnapshot {
                id: 0,
                endpoint: "127.0.0.1:1194".into(),
                phase: HostPhase::Ready,
                selected,
                active_routes: 0,
                sticky_groups: 0,
                latency_ms: Some(latency_ms),
                score_age_seconds: Some(0),
                ipv6: false,
                tx_bytes: tx,
                rx_bytes: rx,
            }],
        }
    }

    #[test]
    fn aggregates_deltas_and_selection_at_sample_time() {
        let mut history = MinuteHistory::new();
        history.observe(snapshot(30_000, 10, 20, 40.0, true));
        history.observe(snapshot(31_000, 30, 50, 60.0, true));
        let frame = history.observe(snapshot(32_000, 35, 65, 100.0, false));
        let minute = &frame.history[0];
        assert_eq!(minute.minute_start_ms, 0);
        assert_eq!(minute.observed_ms, 2_000);
        assert_eq!((minute.tx_bytes, minute.rx_bytes), (25, 45));
        assert_eq!(minute.average_latency_ms, Some(50.0));
        assert_eq!(
            (minute.hosts[0].tx_bytes, minute.hosts[0].rx_bytes),
            (25, 45)
        );
        assert_eq!(minute.hosts[0].average_latency_ms, Some(200.0 / 3.0));
    }

    #[test]
    fn drops_buckets_older_than_the_last_hour_even_after_a_gap() {
        let mut history = MinuteHistory::new();
        history.observe(snapshot(0, 0, 0, 40.0, true));
        let frame = history.observe(snapshot(60 * MILLIS_PER_MINUTE, 20, 30, 50.0, true));
        assert_eq!(frame.history.len(), 1);
        assert_eq!(frame.history[0].minute_start_ms, 60 * MILLIS_PER_MINUTE);
        assert_eq!(
            (frame.history[0].tx_bytes, frame.history[0].rx_bytes),
            (20, 30)
        );
    }
}
