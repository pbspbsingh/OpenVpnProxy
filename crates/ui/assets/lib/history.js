export const MINUTE_MS = 60_000;
export const HISTORY_MINUTES = 60;

export function minuteSeries(history, sampledAtMs, valueForBucket) {
  const currentMinute = Math.floor(sampledAtMs / MINUTE_MS) * MINUTE_MS;
  const indexed = new Map(history.map(bucket => [bucket.minute_start_ms, bucket]));
  return Array.from({ length: HISTORY_MINUTES }, (_, offset) => {
    const bucket = indexed.get(currentMinute - (HISTORY_MINUTES - 1 - offset) * MINUTE_MS);
    return bucket ? valueForBucket(bucket) : null;
  });
}

export function bucketRate(bytes, observedMs) {
  return observedMs > 0 ? bytes * 1000 / observedMs : null;
}

/** Missing hosts, counter resets and stale intervals never produce artificial spikes. */
export function ratesBetween(snapshot, previous) {
  const seconds = previous ? (snapshot.sampled_at_ms - previous.sampled_at_ms) / 1000 : 0;
  const valid = seconds > 0 && seconds <= 20 && snapshot.configuration?.generation === previous?.configuration?.generation;
  const rate = (current, older) => valid && older != null && current >= older ? (current - older) / seconds : 0;
  const counters = (current, older) => ({ rx: rate(current.rx_bytes, older?.rx_bytes), tx: rate(current.tx_bytes, older?.tx_bytes) });
  const priorHosts = new Map((previous?.hosts ?? []).map(host => [host.id, host]));
  return {
    pool: counters(snapshot.pool, previous?.pool),
    hosts: Object.fromEntries(snapshot.hosts.map(host => [host.id, counters(host, priorHosts.get(host.id))])),
  };
}
