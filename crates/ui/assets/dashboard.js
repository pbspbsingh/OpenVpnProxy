import { createFeed } from "./lib/socket.js";
import { ratesBetween } from "./lib/history.js";

export function dashboardStore() {
  let feed;
  return {
    tab: "overview",
    frame: null,
    rates: { pool: { rx: 0, tx: 0 }, hosts: {} },
    feedKind: "connecting",
    feedLabel: "Connecting",
    selectedHostId: null,
    stopping: false,
    get snapshot() { return this.frame?.snapshot ?? null; },
    get pool() { return this.snapshot?.pool ?? null; },
    get hosts() { return this.snapshot?.hosts ?? []; },
    init() {
      feed = createFeed("/ws", {
        staleMs: 20_000,
        onStatus: (kind, label) => { this.feedKind = kind; this.feedLabel = label; },
        onMessage: frame => {
          if (frame?.snapshot?.version !== 1 || !Array.isArray(frame.history)) return false;
          this.rates = ratesBetween(frame.snapshot, this.snapshot);
          this.frame = frame;
          if (!this.hosts.some(host => host.id === this.selectedHostId)) {
            const fastest = this.hosts.filter(host => host.selected && host.latency_ms != null)
              .sort((a, b) => a.latency_ms - b.latency_ms)[0];
            this.selectedHostId = fastest?.id ?? this.hosts[0]?.id ?? null;
          }
        },
      });
      feed.start();
    },
    stop() { feed?.stop(); },
  };
}
