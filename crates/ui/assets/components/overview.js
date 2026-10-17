import { formatters } from "../lib/format.js";

export function overview() {
  return {
    ...formatters,
    get pool() { return this.$store.dashboard.pool; },
    get detail() {
      const snapshot = this.$store.dashboard.snapshot;
      if (!snapshot) return "Waiting for first snapshot";
      return snapshot.message ?? (this.pool.phase === "idle" && this.pool.idle_remaining_seconds != null
        ? `Closes in ${Math.ceil(this.pool.idle_remaining_seconds / 60)} min without traffic`
        : `${this.pool.ready_hosts} of ${this.pool.selected_hosts} selected hosts ready`);
    },
    get tone() {
      return this.pool?.phase === "ready" ? "good" : ["unavailable", "failed"].includes(this.pool?.phase) ? "bad" : "warn";
    },
  };
}
