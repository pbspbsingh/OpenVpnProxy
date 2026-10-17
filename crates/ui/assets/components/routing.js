import { formatters } from "../lib/format.js";

export function routing() {
  return {
    ...formatters,
    get pool() { return this.$store.dashboard.pool; },
    get hosts() { return this.$store.dashboard.hosts; },
    get idle() {
      return this.pool?.idle_remaining_seconds == null ? "Not counting down"
        : `${Math.ceil(this.pool.idle_remaining_seconds / 60)} min remaining`;
    },
  };
}
