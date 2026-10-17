import { formatters } from "../lib/format.js";

export function hosts() {
  let request = null, timer = null;
  return {
    ...formatters,
    groups: [], total: 0,
    status: "Waiting for host selection",
    get hosts() { return this.$store.dashboard.hosts; },
    get selectedId() { return this.$store.dashboard.selectedHostId; },
    get host() { return this.hosts.find(host => host.id === this.selectedId) ?? null; },
    get active() { return this.$store.dashboard.tab === "hosts"; },
    get stats() {
      if (!this.host) return [];
      const rate = this.$store.dashboard.rates.hosts[this.selectedId];
      return [
        ["Latency", this.formatLatency(this.host.latency_ms)],
        ["Download", this.formatRate(rate?.rx ?? 0)],
        ["Upload", this.formatRate(rate?.tx ?? 0)],
        ["Active routes", this.host.active_routes.toLocaleString()],
        ["Sticky groups", this.host.sticky_groups.toLocaleString()],
        ["Score age", this.host.score_age_seconds == null ? "—" : `${this.host.score_age_seconds}s`],
        ["IPv6", this.host.ipv6 ? "Available" : "Unavailable"],
      ];
    },
    init() {
      this.$watch("selectedId", () => this.syncSelection());
      this.$watch("active", () => {
        if (this.active && this.groups.length === 0) this.loadGroups();
        else if (!this.active) this.cancel();
      });
      this.syncSelection();
      timer = setInterval(() => {
        if (this.active && this.groups.length <= 100) this.loadGroups();
      }, 10_000);
    },
    syncSelection() {
      this.cancel();
      this.groups = [];
      this.total = 0;
      this.status = "Waiting for host selection";
      this.loadGroups();
    },
    select(id) { this.$store.dashboard.selectedHostId = id; },
    cancel() { request?.abort(); request = null; },
    async loadGroups(append = false) {
      if (!this.active || this.selectedId == null || request) return;
      const hostId = this.selectedId;
      const offset = append ? this.groups.length : 0;
      const current = new AbortController();
      request = current;
      this.status = "Loading assignments…";
      try {
        const response = await fetch(`/api/hosts/${hostId}/groups?offset=${offset}`, { cache: "no-store", signal: current.signal });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const page = await response.json();
        if (request !== current || this.selectedId !== hostId) return;
        this.groups = append ? this.groups.concat(page.groups) : page.groups;
        this.total = page.total;
        this.status = `Showing ${this.groups.length.toLocaleString()} of ${page.total.toLocaleString()} · updated ${new Date().toLocaleTimeString()}`;
      } catch (error) {
        if (error.name !== "AbortError" && request === current) this.status = `Could not load assignments (${error.message})`;
      } finally {
        if (request === current) request = null;
      }
    },
    activity(group) {
      return group.active_connections > 0 ? `${group.active_connections} active`
        : `Idle · ${Math.ceil((group.idle_remaining_seconds ?? 0) / 60)} min left`;
    },
    destroy() { this.cancel(); clearInterval(timer); },
  };
}
