import { formatters } from "../lib/format.js";

export function profile() {
  let request = null, generation = null;
  return {
    ...formatters,
    summary: null,
    status: "Loading profile summary…",
    init() {
      this.load();
      this.$watch("$store.dashboard.frame", () => {
        const next = this.$store.dashboard.snapshot?.configuration?.generation;
        if (next !== generation) {
          generation = next;
          request?.abort();
          request = null;
          this.summary = null;
          this.status = "Loading profile summary…";
        }
        if (!this.summary && this.$store.dashboard.pool?.phase !== "starting") this.load();
      });
      this.$watch("$store.dashboard.tab", tab => { if (tab === "profile" && !this.summary) this.load(); });
    },
    async load() {
      if (request) return;
      const current = new AbortController();
      request = current;
      try {
        const response = await fetch("/api/profile", { cache: "no-store", signal: current.signal });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const profile = await response.json();
        if (request !== current) return;
        if (!Array.isArray(profile.remotes)) throw new Error("Invalid profile summary");
        if (profile.remotes.length === 0) {
          this.status = this.$store.dashboard.pool?.phase === "failed" ? "Profile unavailable; see Overview" : "Waiting for OpenVPN profile";
          return;
        }
        this.summary = profile;
        this.status = `${profile.remotes.length} configured remote${profile.remotes.length === 1 ? "" : "s"}`;
      } catch (error) {
        if (error.name !== "AbortError" && request === current) this.status = `Could not load profile summary (${error.message})`;
      } finally {
        if (request === current) request = null;
      }
    },
    destroy() { request?.abort(); request = null; },
  };
}
