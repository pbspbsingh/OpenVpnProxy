export function shell() {
  return {
    tabs: ["overview", "hosts", "routing", "profile", "configuration", "logs"],
    shuttingDown: false,
    shutdownAccepted: false,
    shutdownError: "",
    async shutdown() {
      if (this.shuttingDown || !window.confirm("Shut down the proxy? Active connections will close.")) return;
      this.shuttingDown = true;
      this.shutdownError = "";
      try {
        const response = await fetch("/api/shutdown", { method: "POST", cache: "no-store" });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        this.shutdownAccepted = true;
        this.$store.dashboard.stopping = true;
        this.$store.dashboard.stop();
        this.$store.dashboard.feedKind = "offline";
        this.$store.dashboard.feedLabel = "Shutdown requested";
      } catch (error) {
        this.shutdownError = `Could not shut down (${error.message}). Try again.`;
        this.shuttingDown = false;
      }
    },
    selectTab(tab) { this.$store.dashboard.tab = tab; },
    moveTab(event) {
      const index = this.tabs.indexOf(this.$store.dashboard.tab);
      const next = event.key === "Home" ? 0 : event.key === "End" ? this.tabs.length - 1
        : (index + (event.key === "ArrowRight" ? 1 : -1) + this.tabs.length) % this.tabs.length;
      event.preventDefault();
      this.selectTab(this.tabs[next]);
      this.$nextTick(() => this.$el.querySelector(`[data-tab="${this.tabs[next]}"]`).focus());
    },
    destroy() { this.$store.dashboard.stop(); },
  };
}
