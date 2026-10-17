export function shell() {
  return {
    tabs: ["overview", "hosts", "routing", "profile", "logs"],
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
