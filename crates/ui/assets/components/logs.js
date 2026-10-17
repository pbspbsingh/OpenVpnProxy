import { createFeed } from "../lib/socket.js";

const INITIAL_VISIBLE = 2000;
const RANK = { TRACE: 0, DEBUG: 1, INFO: 2, WARN: 3, ERROR: 4 };

export function logs() {
  // Incoming events stay outside Alpine's proxies; publish at most once per frame.
  let entries = [], head = 0, capacity = 1000, sequence = 0, scheduled = null, feed;
  let dirty = false;
  return {
    rows: [], buffered: 0, matching: 0,
    level: "ALL", visibleLimit: INITIAL_VISIBLE, dropped: 0,
    status: "Opens when this tab is selected",
    get active() { return this.$store.dashboard.tab === "logs"; },
    get count() { return `${this.rows.length.toLocaleString()} of ${this.matching.toLocaleString()} matching · ${this.buffered.toLocaleString()} buffered`; },
    init() {
      feed = createFeed("/ws/logs", {
        onStatus: (_, label) => { this.status = label; },
        onMessage: message => this.receive(message),
      });
      this.$watch("active", () => {
        if (this.active) feed.start();
        else { feed.stop(); this.status = feed.exhausted ? "Disconnected" : "Paused while tab is closed"; }
      });
      if (this.active) feed.start();
    },
    receive(message) {
      if (message?.type === "reset") {
        capacity = Math.max(1, Math.min(20_000, message.capacity));
        entries = [];
        head = 0;
        sequence = 0;
        dirty = true;
        this.visibleLimit = INITIAL_VISIBLE;
        this.dropped = message.dropped;
      } else if (message?.type === "batch" && Array.isArray(message.entries)) {
        for (const entry of message.entries) this.append(entry);
      } else if (message?.type === "entry" && message.entry) {
        this.append(message.entry);
      } else if (message?.type === "dropped") {
        this.dropped = message.count;
      } else return false;
      this.schedule();
    },
    append(entry) {
      if (entry.sequence <= sequence) return;
      sequence = entry.sequence;
      entries.push(entry);
      if (this.matches(entry)) dirty = true;
      if (entries.length - head > capacity) {
        if (this.matches(entries[head])) dirty = true;
        head++;
      }
      if (head >= capacity) { entries = entries.slice(head); head = 0; }
    },
    schedule() {
      if (scheduled != null) return;
      scheduled = requestAnimationFrame(() => { scheduled = null; this.render(); });
    },
    matches(entry) {
      return this.level === "ALL" || (RANK[entry.level] ?? -1) >= RANK[this.level];
    },
    render(force = false) {
      this.buffered = entries.length - head;
      if (!dirty && !force) return;
      const scroll = this.$refs.scroll;
      const follow = scroll.scrollHeight - scroll.scrollTop - scroll.clientHeight < 40;
      const matching = entries.slice(head).filter(entry => this.matches(entry));
      this.rows = matching.slice(-this.visibleLimit);
      this.matching = matching.length;
      dirty = false;
      if (follow) this.$nextTick(() => { scroll.scrollTop = scroll.scrollHeight; });
    },
    older() {
      this.visibleLimit += INITIAL_VISIBLE;
      this.render(true);
      this.$nextTick(() => { this.$refs.scroll.scrollTop = 0; });
    },
    time(timestamp) { return new Date(timestamp).toLocaleTimeString(); },
    destroy() { feed.stop(); cancelAnimationFrame(scheduled); },
  };
}
