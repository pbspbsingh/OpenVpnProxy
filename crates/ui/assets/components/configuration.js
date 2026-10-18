const MAX_PROFILE_BYTES = 256 * 1024;

export function configuration() {
  let listing = null, mutation = null, timer = null, upload = null, editVersion = 0;
  return {
    entries: [], status: null, loaded: false,
    editingId: null, readOnly: false, passwordSet: false,
    profileName: "", uploadName: "", reading: false, busy: false,
    notice: "", error: "",
    draft: { name: "", username: "", password: "", clearPassword: false, dns: "", limit: "", revision: null },
    get active() { return this.$store.dashboard.tab === "configuration" && !this.$store.dashboard.stopping; },
    get starting() { return this.status?.phase === "starting"; },
    get stateLabel() {
      if (!this.status || this.status.phase === "unconfigured") return "No configuration active";
      const phase = { starting: "Starting", ready: "Active", failed: "Failed" }[this.status.phase];
      return `${phase}: ${this.status.name}`;
    },
    init() {
      this.$watch("active", () => { if (this.active) this.load(true); else this.cancelList(); });
      timer = setInterval(() => { if (this.active && !this.busy) this.load(); }, 5_000);
      if (this.active) this.load();
    },
    cancelList() { listing?.abort(); listing = null; },
    async load(replace = false) {
      if (replace) this.cancelList();
      if (listing) return;
      const current = new AbortController();
      listing = current;
      try {
        const result = await this.api("/api/configurations", { signal: current.signal });
        if (listing !== current) return;
        this.entries = result.configurations;
        this.status = result.status;
        this.loaded = true;
      } catch (error) {
        if (error.name !== "AbortError" && listing === current) this.error = error.message;
      } finally { if (listing === current) listing = null; }
    },
    edit(entry = null) {
      editVersion++;
      upload = null;
      this.reading = false;
      this.editingId = entry?.id ?? null;
      this.readOnly = entry?.read_only ?? false;
      this.passwordSet = entry?.password_set ?? false;
      this.profileName = entry?.profile_name ?? "";
      this.uploadName = "";
      this.notice = this.error = "";
      this.draft = {
        name: entry?.name ?? "", username: entry?.username ?? "", password: "", clearPassword: false,
        dns: entry?.dns_override ?? "", limit: entry?.max_active_vpn_hosts ?? "", revision: entry?.revision ?? null,
      };
      this.$refs.file.value = "";
    },
    async chooseFile(event) {
      const file = event.target.files[0];
      const version = ++editVersion;
      upload = null;
      this.uploadName = "";
      this.error = "";
      this.reading = false;
      if (!file) return;
      if (file.size > MAX_PROFILE_BYTES) { this.error = "OpenVPN files must be at most 256 KiB"; event.target.value = ""; return; }
      this.reading = true;
      try {
        const content = await file.text();
        if (version !== editVersion) return;
        upload = { name: file.name, content };
        this.uploadName = file.name;
      } catch { if (version === editVersion) this.error = "Could not read the selected file"; }
      finally { if (version === editVersion) this.reading = false; }
    },
    async save() {
      if (this.busy || this.readOnly || this.reading) return;
      this.busy = true;
      this.error = this.notice = "";
      mutation = new AbortController();
      try {
        const id = this.editingId;
        const input = {
          name: this.draft.name, username: this.draft.username,
          password: this.draft.clearPassword ? "" : this.draft.password || null,
          profile: upload, revision: this.draft.revision,
          dns_override: this.draft.dns.trim() || null,
          max_active_vpn_hosts: this.draft.limit === "" ? null : Number(this.draft.limit),
        };
        const saved = await this.api(`/api/configurations${id ? `/${id}` : ""}`, {
          method: id ? "PUT" : "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify(input), signal: mutation.signal,
        });
        this.edit(saved);
        this.notice = "Saved. Activate this configuration to apply it.";
        await this.load(true);
      } catch (error) { if (error.name !== "AbortError") this.error = error.message; }
      finally { this.draft.password = ""; this.busy = false; mutation = null; }
    },
    async activate(entry) {
      if (this.busy || this.starting || !window.confirm(`Activate ${entry.name}? Existing proxy connections will close.`)) return;
      this.busy = true;
      this.error = this.notice = "";
      mutation = new AbortController();
      try {
        await this.api(`/api/configurations/${entry.id}/activate`, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ revision: entry.revision }), signal: mutation.signal,
        });
        this.notice = `Activation requested for ${entry.name}.`;
        await this.load(true);
      } catch (error) { if (error.name !== "AbortError") this.error = error.message; }
      finally { this.busy = false; mutation = null; }
    },
    inUse(entry) { return entry.id === this.status?.id && ["starting", "ready"].includes(this.status.phase); },
    async deleteEntry(entry) {
      if (this.busy || entry.read_only || this.inUse(entry) || !window.confirm(`Delete ${entry.name}? Its saved credentials and profile will be permanently removed.`)) return;
      this.busy = true;
      this.error = this.notice = "";
      mutation = new AbortController();
      try {
        await this.api(`/api/configurations/${entry.id}`, {
          method: "DELETE", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ revision: entry.revision }), signal: mutation.signal,
        });
        if (this.editingId === entry.id) this.edit();
        this.notice = `Deleted ${entry.name}.`;
        await this.load(true);
      } catch (error) { if (error.name !== "AbortError") this.error = error.message; }
      finally { this.busy = false; mutation = null; }
    },
    label(entry) {
      if (entry.id !== this.status?.id) return "Saved";
      if (entry.revision !== this.status.revision) return "Saved changes pending activation";
      return { starting: "Starting", ready: "Active", failed: "Activation failed" }[this.status.phase] ?? "Saved";
    },
    async api(path, options = {}) {
      const response = await fetch(path, { cache: "no-store", ...options });
      if ([202, 204].includes(response.status)) return null;
      const result = await response.json().catch(() => null);
      if (!response.ok) throw new Error(result?.error ?? `Request failed (HTTP ${response.status})`);
      return result;
    },
    destroy() { this.cancelList(); mutation?.abort(); clearInterval(timer); editVersion++; upload = null; this.draft.password = ""; },
  };
}
