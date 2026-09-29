"use strict";

const MINUTE_MS = 60_000;
const HISTORY_MINUTES = 60;
const WS_INTERVAL_MS = 5_000;
const WS_STALE_MS = WS_INTERVAL_MS * 4;
const WS_HEALTH_CHECK_MS = 2_000;
const MAX_RATE_SAMPLE_GAP_SECONDS = WS_STALE_MS / 1000;
const COLORS = { rx: "#42d5c8", tx: "#8f9dff", latency: "#f1bd77" };
const state = { frame: null, previous: null, rates: null, hostRates: new Map(), selectedHostId: null, tab: "overview", socket: null, retryMs: 1000, lastMessageAt: 0, groupHostId: null, groupItems: [], groupTotal: 0, groupRequest: null, profileLoaded: false, profileRequest: false };
const $ = (id) => document.getElementById(id);

function text(id, value) { $(id).textContent = value; }
function humanPhase(phase) { return phase ? phase.replaceAll("_", " ").replace(/^./, (c) => c.toUpperCase()) : "Unknown"; }
function formatBytes(bytes) {
  if (!Number.isFinite(bytes)) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = Math.max(0, bytes);
  let unit = 0;
  while (value >= 1000 && unit < units.length - 1) { value /= 1000; unit++; }
  return `${value.toFixed(unit === 0 ? 0 : value >= 100 ? 0 : 1)} ${units[unit]}`;
}
function formatRate(bytesPerSecond) { return `${formatBytes(bytesPerSecond)}/s`; }
function formatLatency(ms) { return ms == null ? "—" : `${ms.toFixed(1)} ms`; }
function make(tag, className, value) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (value != null) node.textContent = value;
  return node;
}
function setFeed(kind, label) {
  const node = $("feed-status");
  node.className = `feed-status ${kind}`;
  text("feed-label", label);
}

function connect() {
  setFeed("connecting", "Connecting");
  const scheme = location.protocol === "https:" ? "wss:" : "ws:";
  const socket = new WebSocket(`${scheme}//${location.host}/ws`);
  state.socket = socket;
  socket.onopen = () => { state.retryMs = 1000; state.lastMessageAt = Date.now(); setFeed("live", "Live"); };
  socket.onmessage = (event) => {
    let frame;
    try { frame = JSON.parse(event.data); } catch { return; }
    if (frame?.snapshot?.version !== 1 || !Array.isArray(frame.history)) return;
    state.lastMessageAt = Date.now();
    state.previous = state.frame?.snapshot ?? null;
    state.frame = frame;
    updateRates(frame.snapshot);
    render();
    if (!state.profileLoaded && !state.profileRequest && (state.tab === "profile" || frame.snapshot.pool.phase !== "starting")) loadProfile();
  };
  socket.onerror = () => socket.close();
  socket.onclose = () => {
    if (state.socket !== socket) return;
    setFeed("offline", "Reconnecting");
    const delay = state.retryMs;
    state.retryMs = Math.min(state.retryMs * 2, 10000);
    window.setTimeout(connect, delay);
  };
}

function updateRates(snapshot) {
  const previous = state.previous;
  const seconds = previous ? (snapshot.sampled_at_ms - previous.sampled_at_ms) / 1000 : 0;
  const valid = seconds > 0 && seconds <= MAX_RATE_SAMPLE_GAP_SECONDS;
  const rate = (current, older) => valid && current >= older ? (current - older) / seconds : 0;
  state.rates = {
    rx: rate(snapshot.pool.rx_bytes, previous?.pool.rx_bytes ?? snapshot.pool.rx_bytes),
    tx: rate(snapshot.pool.tx_bytes, previous?.pool.tx_bytes ?? snapshot.pool.tx_bytes),
  };
  const priorHosts = new Map((previous?.hosts ?? []).map((host) => [host.id, host]));
  state.hostRates = new Map(snapshot.hosts.map((host) => {
    const old = priorHosts.get(host.id);
    return [host.id, { rx: rate(host.rx_bytes, old?.rx_bytes ?? host.rx_bytes), tx: rate(host.tx_bytes, old?.tx_bytes ?? host.tx_bytes) }];
  }));
}

function render() {
  const frame = state.frame;
  if (!frame) return;
  const { snapshot } = frame;
  text("last-update", new Date(snapshot.sampled_at_ms).toLocaleTimeString());
  renderOverview(snapshot);
  renderHosts(snapshot);
  renderRouting(snapshot);
  requestAnimationFrame(renderCharts);
}

function renderOverview(snapshot) {
  const pool = snapshot.pool;
  const phase = $("pool-phase");
  phase.textContent = humanPhase(pool.phase);
  phase.className = `metric-value status-text ${pool.phase === "ready" ? "good" : ["unavailable", "failed"].includes(pool.phase) ? "bad" : "warn"}`;
  text("pool-detail", snapshot.message ?? (pool.phase === "idle" && pool.idle_remaining_seconds != null
    ? `Closes in ${Math.ceil(pool.idle_remaining_seconds / 60)} min without traffic`
    : `${pool.ready_hosts} of ${pool.selected_hosts} selected hosts ready`));
  $("pool-detail").classList.toggle("error", pool.phase === "failed");
  $("pool-detail").title = snapshot.message ?? "";
  text("active-routes", pool.active_routes.toLocaleString());
  text("system-rx-rate", formatRate(state.rates?.rx ?? 0));
  text("system-tx-rate", formatRate(state.rates?.tx ?? 0));
  text("system-rx-total", `Total ${formatBytes(pool.rx_bytes)}`);
  text("system-tx-total", `Total ${formatBytes(pool.tx_bytes)}`);
  text("hosts-ready", `${pool.ready_hosts} / ${pool.selected_hosts}`);
  text("sticky-count", pool.sticky_groups.toLocaleString());
  text("candidate-count", pool.candidate_hosts.toLocaleString());
  text("active-limit", pool.max_active_hosts.toLocaleString());
}

function renderHosts(snapshot) {
  const focusedHostId = document.activeElement?.closest?.("button[data-host-id]")?.dataset.hostId;
  if (state.selectedHostId == null || !snapshot.hosts.some((host) => host.id === state.selectedHostId)) {
    const fastest = snapshot.hosts.filter((host) => host.selected && host.latency_ms != null)
      .sort((a, b) => a.latency_ms - b.latency_ms)[0];
    state.selectedHostId = fastest?.id ?? snapshot.hosts[0]?.id ?? null;
  }
  if (state.groupHostId !== state.selectedHostId) {
    state.groupRequest?.abort();
    state.groupRequest = null;
    state.groupHostId = state.selectedHostId;
    state.groupItems = [];
    state.groupTotal = 0;
    renderGroups();
    if (state.tab === "hosts" && state.selectedHostId != null) loadGroups();
  }
  const cards = snapshot.hosts.map((host) => {
    const card = make("button", `host-item${host.id === state.selectedHostId ? " selected" : ""}`);
    card.type = "button";
    card.dataset.hostId = String(host.id);
    card.setAttribute("aria-pressed", String(host.id === state.selectedHostId));
    const top = make("div", "host-item-top");
    top.append(make("span", "host-item-title", `Host ${host.id + 1}`), make("span", "host-item-speed", host.selected ? "SELECTED" : "STANDBY"));
    const bottom = make("div", "host-item-bottom");
    const speed = make("span", "host-item-speed");
    speed.append(make("strong", "", formatRate(state.hostRates.get(host.id)?.rx ?? 0)), document.createTextNode(" down"));
    bottom.append(make("span", "host-item-endpoint", host.endpoint), speed);
    card.append(top, bottom);
    return card;
  });
  $("host-list").replaceChildren(...cards);
  if (focusedHostId != null) {
    cards.find((card) => card.dataset.hostId === focusedHostId)?.focus({ preventScroll: true });
  }

  const host = snapshot.hosts.find((entry) => entry.id === state.selectedHostId);
  if (!host) {
    text("assigned-group-count", "0");
    text("selected-host-name", "No hosts available");
    text("selected-host-endpoint", "—");
    text("selected-host-badge", "—");
    $("selected-host-badge").className = "phase-badge";
    $("selected-host-stats").replaceChildren();
    return;
  }
  text("assigned-group-count", host.sticky_groups.toLocaleString());
  text("selected-host-name", `Host ${host.id + 1}`);
  text("selected-host-endpoint", host.endpoint);
  const badge = $("selected-host-badge");
  badge.textContent = humanPhase(host.phase);
  badge.className = `phase-badge ${host.phase}`;
  const stats = [
    ["Latency", formatLatency(host.latency_ms)],
    ["Download", formatRate(state.hostRates.get(host.id)?.rx ?? 0)],
    ["Upload", formatRate(state.hostRates.get(host.id)?.tx ?? 0)],
    ["Active routes", host.active_routes.toLocaleString()],
    ["Sticky groups", host.sticky_groups.toLocaleString()],
    ["Score age", host.score_age_seconds == null ? "—" : `${host.score_age_seconds}s`],
    ["IPv6", host.ipv6 ? "Available" : "Unavailable"],
  ];
  $("selected-host-stats").replaceChildren(...stats.map(([label, value]) => {
    const item = make("span", "", `${label} `);
    item.append(make("strong", "", value));
    return item;
  }));
}

function renderGroups() {
  const rows = state.groupItems.map((group) => {
    const row = document.createElement("tr");
    const activity = group.active_connections > 0
      ? `${group.active_connections} active`
      : `Idle · ${Math.ceil((group.idle_remaining_seconds ?? 0) / 60)} min left`;
    row.append(make("td", "", group.source), make("td", "", group.destination), make("td", "", activity));
    return row;
  });
  if (rows.length === 0) {
    const row = document.createElement("tr");
    const cell = make("td", "groups-empty", "No assignments for this host");
    cell.colSpan = 3;
    row.append(cell);
    rows.push(row);
  }
  $("groups-rows").replaceChildren(...rows);
  $("groups-more").hidden = state.groupItems.length >= state.groupTotal;
}

async function loadGroups(append = false) {
  if (state.tab !== "hosts" || state.selectedHostId == null || state.groupRequest) return;
  const hostId = state.selectedHostId;
  const offset = append ? state.groupItems.length : 0;
  const request = new AbortController();
  state.groupRequest = request;
  text("groups-status", "Loading assignments…");
  try {
    const response = await fetch(`/api/hosts/${hostId}/groups?offset=${offset}`, { cache: "no-store", signal: request.signal });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const page = await response.json();
    if (state.selectedHostId !== hostId) return;
    state.groupItems = append ? state.groupItems.concat(page.groups) : page.groups;
    state.groupTotal = page.total;
    renderGroups();
    text("groups-status", `Showing ${state.groupItems.length.toLocaleString()} of ${page.total.toLocaleString()} · updated ${new Date().toLocaleTimeString()}`);
  } catch (error) {
    if (error.name !== "AbortError") text("groups-status", `Could not load assignments (${error.message})`);
  } finally {
    if (state.groupRequest === request) state.groupRequest = null;
  }
}

function renderRouting(snapshot) {
  const { pool } = snapshot;
  text("routing-candidates", pool.candidate_hosts.toLocaleString());
  text("routing-selected", pool.selected_hosts.toLocaleString());
  text("routing-ready", pool.ready_hosts.toLocaleString());
  text("routing-limit", pool.max_active_hosts.toLocaleString());
  text("routing-idle", pool.idle_remaining_seconds == null ? "Not counting down" : `${Math.ceil(pool.idle_remaining_seconds / 60)} min remaining`);
  text("routing-sticky", pool.sticky_groups.toLocaleString());
  text("routing-routes", pool.active_routes.toLocaleString());
  const rows = snapshot.hosts.map((host) => {
    const row = document.createElement("tr");
    row.append(make("td", "", `Host ${host.id + 1} · ${host.endpoint}`));
    const status = make("td");
    status.append(make("span", `table-state ${host.phase}`, humanPhase(host.phase)));
    row.append(status, make("td", "", host.sticky_groups.toLocaleString()), make("td", "", host.active_routes.toLocaleString()), make("td", "", formatLatency(host.latency_ms)), make("td", "", formatBytes(host.rx_bytes)));
    return row;
  });
  $("routing-hosts").replaceChildren(...rows);
}

function formatDuration(seconds) {
  if (seconds == null) return "Disabled";
  if (seconds % 3600 === 0) return `${seconds / 3600} hr`;
  if (seconds % 60 === 0) return `${seconds / 60} min`;
  return `${seconds} sec`;
}

async function loadProfile() {
  if (state.profileRequest) return;
  state.profileRequest = true;
  try {
    const response = await fetch("/api/profile", { cache: "no-store" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const profile = await response.json();
    if (!Array.isArray(profile.remotes)) throw new Error("Invalid profile summary");
    if (profile.remotes.length === 0) {
      text("profile-status", state.frame?.snapshot.pool.phase === "failed" ? "Profile unavailable; see Overview" : "Waiting for OpenVPN profile");
      return;
    }
    text("profile-remote-count", profile.remotes.length.toLocaleString());
    text("profile-handshake", formatDuration(profile.handshake_window_seconds));
    text("profile-transition", formatDuration(profile.transition_window_seconds));
    text("profile-renegotiation", formatDuration(profile.renegotiate_after_seconds));
    text("profile-credentials", profile.credentials_required ? "Required" : "Not required");
    text("profile-server-purpose", profile.server_certificate_purpose_required ? "Server required" : "Not specified");
    text("profile-ipv6", profile.ipv6_blocked ? "Blocked by profile" : "Allowed if server provides it");
    $("profile-remotes").replaceChildren(...profile.remotes.map((remote, index) => {
      const row = document.createElement("tr");
      row.append(make("td", "", String(index + 1)), make("td", "", remote.host), make("td", "", String(remote.port)));
      return row;
    }));
    state.profileLoaded = true;
    text("profile-status", `${profile.remotes.length} configured remote${profile.remotes.length === 1 ? "" : "s"}`);
  } catch (error) {
    text("profile-status", `Could not load profile summary (${error.message})`);
  } finally {
    state.profileRequest = false;
  }
}

function minuteSeries(history, sampledAtMs, valueForBucket) {
  const currentMinute = Math.floor(sampledAtMs / MINUTE_MS) * MINUTE_MS;
  const indexed = new Map(history.map((bucket) => [bucket.minute_start_ms, bucket]));
  return Array.from({ length: HISTORY_MINUTES }, (_, offset) => {
    const minute = currentMinute - (HISTORY_MINUTES - 1 - offset) * MINUTE_MS;
    const bucket = indexed.get(minute);
    return bucket ? valueForBucket(bucket) : null;
  });
}

function renderCharts() {
  if (!state.frame) return;
  const { history, snapshot } = state.frame;
  if (state.tab === "overview") {
    const rx = minuteSeries(history, snapshot.sampled_at_ms, (bucket) => bucket.rx_bytes / 1e6);
    const tx = minuteSeries(history, snapshot.sampled_at_ms, (bucket) => bucket.tx_bytes / 1e6);
    drawChart($("system-traffic-chart"), [{ values: rx, color: COLORS.rx }, { values: tx, color: COLORS.tx }], "MB/min", snapshot.sampled_at_ms);
    const latency = minuteSeries(history, snapshot.sampled_at_ms, (bucket) => bucket.average_latency_ms);
    drawChart($("system-latency-chart"), [{ values: latency, color: COLORS.latency }], "ms", snapshot.sampled_at_ms, true);
  } else if (state.tab === "hosts" && state.selectedHostId != null) {
    const id = state.selectedHostId;
    const hostValue = (bucket, field) => bucket.hosts.find((host) => host.host_id === id)?.[field] ?? null;
    const rx = minuteSeries(history, snapshot.sampled_at_ms, (bucket) => {
      const value = hostValue(bucket, "rx_bytes"); return value == null ? null : value / 1e6;
    });
    const tx = minuteSeries(history, snapshot.sampled_at_ms, (bucket) => {
      const value = hostValue(bucket, "tx_bytes"); return value == null ? null : value / 1e6;
    });
    const latency = minuteSeries(history, snapshot.sampled_at_ms, (bucket) => hostValue(bucket, "average_latency_ms"));
    drawChart($("host-traffic-chart"), [{ values: rx, color: COLORS.rx }, { values: tx, color: COLORS.tx }], "MB/min", snapshot.sampled_at_ms);
    drawChart($("host-latency-chart"), [{ values: latency, color: COLORS.latency }], "ms", snapshot.sampled_at_ms, true);
  }
}

function drawChart(canvas, series, unit, sampledAtMs, latencyScale = false) {
  const width = canvas.clientWidth;
  const height = canvas.clientHeight;
  if (width < 50 || height < 50) return;
  const pixelRatio = Math.min(window.devicePixelRatio || 1, 2);
  const targetWidth = Math.round(width * pixelRatio);
  const targetHeight = Math.round(height * pixelRatio);
  if (canvas.width !== targetWidth || canvas.height !== targetHeight) {
    canvas.width = targetWidth; canvas.height = targetHeight;
  }
  const ctx = canvas.getContext("2d");
  ctx.setTransform(pixelRatio, 0, 0, pixelRatio, 0, 0);
  ctx.clearRect(0, 0, width, height);
  const left = 43, right = 12, top = 13, bottom = 28;
  const plotWidth = width - left - right, plotHeight = height - top - bottom;
  const all = series.flatMap((line) => line.values.filter((value) => Number.isFinite(value)));
  const observedMin = all.length ? Math.min(...all) : 0;
  const observedMax = all.length ? Math.max(...all) : 1;
  const low = latencyScale ? Math.max(0, Math.floor((observedMin - 10) / 10) * 10) : 0;
  const high = latencyScale ? Math.max(low + 10, Math.ceil((observedMax + 10) / 10) * 10) : Math.max(1, observedMax * 1.15);
  const xAt = (index) => left + index / (HISTORY_MINUTES - 1) * plotWidth;
  const yAt = (value) => top + (high - value) / (high - low) * plotHeight;

  ctx.font = "11px ui-sans-serif, system-ui, sans-serif";
  ctx.textBaseline = "middle";
  for (let tick = 0; tick <= 4; tick++) {
    const y = top + tick / 4 * plotHeight;
    ctx.beginPath(); ctx.moveTo(left, y); ctx.lineTo(width - right, y);
    ctx.strokeStyle = "rgba(142,160,178,.13)"; ctx.lineWidth = 1; ctx.stroke();
    const value = high - tick / 4 * (high - low);
    ctx.fillStyle = "#8192a5"; ctx.textAlign = "right";
    ctx.fillText(unit === "ms" ? value.toFixed(0) : value.toFixed(value >= 10 ? 0 : 1), left - 9, y);
  }
  const currentMinute = Math.floor(sampledAtMs / MINUTE_MS) * MINUTE_MS;
  for (const index of [0, 29, 59]) {
    const time = new Date(currentMinute - (59 - index) * MINUTE_MS);
    ctx.textAlign = index === 0 ? "left" : index === 59 ? "right" : "center";
    ctx.fillStyle = "#718399";
    ctx.fillText(time.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }), xAt(index), height - 9);
  }
  for (const line of series) {
    let drawing = false;
    ctx.beginPath();
    line.values.forEach((value, index) => {
      if (!Number.isFinite(value)) { drawing = false; return; }
      if (!drawing) { ctx.moveTo(xAt(index), yAt(value)); drawing = true; }
      else ctx.lineTo(xAt(index), yAt(value));
    });
    ctx.strokeStyle = line.color; ctx.lineWidth = 2; ctx.lineJoin = "round"; ctx.lineCap = "round";
    ctx.shadowColor = line.color; ctx.shadowBlur = 8; ctx.stroke(); ctx.shadowBlur = 0;
    const last = line.values.findLastIndex((value) => Number.isFinite(value));
    if (last >= 0) {
      ctx.beginPath(); ctx.arc(xAt(last), yAt(line.values[last]), 3, 0, Math.PI * 2);
      ctx.fillStyle = line.color; ctx.fill();
    }
  }
  if (all.length === 0) {
    ctx.textAlign = "center"; ctx.fillStyle = "#718399";
    ctx.fillText("Waiting for chart samples", left + plotWidth / 2, top + plotHeight / 2);
  }
}

document.querySelectorAll(".tab").forEach((button) => button.addEventListener("click", () => {
  state.tab = button.dataset.tab;
  document.querySelectorAll(".tab").forEach((tab) => {
    const active = tab === button;
    tab.classList.toggle("active", active);
    tab.setAttribute("aria-selected", String(active));
  });
  document.querySelectorAll(".tab-panel").forEach((panel) => { panel.hidden = panel.id !== state.tab; });
  if (state.tab === "hosts" && state.selectedHostId != null && state.groupItems.length === 0) loadGroups();
  if (state.tab === "profile" && !state.profileLoaded) loadProfile();
  requestAnimationFrame(renderCharts);
}));
$("host-list").addEventListener("click", (event) => {
  const button = event.target.closest("button[data-host-id]");
  if (!button) return;
  state.selectedHostId = Number(button.dataset.hostId);
  render();
});
$("groups-refresh").addEventListener("click", () => loadGroups());
$("groups-more").addEventListener("click", () => loadGroups(true));
window.setInterval(() => {
  if (state.tab === "hosts" && state.groupItems.length <= 100) loadGroups();
}, 10000);
window.addEventListener("resize", () => requestAnimationFrame(renderCharts));
window.setInterval(() => {
  if (state.socket?.readyState === WebSocket.OPEN && state.lastMessageAt && Date.now() - state.lastMessageAt > WS_STALE_MS) {
    setFeed("offline", "Connection stale");
    state.socket.close();
  }
}, WS_HEALTH_CHECK_MS);
connect();
loadProfile();
