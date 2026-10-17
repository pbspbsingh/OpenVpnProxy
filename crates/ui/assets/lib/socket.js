const RETRY_DELAYS_MS = [5_000, 10_000, 30_000];

/** Owns one feed, its bounded retries, and optional stale-message detection. */
export function createFeed(path, { onMessage, onStatus, staleMs = 0 }) {
  let socket = null, retryTimer = null, healthTimer = null;
  let running = false, exhausted = false, attempt = 0, lastMessageAt = 0;

  function connect() {
    if (!running) return;
    onStatus("connecting", "Connecting");
    const scheme = location.protocol === "https:" ? "wss:" : "ws:";
    const current = new WebSocket(`${scheme}//${location.host}${path}`);
    socket = current;
    current.onopen = () => {
      if (socket !== current) return;
      lastMessageAt = Date.now();
      onStatus("live", "Live");
    };
    current.onmessage = event => {
      if (socket !== current) return;
      let message;
      try { message = JSON.parse(event.data); } catch { return; }
      if (onMessage(message) === false) return;
      lastMessageAt = Date.now();
      attempt = 0;
    };
    current.onerror = () => current.close();
    current.onclose = () => {
      if (socket !== current || !running) return;
      socket = null;
      if (attempt >= RETRY_DELAYS_MS.length) {
        exhausted = true;
        onStatus("offline", "Disconnected");
        return;
      }
      const delay = RETRY_DELAYS_MS[attempt++];
      onStatus("offline", `Reconnecting in ${delay / 1000}s`);
      retryTimer = setTimeout(() => { retryTimer = null; connect(); }, delay);
    };
  }

  return {
    start() {
      if (running) return;
      if (exhausted) { onStatus("offline", "Disconnected"); return; }
      running = true;
      attempt = 0;
      connect();
      if (staleMs) healthTimer = setInterval(() => {
        if (socket?.readyState === WebSocket.OPEN && Date.now() - lastMessageAt > staleMs) {
          onStatus("offline", "Connection stale");
          socket.close();
        }
      }, 2_000);
    },
    stop() {
      running = false;
      clearTimeout(retryTimer);
      clearInterval(healthTimer);
      retryTimer = healthTimer = null;
      const current = socket;
      socket = null;
      current?.close();
    },
    get exhausted() { return exhausted; },
  };
}
