export function humanPhase(phase) {
  return phase ? phase.replaceAll("_", " ").replace(/^./, c => c.toUpperCase()) : "Unknown";
}

export function formatBytes(bytes) {
  if (!Number.isFinite(bytes)) return "—";
  const units = ["B", "kB", "MB", "GB", "TB"];
  let value = Math.max(0, bytes), unit = 0;
  while (value >= 1000 && unit < units.length - 1) { value /= 1000; unit++; }
  return `${value.toFixed(unit === 0 ? 0 : value >= 100 ? 0 : 1)} ${units[unit]}`;
}

export function formatRate(bytesPerSecond) {
  if (bytesPerSecond > 0 && bytesPerSecond < 1) return `${bytesPerSecond.toPrecision(2)} B/s`;
  return `${formatBytes(bytesPerSecond)}/s`;
}

export function formatLatency(ms) { return ms == null ? "—" : `${ms.toFixed(1)} ms`; }
export function formatDuration(seconds) {
  if (seconds == null) return "Disabled";
  if (seconds % 3600 === 0) return `${seconds / 3600} hr`;
  if (seconds % 60 === 0) return `${seconds / 60} min`;
  return `${seconds} sec`;
}

export const formatters = { humanPhase, formatBytes, formatRate, formatLatency, formatDuration };
