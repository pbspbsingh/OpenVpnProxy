import { bucketRate, minuteSeries, MINUTE_MS, HISTORY_MINUTES } from "../lib/history.js";
import { formatLatency, formatRate } from "../lib/format.js";

const COLORS = { rx: "#42d5c8", tx: "#8f9dff", latency: "#f1bd77" };

export function trafficChart(scope, kind) {
  // Chart.js instances must stay outside Alpine's reactive proxies.
  let chart = null, scheduled = null;
  function drawChart(canvas, series, unit, sampledAtMs, latencyScale = false) {
    if (!window.Chart || canvas.clientWidth < 50 || canvas.clientHeight < 50) return;
    const all = series.flatMap((line) => line.values.filter((value) => Number.isFinite(value)));
    const observedMin = all.length ? Math.min(...all) : 0;
    const observedMax = all.length ? Math.max(...all) : 1;
    const low = latencyScale ? Math.max(0, Math.floor((observedMin - 10) / 10) * 10) : 0;
    const high = latencyScale ? Math.max(low + 10, Math.ceil((observedMax + 10) / 10) * 10) : Math.max(1, observedMax * 1.15);
    const currentMinute = Math.floor(sampledAtMs / MINUTE_MS) * MINUTE_MS;
    const labels = Array.from({ length: HISTORY_MINUTES }, (_, index) =>
      new Date(currentMinute - (HISTORY_MINUTES - 1 - index) * MINUTE_MS).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }));
    const datasets = series.map((line) => ({
      label: line.label, data: line.values, borderColor: line.color, backgroundColor: line.color,
      borderWidth: 2, pointRadius: 0, pointHoverRadius: 4, pointHitRadius: 10, spanGaps: false,
    }));
    if (chart) {
      chart.data.labels = labels;
      chart.data.datasets = datasets;
      chart.options.scales.y.min = low;
      chart.options.scales.y.max = high;
      chart.resize();
      chart.update("none");
      return;
    }
    chart = new window.Chart(canvas, {
      type: "line",
      data: { labels, datasets },
      options: {
        responsive: true, maintainAspectRatio: false, animation: false,
        interaction: { mode: "index", intersect: false },
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: "#172230", borderColor: "#3a5268", borderWidth: 1,
            titleColor: "#e9f0f7", bodyColor: "#e9f0f7",
            callbacks: {
              label: (item) => `${item.dataset.label}: ${unit === "ms" ? formatLatency(item.parsed.y) : formatRate(item.parsed.y)}`,
            },
          },
        },
        scales: {
          x: {
            grid: { display: false }, border: { display: false },
            ticks: { color: "#718399", font: { size: 11 }, maxTicksLimit: 3, maxRotation: 0 },
          },
          y: {
            min: low, max: high, border: { display: false },
            grid: { color: "rgba(142,160,178,.13)" },
            ticks: {
              color: "#8192a5", font: { size: 11 }, maxTicksLimit: 5,
              callback: (value) => unit === "ms" ? formatLatency(value) : formatRate(value),
            },
          },
        },
      },
      plugins: [{
        id: "emptyChartMessage",
        afterDraw: (chart) => {
          if (chart.data.datasets.some((line) => line.data.some((value) => Number.isFinite(value)))) return;
          const { ctx, chartArea } = chart;
          ctx.save();
          ctx.fillStyle = "#718399";
          ctx.font = "11px ui-sans-serif, system-ui, sans-serif";
          ctx.textAlign = "center";
          ctx.fillText("Waiting for chart samples", (chartArea.left + chartArea.right) / 2, (chartArea.top + chartArea.bottom) / 2);
          ctx.restore();
        },
      }],
    });
  }

  return {
    refresh(frame, selectedId, tab) {
      cancelAnimationFrame(scheduled);
      if (!frame || tab !== scope) return;
      scheduled = requestAnimationFrame(() => {
        scheduled = null;
        const { history, snapshot } = frame;
        const hostValue = (bucket, field) => bucket.hosts.find(host => host.host_id === selectedId)?.[field] ?? null;
        const values = field => minuteSeries(history, snapshot.sampled_at_ms, bucket => {
          const value = scope === "hosts" ? hostValue(bucket, field) : bucket[field];
          return value == null ? null : field === "average_latency_ms" ? value : bucketRate(value, bucket.observed_ms);
        });
        const series = kind === "latency"
          ? [{ label: scope === "hosts" ? "Probe score" : "Selected host mean", values: values("average_latency_ms"), color: COLORS.latency }]
          : [{ label: "Download", values: values("rx_bytes"), color: COLORS.rx }, { label: "Upload", values: values("tx_bytes"), color: COLORS.tx }];
        drawChart(this.$refs.canvas, series, kind === "latency" ? "ms" : "B/s", snapshot.sampled_at_ms, kind === "latency");
      });
    },
    destroy() { cancelAnimationFrame(scheduled); chart?.destroy(); chart = null; },
  };
}
