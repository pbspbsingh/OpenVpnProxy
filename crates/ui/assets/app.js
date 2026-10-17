import Alpine from "https://cdn.jsdelivr.net/npm/alpinejs@3.17.4/dist/module.esm.min.js";
import "https://cdn.jsdelivr.net/npm/chart.js@4.5.1/dist/chart.umd.min.js";
import { dashboardStore } from "./dashboard.js";
import { shell } from "./components/shell.js";
import { overview } from "./components/overview.js";
import { hosts } from "./components/hosts.js";
import { routing } from "./components/routing.js";
import { profile } from "./components/profile.js";
import { logs } from "./components/logs.js";
import { trafficChart } from "./components/chart.js";

Alpine.store("dashboard", dashboardStore());
for (const [name, component] of Object.entries({ shell, overview, hosts, routing, profile, logs, trafficChart })) {
  Alpine.data(name, component);
}
Alpine.start();
document.getElementById("boot-status").remove();
