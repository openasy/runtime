// Prometheus text exposition, written by hand: a few lines, no client library needed.
const requests = new Map<string, number>();
let eventsIn = 0;
let eventsRefused = 0;

export function countRequest(method: string, route: string, status: number) {
  const key = `method="${method}",route="${route}",status="${status}"`;
  requests.set(key, (requests.get(key) ?? 0) + 1);
}

export function countEvents(taken: number, refused: number) {
  eventsIn += taken;
  eventsRefused += refused;
}

export interface Gauges {
  open: Record<string, number>;
  hosts: { healthy: number; silent: number; sensorDown: number; outdated: number };
  unreviewed: number;
  /** Events waiting for SIEM; undefined when no SIEM is set. */
  siemPending?: number;
}

export function renderMetrics(version: string, g: Gauges): string {
  const lines = [
    "# HELP openasy_build_info Build information.",
    "# TYPE openasy_build_info gauge",
    `openasy_build_info{product="runtime",version="${version}"} 1`,
    "# HELP openasy_http_requests_total HTTP requests handled.",
    "# TYPE openasy_http_requests_total counter",
    ...[...requests].map(([labels, n]) => `openasy_http_requests_total{${labels}} ${n}`),
    "# HELP openasy_runtime_events_received_total Falco events taken from agents since the start.",
    "# TYPE openasy_runtime_events_received_total counter",
    `openasy_runtime_events_received_total ${eventsIn}`,
    "# HELP openasy_runtime_events_refused_total Events from agents left out because they were not what Falco writes.",
    "# TYPE openasy_runtime_events_refused_total counter",
    `openasy_runtime_events_refused_total ${eventsRefused}`,
    "# HELP openasy_runtime_detections_active Detections open or being investigated, by severity.",
    "# TYPE openasy_runtime_detections_active gauge",
    ...Object.entries(g.open).map(([s, n]) => `openasy_runtime_detections_active{severity="${s}"} ${n}`),
    "# HELP openasy_runtime_hosts Hosts by status. Silent ones have not reported for two minutes; watch them from another system.",
    "# TYPE openasy_runtime_hosts gauge",
    `openasy_runtime_hosts{status="healthy"} ${g.hosts.healthy}`,
    `openasy_runtime_hosts{status="silent"} ${g.hosts.silent}`,
    `openasy_runtime_hosts{status="sensor-down"} ${g.hosts.sensorDown}`,
    `openasy_runtime_hosts{status="outdated"} ${g.hosts.outdated}`,
    "# HELP openasy_runtime_file_changes_unreviewed Changes to watched files nobody has reviewed.",
    "# TYPE openasy_runtime_file_changes_unreviewed gauge",
    `openasy_runtime_file_changes_unreviewed ${g.unreviewed}`,
    ...(g.siemPending === undefined
      ? []
      : [
          "# HELP openasy_runtime_siem_pending Events waiting to go to SIEM.",
          "# TYPE openasy_runtime_siem_pending gauge",
          `openasy_runtime_siem_pending ${g.siemPending}`,
        ]),
    "# HELP process_uptime_seconds Seconds since the process started.",
    "# TYPE process_uptime_seconds gauge",
    `process_uptime_seconds ${process.uptime().toFixed(0)}`,
  ];
  return lines.join("\n") + "\n";
}
