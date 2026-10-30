// Prometheus text exposition, written by hand: a few lines, no client library needed.
const requests = new Map<string, number>();

export function countRequest(method: string, route: string, status: number) {
  const key = `method="${method}",route="${route}",status="${status}"`;
  requests.set(key, (requests.get(key) ?? 0) + 1);
}

export interface Gauges {
  vaults: number;
  /** Confirmed members of the organization. */
  members: number;
  /** Members waiting for an admin to confirm them. */
  waiting: number;
  /** Whether the last sync with Vaultwarden worked, or null before the first. */
  syncOk: boolean | null;
  /** People with a leaving date who are still members. */
  leaving: number;
  /** 1 when the vaults file on disk could not be applied and an older version is in use. */
  fileError: boolean;
}

export function renderMetrics(version: string, g: Gauges): string {
  const lines = [
    "# HELP openasy_build_info Build information.",
    "# TYPE openasy_build_info gauge",
    `openasy_build_info{product="passwords",version="${version}"} 1`,
    "# HELP openasy_http_requests_total HTTP requests handled.",
    "# TYPE openasy_http_requests_total counter",
    ...[...requests].map(([labels, n]) => `openasy_http_requests_total{${labels}} ${n}`),
    "# HELP openasy_passwords_vaults Shared vaults in the vaults file.",
    "# TYPE openasy_passwords_vaults gauge",
    `openasy_passwords_vaults ${g.vaults}`,
    "# HELP openasy_passwords_members Confirmed members of the organization.",
    "# TYPE openasy_passwords_members gauge",
    `openasy_passwords_members ${g.members}`,
    "# HELP openasy_passwords_waiting Members waiting for an admin to confirm them.",
    "# TYPE openasy_passwords_waiting gauge",
    `openasy_passwords_waiting ${g.waiting}`,
    "# HELP openasy_passwords_leaving People with a leaving date who are still members.",
    "# TYPE openasy_passwords_leaving gauge",
    `openasy_passwords_leaving ${g.leaving}`,
    "# HELP openasy_passwords_sync_ok 1 when Vaultwarden was last brought in step with the file, 0 when that failed.",
    "# TYPE openasy_passwords_sync_ok gauge",
    ...(g.syncOk === null ? [] : [`openasy_passwords_sync_ok ${g.syncOk ? 1 : 0}`]),
    "# HELP openasy_passwords_config_error 1 when the vaults file could not be applied and its last good version is in use.",
    "# TYPE openasy_passwords_config_error gauge",
    `openasy_passwords_config_error ${g.fileError ? 1 : 0}`,
    "# HELP process_uptime_seconds Seconds since the process started.",
    "# TYPE process_uptime_seconds gauge",
    `process_uptime_seconds ${process.uptime().toFixed(0)}`,
  ];
  return lines.join("\n") + "\n";
}
