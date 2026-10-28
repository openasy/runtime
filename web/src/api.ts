// The UI is an ordinary client of the public API (ADR 0014, 0018). Types follow openapi.json.

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type DetectionStatus = "open" | "investigating" | "resolved" | "false-positive";
export type Kind = "exec" | "network" | "file" | "kernel" | "other";
export type Baseline = "known" | "new" | "drift";
export type Review = "unreviewed" | "approved" | "suspicious";
export type HostStatus = "healthy" | "silent" | "sensor-down" | "outdated";

/** Another OpenAsy product of this install, from OPENASY_PRODUCTS. */
export interface ProductLink {
  id: string;
  url: string;
}

export interface ProcNode {
  pid: number | null;
  cmd: string;
  user: string | null;
  flagged: boolean;
  children: ProcNode[];
}

export interface Container {
  id: string;
  name: string | null;
  image: string | null;
  namespace: string | null;
  pod: string | null;
}

export interface Detection {
  id: string;
  rule: string;
  severity: Severity;
  status: DetectionStatus;
  host: { id: string; name: string };
  container: Container | null;
  process: string | null;
  user: string | null;
  output: string;
  tags: string[];
  attack: string[];
  count: number;
  firstAt: string;
  lastAt: string;
  reason: string | null;
  updatedBy: string | null;
  updatedAt: string | null;
}

export interface RtEvent {
  id: string;
  time: string;
  receivedAt: string;
  host: string;
  kind: Kind;
  rule: string;
  priority: string;
  severity: Severity;
  source: string;
  tags: string[];
  output: string;
  container: { id: string; name: string | null } | null;
  process: string | null;
  pid: number | null;
  user: string | null;
  file: string | null;
  result: "alerted" | "kept";
  detectionId: string | null;
  fields: Record<string, string | number | boolean | null>;
}

export interface DetectionDetail extends Detection {
  tree: ProcNode[];
  events: RtEvent[];
}

export interface Process {
  id: string;
  host: { id: string; name: string };
  image: string | null;
  container: string | null;
  namespace: string | null;
  exe: string;
  parent: string | null;
  user: string | null;
  cmdline: string;
  pid: number | null;
  ppid: number | null;
  count: number;
  firstSeenAt: string;
  lastSeenAt: string;
  baseline: Baseline;
}

export interface FileState {
  kind: "file" | "link";
  sha256: string | null;
  size: number;
  mode: string;
  uid: number;
  gid: number;
  target: string | null;
}

export interface FileChange {
  id: string;
  host: { id: string; name: string };
  path: string;
  change: "created" | "modified" | "deleted" | "permissions";
  before: FileState | null;
  after: FileState | null;
  at: string;
  by: string | null;
  byEventId: string | null;
  review: Review;
  note: string | null;
  reviewedBy: string | null;
  reviewedAt: string | null;
}

export interface Policy {
  rule: string;
  source: string;
  priority: string;
  severity: Severity;
  severityOverride: Severity | null;
  mode: "alert" | "off";
  tags: string[];
  attack: string[];
  hits7d: number;
  firstSeenAt: string;
  lastSeenAt: string;
  updatedBy: string | null;
  updatedAt: string | null;
}

export interface Host {
  id: string;
  name: string;
  status: HostStatus;
  version: string;
  os: string | null;
  kernel: string | null;
  arch: string | null;
  falco: { status: "ok" | "down" | "unknown"; version: string | null; detail: string | null };
  eventsIn: number;
  dropped: number;
  lastEventAt: string | null;
  lastSeenAt: string;
  enrolledAt: string;
  learningUntil: string;
  fim: { paths: string[]; scannedAt: string | null; files: number };
  eventsPerHour: number[];
}

export interface EnrollmentToken {
  id: string;
  name: string;
  maxUses: number;
  uses: number;
  expiresAt: string;
  state: "active" | "used" | "expired";
  createdBy: string;
  createdAt: string;
  /** Only in the answer that made it. */
  token?: string;
}

type BySeverity = Record<Severity, number>;

export interface Summary {
  detections: { active: number; bySeverity: BySeverity; openedLastDay: number; openedDayBefore: number };
  events: { lastDay: number; alertedLastDay: number; perHour: Array<{ hour: string } & BySeverity> };
  files: { changesLastDay: number; unreviewed: number };
  processes: { new: number };
  policies: { total: number; off: number };
  hosts: { total: number; healthy: number; silent: number; sensorDown: number; outdated: number };
  siem: { configured: boolean; url?: string; pending?: number; lastError?: string | null; lastSentAt?: string | null };
}

export class Unauthorized extends Error {}
/** The signed-in owner or admin has no second factor yet; the sign-in gate asks for one. */
export class MfaSetupRequired extends Error {}
export class ApiError extends Error {}

// The session is an HttpOnly cookie set by sign-in (@openasy/auth); the browser sends it, nothing is stored here.
export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const res = await fetch(path, {
    ...init,
    credentials: "same-origin",
    headers: { ...(init.body ? { "content-type": "application/json" } : {}), ...init.headers },
  });
  if (!res.ok) {
    const problem = (await res.json().catch(() => ({}))) as { code?: string; detail?: string };
    if (res.status === 401) throw new Unauthorized(problem.detail);
    if (problem.code === "mfa-setup-required") throw new MfaSetupRequired(problem.detail);
    throw new ApiError(problem.detail ?? `${path}: ${res.status}`);
  }
  return (res.status === 204 ? undefined : await res.json()) as T;
}
