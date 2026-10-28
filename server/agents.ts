// Hosts and how their agents get in (ADR 0066, 0023, 0032). An admin makes an enrolment token for one host or for a
// fleet; runtime-agent trades it once for a secret of its own, which speaks for its host and no other. Runtime keeps
// only hashes of both. It never connects to an agent and never sends one a command: agents send what Falco saw, and
// a report of themselves, and get nothing back but "taken".
import { createHash, randomBytes, randomUUID } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import { log } from "./log.ts";
import { bad, conflict, isObject, notFound, only, RuntimeError } from "./problem.ts";

export interface HostRow {
  id: string;
  name: string;
  secret_hash: string;
  token_id: string | null;
  version: string;
  os: string | null;
  kernel: string | null;
  arch: string | null;
  falco_status: "ok" | "down" | "unknown";
  falco_version: string | null;
  falco_detail: string | null;
  fim_paths: string;
  fim_scanned_at: string | null;
  events_in: number;
  dropped: number;
  last_event_at: string | null;
  enrolled_at: string;
  last_seen_at: string;
  learning_until: string;
}

interface TokenRow {
  id: string;
  name: string;
  token_hash: string;
  max_uses: number;
  uses: number;
  expires_at: string;
  created_by: string;
  created_at: string;
}

export type HostStatus = "healthy" | "silent" | "sensor-down" | "outdated";

/** A Kubernetes node name or a host name. */
const NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$/;
const TOKEN_NAME = /^[^\u0000-\u001f]{1,100}$/;
const DAY = 86_400_000;
/** An agent reports every 30 seconds and sends events every few; two minutes without a word is silence. */
export const SILENT_MS = 2 * 60_000;
const MAX_FIM_PATHS = 256;

const sha256 = (s: string) => createHash("sha256").update(s).digest("hex");

export interface Report {
  version: string;
  os: string | null;
  kernel: string | null;
  arch: string | null;
  falco: { status: "ok" | "down" | "unknown"; version: string | null; detail: string | null };
  fimPaths: string[] | null;
  dropped: number;
}

const text = (v: unknown, max: number, name: string): string | null => {
  if (v === undefined || v === null || v === "") return null;
  if (typeof v !== "string" || v.length > max) throw bad(`${name} is text of at most ${max} characters.`);
  return v;
};

/** What every agent call carries about the agent itself, as `report`. */
export function parseReport(b: Record<string, unknown>): Report {
  only(b, ["version", "os", "kernel", "arch", "falco", "fimPaths", "dropped"], "{ version, os, kernel, arch, falco, fimPaths, dropped }");
  if (typeof b.version !== "string" || !/^\d+\.\d+\.\d+[\w.+-]*$/.test(b.version) || b.version.length > 32)
    throw bad("version is the agent's version, such as 0.1.0.");
  const f = b.falco === undefined ? {} : b.falco;
  if (!isObject(f)) throw bad("falco is { status, version, detail }.");
  const status = f.status ?? "unknown";
  if (status !== "ok" && status !== "down" && status !== "unknown") throw bad("falco.status is ok, down or unknown.");
  let fimPaths: string[] | null = null;
  if (b.fimPaths !== undefined) {
    if (
      !Array.isArray(b.fimPaths) ||
      b.fimPaths.length > MAX_FIM_PATHS ||
      b.fimPaths.some((p) => typeof p !== "string" || !p.startsWith("/") || p.length > 4096)
    )
      throw bad(`fimPaths is a list of at most ${MAX_FIM_PATHS} absolute paths.`);
    fimPaths = b.fimPaths as string[];
  }
  const dropped = b.dropped ?? 0;
  if (typeof dropped !== "number" || !Number.isSafeInteger(dropped) || dropped < 0) throw bad("dropped is a count.");
  return {
    version: b.version,
    os: text(b.os, 128, "os"),
    kernel: text(b.kernel, 128, "kernel"),
    arch: text(b.arch, 32, "arch"),
    falco: { status, version: text(f.version, 64, "falco.version"), detail: text(f.detail, 500, "falco.detail") },
    fimPaths,
    dropped,
  };
}

export interface AgentsOptions {
  /** Runtime's version: an agent of another one is shown as outdated (ADR 0019). */
  version: string;
  /** Days after enrolment during which every process a host runs is learned as normal. */
  learningDays: number;
  clock: () => number;
}

export function createAgents(db: DatabaseSync, o: AgentsOptions) {
  const iso = (t = o.clock()) => new Date(t).toISOString();

  // ---- Enrolment tokens -----------------------------------------------------------------------------------------

  const toToken = (t: TokenRow) => ({
    id: t.id,
    name: t.name,
    maxUses: t.max_uses,
    uses: t.uses,
    expiresAt: t.expires_at,
    state: (t.uses >= t.max_uses ? "used" : t.expires_at <= iso() ? "expired" : "active") as "active" | "used" | "expired",
    createdBy: t.created_by,
    createdAt: t.created_at,
  });

  function createToken(b: Record<string, unknown>, by: string) {
    only(b, ["name", "maxUses", "days"], "{ name, maxUses, days }");
    if (typeof b.name !== "string" || !TOKEN_NAME.test(b.name.trim())) throw bad("name says what the token is for, up to 100 characters.");
    const maxUses = b.maxUses ?? 1;
    if (typeof maxUses !== "number" || !Number.isInteger(maxUses) || maxUses < 1 || maxUses > 10_000)
      throw bad("maxUses is how many hosts may enrol with it: 1 for one host, up to 10000 for a fleet.");
    const days = b.days ?? 7;
    if (typeof days !== "number" || !Number.isInteger(days) || days < 1 || days > 30) throw bad("days is how long it is valid: 1 to 30.");
    const token = `oie_${randomBytes(24).toString("base64url")}`;
    const id = randomUUID();
    db.prepare("INSERT INTO enrollment_tokens (id, name, token_hash, max_uses, expires_at, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)").run(
      id,
      b.name.trim(),
      sha256(token),
      maxUses,
      iso(o.clock() + days * DAY),
      by,
      iso(),
    );
    log("info", "enrolment token created", { name: b.name.trim(), maxUses, days, by });
    // The token itself is shown this once (ADR 0021).
    return { ...toToken(db.prepare("SELECT * FROM enrollment_tokens WHERE id = ?").get(id) as unknown as TokenRow), token };
  }

  const tokens = () => (db.prepare("SELECT * FROM enrollment_tokens ORDER BY created_at DESC").all() as unknown as TokenRow[]).map(toToken);

  /** Ends a token at once. Hosts that enrolled with it keep their own secrets. */
  function deleteToken(id: string) {
    if (!db.prepare("DELETE FROM enrollment_tokens WHERE id = ?").run(id).changes) throw notFound("The enrolment token");
  }

  // ---- Hosts ------------------------------------------------------------------------------------------------------

  function statusOf(h: HostRow): HostStatus {
    if (Date.parse(h.last_seen_at) + SILENT_MS < o.clock()) return "silent";
    if (h.falco_status === "down") return "sensor-down";
    return h.version === o.version ? "healthy" : "outdated";
  }

  function toHost(h: HostRow, perHour?: number[]) {
    return {
      id: h.id,
      name: h.name,
      status: statusOf(h),
      version: h.version,
      os: h.os,
      kernel: h.kernel,
      arch: h.arch,
      falco: { status: h.falco_status, version: h.falco_version, detail: h.falco_detail },
      eventsIn: h.events_in,
      dropped: h.dropped,
      lastEventAt: h.last_event_at,
      lastSeenAt: h.last_seen_at,
      enrolledAt: h.enrolled_at,
      learningUntil: h.learning_until,
      fim: {
        paths: JSON.parse(h.fim_paths) as string[],
        scannedAt: h.fim_scanned_at,
        files: (db.prepare("SELECT COUNT(*) AS n FROM files WHERE host_id = ?").get(h.id) as { n: number }).n,
      },
      eventsPerHour: perHour ?? Array.from({ length: 24 }, () => 0),
    };
  }

  const hostRows = () => db.prepare("SELECT * FROM hosts ORDER BY name").all() as unknown as HostRow[];

  /** Every host, with its events per hour over the last 24 hours. */
  function hosts() {
    const from = o.clock() - 24 * 3_600_000;
    const counts = new Map<string, number[]>();
    const rows = db
      .prepare("SELECT host_id, CAST((julianday(time) - julianday(?)) * 24 AS INTEGER) AS h, COUNT(*) AS n FROM events WHERE time >= ? GROUP BY host_id, h")
      .all(iso(from), iso(from)) as Array<{ host_id: string; h: number; n: number }>;
    for (const r of rows) {
      const c = counts.get(r.host_id) ?? Array.from({ length: 24 }, () => 0);
      if (r.h >= 0 && r.h < 24) c[r.h] = r.n;
      counts.set(r.host_id, c);
    }
    return hostRows().map((h) => toHost(h, counts.get(h.id)));
  }

  function host(id: string) {
    const h = db.prepare("SELECT * FROM hosts WHERE id = ?").get(id) as HostRow | undefined;
    if (!h) throw notFound("The host");
    return h;
  }

  /** Ends the host's secret at once. Its detections and events stay, under its name; its inventory goes. */
  function deleteHost(id: string, by: string) {
    const h = host(id);
    db.exec("BEGIN");
    try {
      db.prepare("DELETE FROM processes WHERE host_id = ?").run(id);
      db.prepare("DELETE FROM files WHERE host_id = ?").run(id);
      db.prepare("DELETE FROM hosts WHERE id = ?").run(id);
      db.exec("COMMIT");
    } catch (err) {
      db.exec("ROLLBACK");
      throw err;
    }
    log("info", "host removed", { host: h.name, by });
  }

  // ---- What agents call -------------------------------------------------------------------------------------------

  /** Trades an enrolment token for the host's own secret. A name already enrolled is refused: removing it is an admin's decision. */
  function enroll(b: Record<string, unknown>) {
    const token = typeof b.token === "string" ? b.token : "";
    const t = db.prepare("SELECT * FROM enrollment_tokens WHERE token_hash = ?").get(sha256(token)) as TokenRow | undefined;
    if (!t || t.uses >= t.max_uses || t.expires_at <= iso())
      throw new RuntimeError(401, "invalid-token", "The enrolment token is unknown, used up or expired. Make a new one under Hosts.");
    if (typeof b.name !== "string" || !NAME.test(b.name)) throw bad("name is the host's name: letters, digits, dots, dashes and underscores.");
    if (!isObject(b.report)) throw bad("report is the agent's report of itself: { version, os, kernel, arch, falco, dropped }.");
    const r = parseReport(b.report);
    if (db.prepare("SELECT 1 FROM hosts WHERE name = ?").get(b.name))
      throw conflict(`A host named ${b.name} is enrolled. Remove it under Hosts to enrol it again, for a lost volume or a leaked secret.`);
    const secret = `oia_${randomBytes(32).toString("base64url")}`;
    const id = randomUUID();
    db.exec("BEGIN");
    try {
      // Counted in the same statement that checks it, so two hosts racing for the last use cannot both have it.
      if (!db.prepare("UPDATE enrollment_tokens SET uses = uses + 1 WHERE id = ? AND uses < max_uses").run(t.id).changes)
        throw new RuntimeError(401, "invalid-token", "The enrolment token is used up. Make a new one under Hosts.");
      db.prepare(
        `INSERT INTO hosts (id, name, secret_hash, token_id, version, os, kernel, arch, falco_status, falco_version, falco_detail, fim_paths, dropped,
           enrolled_at, last_seen_at, learning_until) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      ).run(
        id,
        b.name,
        sha256(secret),
        t.id,
        r.version,
        r.os,
        r.kernel,
        r.arch,
        r.falco.status,
        r.falco.version,
        r.falco.detail,
        JSON.stringify(r.fimPaths ?? []),
        r.dropped,
        iso(),
        iso(),
        iso(o.clock() + o.learningDays * DAY),
      );
      db.exec("COMMIT");
    } catch (err) {
      db.exec("ROLLBACK");
      throw err;
    }
    log("info", "host enrolled", { host: b.name, version: r.version, token: t.name });
    return { hostId: id, secret };
  }

  /** The host whose agent sent this secret. */
  function hostBySecret(header: string | undefined): HostRow {
    const secret = header?.startsWith("Bearer oia_") ? header.slice(7) : "";
    const h = secret ? (db.prepare("SELECT * FROM hosts WHERE secret_hash = ?").get(sha256(secret)) as HostRow | undefined) : undefined;
    if (!h)
      throw new RuntimeError(
        401,
        "invalid-token",
        "Unknown agent secret. The host was removed, or the agent's volume belongs to another Runtime: enrol it again.",
      );
    return h;
  }

  /** The agent's report of itself, which comes with every call. */
  function saw(h: HostRow, r: Report) {
    db.prepare(
      `UPDATE hosts SET version = ?, os = ?, kernel = ?, arch = ?, falco_status = ?, falco_version = ?, falco_detail = ?, dropped = ?,
         fim_paths = COALESCE(?, fim_paths), last_seen_at = ? WHERE id = ?`,
    ).run(
      r.version,
      r.os,
      r.kernel,
      r.arch,
      r.falco.status,
      r.falco.version,
      r.falco.detail,
      r.dropped,
      r.fimPaths ? JSON.stringify(r.fimPaths) : null,
      iso(),
      h.id,
    );
  }

  function counts() {
    const all = hostRows().map(statusOf);
    const by = (s: HostStatus) => all.filter((x) => x === s).length;
    return { total: all.length, healthy: by("healthy"), silent: by("silent"), sensorDown: by("sensor-down"), outdated: by("outdated") };
  }

  return { createToken, tokens, deleteToken, hosts, host, deleteHost, enroll, hostBySecret, saw, counts, statusOf };
}

export type Agents = ReturnType<typeof createAgents>;
