// Falco's alerts in, detections out (ADR 0066). Every alert an agent sends is kept as an event for the retention
// period. Each Falco rule has a policy: in alert mode, which every rule starts in, an event opens a detection or
// joins the open one for the same rule, host, container and program, and the detection's process tree grows with
// each event's chain of processes; off keeps the events and raises nothing. Runtime matches no rules itself apart
// from the process inventory's "new process in a container" (inventory.ts): Falco's rules are Falco's.
import { createHash, randomUUID } from "node:crypto";
import type { DatabaseSync, SQLInputValue } from "node:sqlite";
import type { HostRow } from "./agents.ts";
import {
  attackOf,
  chainOf,
  containerOf,
  FalcoError,
  fileOf,
  kindOf,
  mergeTree,
  parseFalco,
  processOf,
  SEVERITIES,
  SEVERITY_RANK,
  severityOf,
  type FalcoEvent,
  type Kind,
  type Priority,
  type ProcNode,
  type Severity,
} from "./falco.ts";
import { log } from "./log.ts";
import { bad, notFound, only } from "./problem.ts";

export type DetectionStatus = "open" | "investigating" | "resolved" | "false-positive";
const STATUSES: DetectionStatus[] = ["open", "investigating", "resolved", "false-positive"];
const KINDS: Kind[] = ["exec", "network", "file", "kernel", "other"];

/** Most events in one call from an agent; it sends the rest in the next. */
export const MAX_BATCH = 5000;
const HOUR = 3_600_000;
const DAY = 24 * HOUR;

interface RuleRow {
  rule: string;
  source: string;
  priority: Priority;
  tags: string;
  mode: "alert" | "off";
  severity: Severity | null;
  first_seen_at: string;
  last_seen_at: string;
  updated_by: string | null;
  updated_at: string | null;
}

interface DetectionRow {
  id: string;
  key: string;
  rule: string;
  host_id: string;
  host: string;
  severity: Severity;
  container_id: string | null;
  container_name: string | null;
  image: string | null;
  namespace: string | null;
  pod: string | null;
  process: string | null;
  user_name: string | null;
  output: string;
  tags: string;
  tree: string;
  count: number;
  first_at: string;
  last_at: string;
  status: DetectionStatus;
  reason: string | null;
  updated_by: string | null;
  updated_at: string | null;
}

interface EventRow {
  id: number;
  host_id: string;
  host: string;
  time: string;
  received_at: string;
  rule: string;
  priority: Priority;
  severity: Severity;
  source: string;
  kind: Kind;
  tags: string;
  output: string;
  fields: string;
  container_id: string | null;
  container_name: string | null;
  process: string | null;
  pid: number | null;
  user_name: string | null;
  file: string | null;
  result: "alerted" | "kept";
  detection_id: string | null;
}

export interface RuntimeOptions {
  clock: () => number;
  /** Events older than this are deleted (ADR 0015). */
  retentionDays: number;
  /** Called with each new detection and the event that opened it, to send on to SIEM. */
  onDetection?: (d: ReturnType<typeof toDetection>, e: ReturnType<typeof toEvent>) => void;
}

const sha = (s: string) => createHash("sha256").update(s).digest("hex").slice(0, 32);

export function toDetection(d: DetectionRow) {
  const tags = JSON.parse(d.tags) as string[];
  return {
    id: d.id,
    rule: d.rule,
    severity: d.severity,
    status: d.status,
    host: { id: d.host_id, name: d.host },
    container: d.container_id ? { id: d.container_id, name: d.container_name, image: d.image, namespace: d.namespace, pod: d.pod } : null,
    process: d.process,
    user: d.user_name,
    output: d.output,
    tags,
    attack: attackOf(tags),
    count: d.count,
    firstAt: d.first_at,
    lastAt: d.last_at,
    reason: d.reason,
    updatedBy: d.updated_by,
    updatedAt: d.updated_at,
  };
}

export function toEvent(e: EventRow) {
  return {
    id: String(e.id),
    time: e.time,
    receivedAt: e.received_at,
    host: e.host,
    kind: e.kind,
    rule: e.rule,
    priority: e.priority,
    severity: e.severity,
    source: e.source,
    tags: JSON.parse(e.tags) as string[],
    output: e.output,
    container: e.container_id ? { id: e.container_id, name: e.container_name } : null,
    process: e.process,
    pid: e.pid,
    user: e.user_name,
    file: e.file,
    result: e.result,
    detectionId: e.detection_id,
    fields: JSON.parse(e.fields) as Record<string, unknown>,
  };
}

export function createRuntime(db: DatabaseSync, o: RuntimeOptions) {
  const iso = (t = o.clock()) => new Date(t).toISOString();
  const tx = <T>(fn: () => T): T => {
    db.exec("BEGIN");
    try {
      const r = fn();
      db.exec("COMMIT");
      return r;
    } catch (err) {
      db.exec("ROLLBACK");
      throw err;
    }
  };

  // ---- Policies ---------------------------------------------------------------------------------------------------

  const ruleRow = (rule: string) => db.prepare("SELECT * FROM rules WHERE rule = ?").get(rule) as RuleRow | undefined;

  /** Notes the rule as seen and returns its policy. A rule seen for the first time alerts. */
  function seen(e: Pick<FalcoEvent, "rule" | "source" | "priority" | "tags" | "time">): RuleRow {
    db.prepare(
      `INSERT INTO rules (rule, source, priority, tags, first_seen_at, last_seen_at) VALUES (?, ?, ?, ?, ?, ?)
       ON CONFLICT (rule) DO UPDATE SET source = excluded.source, priority = excluded.priority, tags = excluded.tags,
         last_seen_at = MAX(last_seen_at, excluded.last_seen_at)`,
    ).run(e.rule, e.source, e.priority, JSON.stringify(e.tags), e.time, e.time);
    return ruleRow(e.rule)!;
  }

  function toPolicy(r: RuleRow, hits: number) {
    const tags = JSON.parse(r.tags) as string[];
    return {
      rule: r.rule,
      source: r.source,
      priority: r.priority,
      severity: r.severity ?? severityOf(r.priority),
      severityOverride: r.severity,
      mode: r.mode,
      tags,
      attack: attackOf(tags),
      hits7d: hits,
      firstSeenAt: r.first_seen_at,
      lastSeenAt: r.last_seen_at,
      updatedBy: r.updated_by,
      updatedAt: r.updated_at,
    };
  }

  function policies() {
    const hits = new Map(
      (
        db.prepare("SELECT rule, COUNT(*) AS n FROM events WHERE time >= ? GROUP BY rule").all(iso(o.clock() - 7 * DAY)) as Array<{ rule: string; n: number }>
      ).map((r) => [r.rule, r.n]),
    );
    return (db.prepare("SELECT * FROM rules ORDER BY rule").all() as unknown as RuleRow[]).map((r) => toPolicy(r, hits.get(r.rule) ?? 0));
  }

  /** Sets a rule's mode and severity. Open detections stay open; the change applies to events from now on. */
  function setPolicy(rule: string, b: Record<string, unknown>, by: string) {
    only(b, ["mode", "severity"], "{ mode, severity }");
    const r = ruleRow(rule);
    if (!r) throw notFound(`The rule ${rule}`);
    const mode = b.mode ?? r.mode;
    if (mode !== "alert" && mode !== "off") throw bad("mode is alert or off.");
    const severity = b.severity === undefined ? r.severity : b.severity;
    if (severity !== null && !SEVERITIES.includes(severity as Severity))
      throw bad(`severity is null, for Falco's priority, or one of ${SEVERITIES.join(", ")}.`);
    db.prepare("UPDATE rules SET mode = ?, severity = ?, updated_by = ?, updated_at = ? WHERE rule = ?").run(
      mode,
      severity as Severity | null,
      by,
      iso(),
      rule,
    );
    log("info", "policy changed", { rule, mode, severity, by });
    return policies().find((p) => p.rule === rule)!;
  }

  // ---- Events in --------------------------------------------------------------------------------------------------

  /**
   * Opens a detection for the event, or adds it to the open one for the same rule, host, container and program.
   * Returns the detection's id, and whether it is new.
   */
  function detect(h: HostRow, e: FalcoEvent, severity: Severity, chain: ProcNode[]): { id: string; created: boolean } {
    const c = containerOf(e.fields);
    const p = processOf(e.fields);
    const key = sha([e.rule, h.id, c?.id ?? "", p.exe ?? p.name ?? ""].join("\u0000"));
    const open = db.prepare("SELECT * FROM detections WHERE key = ? AND status IN ('open', 'investigating') ORDER BY first_at DESC LIMIT 1").get(key) as
      DetectionRow | undefined;
    if (open) {
      const tree = mergeTree(JSON.parse(open.tree) as ProcNode[], chain);
      db.prepare(
        `UPDATE detections SET count = count + 1, last_at = MAX(last_at, ?), first_at = MIN(first_at, ?), tree = ?, output = ?,
           severity = CASE WHEN ? > (CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END) THEN ? ELSE severity END
         WHERE id = ?`,
      ).run(e.time, e.time, JSON.stringify(tree), e.output, SEVERITY_RANK[severity], severity, open.id);
      return { id: open.id, created: false };
    }
    const id = randomUUID();
    db.prepare(
      `INSERT INTO detections (id, key, rule, host_id, host, severity, container_id, container_name, image, namespace, pod, process, user_name,
         output, tags, tree, count, first_at, last_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)`,
    ).run(
      id,
      key,
      e.rule,
      h.id,
      h.name,
      severity,
      c?.id ?? null,
      c?.name ?? null,
      c?.image ?? null,
      c?.namespace ?? null,
      c?.pod ?? null,
      p.cmdline,
      p.user,
      e.output,
      JSON.stringify(e.tags),
      JSON.stringify(mergeTree([], chain)),
      e.time,
      e.time,
    );
    return { id, created: true };
  }

  /** Keeps one checked event: notes its rule, raises or joins a detection when the policy alerts, and stores it. */
  function keep(h: HostRow, e: FalcoEvent, chain = chainOf(e.fields)) {
    const r = seen(e);
    const severity = r.severity ?? severityOf(e.priority);
    const d = r.mode === "alert" ? detect(h, e, severity, chain) : null;
    const c = containerOf(e.fields);
    const p = processOf(e.fields);
    const row = db
      .prepare(
        `INSERT INTO events (host_id, host, time, received_at, rule, priority, severity, source, kind, tags, output, fields, container_id, container_name,
           process, pid, user_name, file, result, detection_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING *`,
      )
      .get(
        h.id,
        h.name,
        e.time,
        iso(),
        e.rule,
        e.priority,
        severity,
        e.source,
        kindOf(e),
        JSON.stringify(e.tags),
        e.output,
        JSON.stringify(e.fields),
        c?.id ?? null,
        c?.name ?? null,
        p.cmdline,
        p.pid,
        p.user,
        fileOf(e.fields),
        d ? "alerted" : "kept",
        d?.id ?? null,
      ) as unknown as EventRow;
    db.prepare("UPDATE hosts SET events_in = events_in + 1, last_event_at = MAX(COALESCE(last_event_at, ''), ?) WHERE id = ?").run(e.time, h.id);
    if (d?.created) {
      const det = toDetection(db.prepare("SELECT * FROM detections WHERE id = ?").get(d.id) as unknown as DetectionRow);
      queueMicrotask(() => o.onDetection?.(det, toEvent(row)));
    }
    return row;
  }

  /**
   * Takes the events of one agent call. An event that is not what Falco writes is left out and named in the answer,
   * so one bad event never holds back the rest, and the agent does not send it again.
   */
  function ingest(h: HostRow, raw: unknown) {
    if (raw === undefined) return { taken: 0, refused: [] };
    if (!Array.isArray(raw)) throw bad("events is a list of Falco alerts.");
    if (raw.length > MAX_BATCH) throw bad(`At most ${MAX_BATCH} events in one call.`);
    const refused: Array<{ index: number; detail: string }> = [];
    const now = o.clock();
    const oldest = now - o.retentionDays * DAY;
    let taken = 0;
    tx(() => {
      raw.forEach((item, index) => {
        try {
          const e = parseFalco(item, now);
          // Older than retention would be deleted at once; an agent that was cut off for weeks sends only what is kept.
          if (Date.parse(e.time) < oldest) throw new FalcoError("time is older than the retention period.");
          keep(h, e);
          taken++;
        } catch (err) {
          if (!(err instanceof FalcoError)) throw err;
          refused.push({ index, detail: err.message });
        }
      });
    });
    if (refused.length) log("warn", "events refused", { host: h.name, refused: refused.length, first: refused[0] });
    return { taken, refused };
  }

  // ---- Detections -------------------------------------------------------------------------------------------------

  const detectionRow = (id: string) => db.prepare("SELECT * FROM detections WHERE id = ?").get(id) as DetectionRow | undefined;

  function detections(q: URLSearchParams) {
    const where: string[] = [];
    const args: SQLInputValue[] = [];
    const status = q.get("status");
    if (status === "active") where.push("status IN ('open', 'investigating')");
    else if (status) {
      if (!STATUSES.includes(status as DetectionStatus)) throw bad(`status is active or one of ${STATUSES.join(", ")}.`);
      (where.push("status = ?"), args.push(status));
    }
    const severity = q.get("severity");
    if (severity) {
      const list = severity.split(",");
      if (list.some((s) => !SEVERITIES.includes(s as Severity))) throw bad(`severity is a list of ${SEVERITIES.join(", ")}.`);
      (where.push(`severity IN (${list.map(() => "?").join(", ")})`), args.push(...list));
    }
    const host = q.get("host");
    if (host) (where.push("host = ?"), args.push(host));
    const text = q.get("q")?.trim().toLowerCase();
    if (text) {
      where.push("(instr(lower(rule), ?) OR instr(lower(host), ?) OR instr(lower(COALESCE(process, '')), ?) OR instr(lower(COALESCE(container_name, '')), ?))");
      args.push(text, text, text, text);
    }
    const limit = Math.min(Number(q.get("limit") ?? 500) || 500, 1000);
    const rows = db
      .prepare(`SELECT * FROM detections ${where.length ? `WHERE ${where.join(" AND ")}` : ""} ORDER BY last_at DESC LIMIT ?`)
      .all(...args, limit) as unknown as DetectionRow[];
    return rows.map(toDetection);
  }

  function detection(id: string) {
    const d = detectionRow(id);
    if (!d) throw notFound("The detection");
    const events = (db.prepare("SELECT * FROM events WHERE detection_id = ? ORDER BY time DESC LIMIT 20").all(id) as unknown as EventRow[]).map(toEvent);
    return { ...toDetection(d), tree: JSON.parse(d.tree) as ProcNode[], events };
  }

  /** Sets who is on it and how it ended. A false positive needs a reason, as in SIEM (ADR 0040). */
  function setStatus(id: string, b: Record<string, unknown>, by: string) {
    only(b, ["status", "reason"], "{ status, reason }");
    const d = detectionRow(id);
    if (!d) throw notFound("The detection");
    if (!STATUSES.includes(b.status as DetectionStatus)) throw bad(`status is one of ${STATUSES.join(", ")}.`);
    const reason = typeof b.reason === "string" ? b.reason.trim().slice(0, 1000) : "";
    if (b.reason !== undefined && typeof b.reason !== "string") throw bad("reason is text.");
    if (b.status === "false-positive" && !reason) throw bad("Say why it is a false positive: the reason is kept with the detection.");
    db.prepare("UPDATE detections SET status = ?, reason = ?, updated_by = ?, updated_at = ? WHERE id = ?").run(
      b.status as string,
      reason || null,
      by,
      iso(),
      id,
    );
    log("info", "detection status", { id, rule: d.rule, host: d.host, status: b.status, by });
    return detection(id);
  }

  // ---- Events -----------------------------------------------------------------------------------------------------

  function events(q: URLSearchParams) {
    const where: string[] = [];
    const args: SQLInputValue[] = [];
    const kind = q.get("kind");
    if (kind) {
      if (!KINDS.includes(kind as Kind)) throw bad(`kind is one of ${KINDS.join(", ")}.`);
      (where.push("kind = ?"), args.push(kind));
    }
    for (const [param, col] of [
      ["host", "host"],
      ["rule", "rule"],
      ["detection", "detection_id"],
    ] as const) {
      const v = q.get(param);
      if (v) (where.push(`${col} = ?`), args.push(v));
    }
    const result = q.get("result");
    if (result) {
      if (result !== "alerted" && result !== "kept") throw bad("result is alerted or kept.");
      (where.push("result = ?"), args.push(result));
    }
    const since = q.get("since");
    if (since) {
      if (!Number.isFinite(Date.parse(since))) throw bad("since is an RFC 3339 time.");
      (where.push("time >= ?"), args.push(new Date(since).toISOString()));
    }
    const text = q.get("q")?.trim().toLowerCase();
    if (text) {
      where.push("(instr(lower(output), ?) OR instr(lower(rule), ?) OR instr(lower(host), ?) OR instr(lower(COALESCE(container_name, '')), ?))");
      args.push(text, text, text, text);
    }
    const before = q.get("before");
    if (before) {
      if (!/^\d{1,15}$/.test(before)) throw bad("before is the next value of an earlier page.");
      (where.push("id < ?"), args.push(Number(before)));
    }
    const limit = Math.max(1, Math.min(Number(q.get("limit") ?? 100) || 100, 500));
    const rows = db
      .prepare(`SELECT * FROM events ${where.length ? `WHERE ${where.join(" AND ")}` : ""} ORDER BY id DESC LIMIT ?`)
      .all(...args, limit + 1) as unknown as EventRow[];
    const page = rows.slice(0, limit);
    return { events: page.map(toEvent), next: rows.length > limit ? String(page.at(-1)!.id) : null };
  }

  /** The newest Falco event on a host about a file, between two times: who changed a watched file. */
  function lastEventOnFile(hostId: string, path: string, from: string, to: string) {
    return db
      .prepare("SELECT * FROM events WHERE host_id = ? AND file = ? AND time > ? AND time <= ? ORDER BY time DESC LIMIT 1")
      .get(hostId, path, from, to) as EventRow | undefined;
  }

  // ---- Overview ---------------------------------------------------------------------------------------------------

  function summary() {
    const now = o.clock();
    const from = now - 24 * HOUR;
    const bySeverity = Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as Record<Severity, number>;
    for (const r of db.prepare("SELECT severity, COUNT(*) AS n FROM detections WHERE status IN ('open', 'investigating') GROUP BY severity").all() as Array<{
      severity: Severity;
      n: number;
    }>)
      bySeverity[r.severity] = r.n;
    const opened = (a: number, b: number) =>
      (db.prepare("SELECT COUNT(*) AS n FROM detections WHERE first_at >= ? AND first_at < ?").get(iso(a), iso(b)) as { n: number }).n;
    // The hour is counted from the start of the window, so the 24 bars are the last 24 hours, oldest first.
    const perHour = Array.from({ length: 24 }, (_, i) => ({
      hour: iso(from + i * HOUR),
      ...(Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as Record<Severity, number>),
    }));
    for (const r of db
      .prepare("SELECT CAST((julianday(time) - julianday(?)) * 24 AS INTEGER) AS h, severity, COUNT(*) AS n FROM events WHERE time >= ? GROUP BY h, severity")
      .all(iso(from), iso(from)) as Array<{ h: number; severity: Severity; n: number }>)
      if (r.h >= 0 && r.h < 24) perHour[r.h]![r.severity] = r.n;
    const count = (sql: string, ...args: SQLInputValue[]) => (db.prepare(sql).get(...args) as { n: number }).n;
    return {
      detections: {
        active: Object.values(bySeverity).reduce((a, b) => a + b, 0),
        bySeverity,
        openedLastDay: opened(from, now + 1),
        openedDayBefore: opened(from - 24 * HOUR, from),
      },
      events: {
        lastDay: count("SELECT COUNT(*) AS n FROM events WHERE time >= ?", iso(from)),
        alertedLastDay: count("SELECT COUNT(*) AS n FROM events WHERE time >= ? AND result = 'alerted'", iso(from)),
        perHour,
      },
      files: {
        changesLastDay: count("SELECT COUNT(*) AS n FROM file_changes WHERE at >= ?", iso(from)),
        unreviewed: count("SELECT COUNT(*) AS n FROM file_changes WHERE review = 'unreviewed'"),
      },
      processes: { new: count("SELECT COUNT(*) AS n FROM processes WHERE baseline != 'known'") },
      policies: { total: count("SELECT COUNT(*) AS n FROM rules"), off: count("SELECT COUNT(*) AS n FROM rules WHERE mode = 'off'") },
    };
  }

  function gauges() {
    const open = Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as Record<Severity, number>;
    for (const r of db.prepare("SELECT severity, COUNT(*) AS n FROM detections WHERE status IN ('open', 'investigating') GROUP BY severity").all() as Array<{
      severity: Severity;
      n: number;
    }>)
      open[r.severity] = r.n;
    const unreviewed = (db.prepare("SELECT COUNT(*) AS n FROM file_changes WHERE review = 'unreviewed'").get() as { n: number }).n;
    return { open, unreviewed };
  }

  /** Deletes events past retention, and detections and file changes a year after they were closed or reviewed. */
  function purge() {
    const now = o.clock();
    const events = db.prepare("DELETE FROM events WHERE time < ?").run(iso(now - o.retentionDays * DAY)).changes;
    const year = iso(now - 365 * DAY);
    const detections = db.prepare("DELETE FROM detections WHERE status IN ('resolved', 'false-positive') AND last_at < ?").run(year).changes;
    const changes = db.prepare("DELETE FROM file_changes WHERE review != 'unreviewed' AND at < ?").run(year).changes;
    const processes = db.prepare("DELETE FROM processes WHERE last_seen_at < ?").run(iso(now - 90 * DAY)).changes;
    if (events || detections || changes || processes) log("info", "purged", { events, detections, changes, processes });
  }

  return {
    ingest,
    keep,
    seen,
    tx,
    detections,
    detection,
    setStatus,
    events,
    lastEventOnFile,
    policies,
    setPolicy,
    summary,
    gauges,
    purge,
  };
}

export type Runtime = ReturnType<typeof createRuntime>;
