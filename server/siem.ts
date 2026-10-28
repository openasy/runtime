// Detections and file changes on to OpenAsy SIEM (ADR 0040, 0066), where they are events among the other security
// events: Sigma rules there can match them with source "runtime", correlate them with logins and network events,
// and open incidents for severe ones. They go as SIEM's flat events with its ingest token, through an outbox in the
// database, so that SIEM being down or slow loses nothing and never holds up an agent.
import type { DatabaseSync } from "node:sqlite";
import { log } from "./log.ts";

export interface SiemLinkOptions {
  /** Where Runtime calls SIEM, such as http://siem:8080 in the same compose network. */
  url: string;
  /** SIEM's ingest token (SIEM_INGEST_TOKEN): it can send events and nothing else. */
  token: string;
  /** Where people open Runtime, for the link in each event. */
  publicUrl: string;
  clock: () => number;
  /** For tests: the HTTP client. */
  fetch?: typeof fetch;
}

export type FlatEvent = Record<string, string | number | boolean>;

/** SIEM's limits: at most 64 fields and 4096 characters a value; up to 1000 events in one call. */
const BATCH = 500;
const MAX_VALUE = 4000;
/** An event SIEM has refused this many times, about two days of trying, is dropped with a line in the log. */
const GIVE_UP_ATTEMPTS = 48;

/** Keeps only what SIEM takes: no empty values, text cut to its limit. */
export function flat(fields: Record<string, unknown>): FlatEvent {
  const out: FlatEvent = {};
  for (const [k, v] of Object.entries(fields)) {
    if (v === null || v === undefined || v === "") continue;
    if (typeof v === "number" || typeof v === "boolean") out[k] = v;
    else out[k] = String(v).slice(0, MAX_VALUE);
  }
  return out;
}

export function createSiemLink(db: DatabaseSync, o: SiemLinkOptions) {
  const http = o.fetch ?? fetch;
  const base = o.url.replace(/\/$/, "");
  const iso = (t = o.clock()) => new Date(t).toISOString();
  let lastError: string | null = null;
  let lastSentAt: string | null = null;

  const add = (e: FlatEvent) => db.prepare("INSERT INTO outbox (event, next_at) VALUES (?, ?)").run(JSON.stringify(e), iso());

  /** Sends what is due, oldest first. A refusal waits longer each time: a minute, two, four, up to an hour. */
  async function flush(): Promise<number> {
    const rows = db.prepare("SELECT id, event, attempts FROM outbox WHERE next_at <= ? ORDER BY id LIMIT ?").all(iso(), BATCH) as Array<{
      id: number;
      event: string;
      attempts: number;
    }>;
    if (!rows.length) return 0;
    try {
      const res = await http(`${base}/api/v1/events`, {
        method: "POST",
        headers: { authorization: `Bearer ${o.token}`, "content-type": "application/json", "user-agent": "openasy-runtime" },
        body: `[${rows.map((r) => r.event).join(",")}]`,
        signal: AbortSignal.timeout(10_000),
      });
      if (!res.ok) {
        const detail = ((await res.json().catch(() => ({}))) as { detail?: unknown }).detail;
        throw new Error(
          res.status === 401
            ? "SIEM refused the token: set RUNTIME_SIEM_TOKEN to SIEM's ingest token."
            : `SIEM answered ${res.status}${typeof detail === "string" ? `: ${detail}` : "."}`,
        );
      }
      const del = db.prepare("DELETE FROM outbox WHERE id = ?");
      for (const r of rows) del.run(r.id);
      lastError = null;
      lastSentAt = iso();
      return rows.length;
    } catch (err) {
      lastError = (err as Error).message;
      log("warn", "SIEM did not take events; trying again later", { error: lastError, events: rows.length });
      const later = db.prepare("UPDATE outbox SET attempts = attempts + 1, last_error = ?, next_at = ? WHERE id = ?");
      for (const r of rows) later.run(lastError, iso(o.clock() + Math.min(2 ** r.attempts, 60) * 60_000), r.id);
      const dropped = db.prepare("DELETE FROM outbox WHERE attempts >= ?").run(GIVE_UP_ATTEMPTS).changes;
      if (dropped) log("warn", "dropped events SIEM did not take for two days", { events: dropped });
      return 0;
    }
  }

  const status = () => ({
    configured: true,
    url: base,
    pending: (db.prepare("SELECT COUNT(*) AS n FROM outbox").get() as { n: number }).n,
    lastError,
    lastSentAt,
  });

  /** What a detection looks like in SIEM: the event that opened it, with the detection's link. */
  const detection = (
    d: {
      id: string;
      rule: string;
      severity: string;
      host: { name: string };
      container: { id: string; name: string | null; image: string | null; namespace: string | null; pod: string | null } | null;
      process: string | null;
      user: string | null;
      tags: string[];
      attack: string[];
    },
    e: { time: string; output: string; kind: string; priority: string; pid: number | null; file: string | null },
  ) =>
    flat({
      time: e.time,
      host: d.host.name,
      source: "runtime",
      message: e.output || d.rule,
      rule: d.rule,
      severity: d.severity,
      priority: e.priority,
      kind: e.kind,
      "detection.id": d.id,
      "detection.url": `${o.publicUrl}/detections/${d.id}`,
      "container.id": d.container?.id,
      "container.name": d.container?.name,
      "container.image": d.container?.image,
      "k8s.ns.name": d.container?.namespace,
      "k8s.pod.name": d.container?.pod,
      "proc.cmdline": d.process,
      "proc.pid": e.pid ?? undefined,
      "user.name": d.user,
      "fd.name": e.file,
      tags: d.tags.join(","),
      "mitre.technique": d.attack.join(","),
    });

  const fileChange = (c: {
    id: string;
    host: { name: string };
    path: string;
    change: string;
    at: string;
    by: string | null;
    after: { sha256: string | null } | null;
  }) =>
    flat({
      time: c.at,
      host: c.host.name,
      source: "runtime",
      message: `${c.path} ${c.change}${c.by ? ` by ${c.by}` : ""}`,
      rule: "File integrity change",
      kind: "file",
      "fim.change": c.change,
      "fim.path": c.path,
      "fim.sha256": c.after?.sha256 ?? undefined,
      "fim.by": c.by,
      "fim.url": `${o.publicUrl}/file-integrity?change=${c.id}`,
    });

  return { add, flush, status, detection, fileChange };
}

export type SiemLink = ReturnType<typeof createSiemLink>;
