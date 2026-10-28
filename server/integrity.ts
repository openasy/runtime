// File integrity (ADR 0066). runtime-agent reads the files it watches on its host, read-only, every few minutes:
// their SHA-256, mode, owner and size, or a link's target. Runtime compares each read with the last: a file that
// appears, changes, loses or gains permissions, or goes is a change to review. The first read of a host, and files
// under a path the agent was told to watch only now, are its baseline and no change. Which process changed a file
// comes from Falco: the newest event about that file on that host since the read before.
import { randomUUID } from "node:crypto";
import type { DatabaseSync, SQLInputValue } from "node:sqlite";
import type { HostRow } from "./agents.ts";
import { bad, isObject, notFound, only } from "./problem.ts";
import type { Runtime } from "./runtime.ts";

export type Change = "created" | "modified" | "deleted" | "permissions";
export type Review = "unreviewed" | "approved" | "suspicious";
const REVIEWS: Review[] = ["unreviewed", "approved", "suspicious"];
const MAX_FILES = 50_000;

/** A watched file as the agent read it. `sha256` is null for a file larger than the agent hashes. */
export interface FileState {
  kind: "file" | "link";
  sha256: string | null;
  size: number;
  mode: string;
  uid: number;
  gid: number;
  target: string | null;
}

interface ChangeRow {
  id: string;
  host_id: string;
  host: string;
  path: string;
  change: Change;
  before: string | null;
  after: string | null;
  at: string;
  by_process: string | null;
  by_event_id: number | null;
  review: Review;
  note: string | null;
  reviewed_by: string | null;
  reviewed_at: string | null;
}

export const toChange = (c: ChangeRow) => ({
  id: c.id,
  host: { id: c.host_id, name: c.host },
  path: c.path,
  change: c.change,
  before: c.before ? (JSON.parse(c.before) as FileState) : null,
  after: c.after ? (JSON.parse(c.after) as FileState) : null,
  at: c.at,
  by: c.by_process,
  byEventId: c.by_event_id === null ? null : String(c.by_event_id),
  review: c.review,
  note: c.note,
  reviewedBy: c.reviewed_by,
  reviewedAt: c.reviewed_at,
});

function parseState(raw: unknown, i: number): [string, FileState] {
  const err = (why: string) => bad(`files[${i}]: ${why}`);
  if (!isObject(raw)) throw err("a file is { path, kind, sha256, size, mode, uid, gid, target }.");
  const { path, kind, sha256, size, mode, uid, gid, target } = raw;
  if (typeof path !== "string" || !path.startsWith("/") || path.length > 4096 || path.includes("\u0000")) throw err("path is an absolute path.");
  if (kind !== "file" && kind !== "link") throw err("kind is file or link.");
  if (sha256 !== null && (typeof sha256 !== "string" || !/^[0-9a-f]{64}$/.test(sha256))) throw err("sha256 is 64 hex digits, or null.");
  if (typeof size !== "number" || !Number.isSafeInteger(size) || size < 0) throw err("size is a number of bytes.");
  if (typeof mode !== "string" || !/^[0-7]{3,4}$/.test(mode)) throw err("mode is octal, such as 0644.");
  for (const [n, v] of [
    ["uid", uid],
    ["gid", gid],
  ] as const)
    if (typeof v !== "number" || !Number.isSafeInteger(v) || v < 0) throw err(`${n} is a number.`);
  if (target !== null && target !== undefined && (typeof target !== "string" || target.length > 4096)) throw err("target is a link's target, or null.");
  return [
    path,
    { kind, sha256: sha256 as string | null, size, mode: mode.padStart(4, "0"), uid: uid as number, gid: gid as number, target: (target as string) ?? null },
  ];
}

/** A file is watched when it is a watched path, or under one. */
const covered = (path: string, paths: string[]) => paths.some((p) => path === p || path.startsWith(p.endsWith("/") ? p : `${p}/`));

function changeOf(a: FileState, b: FileState): Change | null {
  if (a.kind !== b.kind || a.sha256 !== b.sha256 || a.size !== b.size || a.target !== b.target) return "modified";
  if (a.mode !== b.mode || a.uid !== b.uid || a.gid !== b.gid) return "permissions";
  return null;
}

export interface IntegrityOptions {
  clock: () => number;
  /** Called with each change, to send on to SIEM. */
  onChange?: (c: ReturnType<typeof toChange>) => void;
}

export function createIntegrity(db: DatabaseSync, runtime: Runtime, o: IntegrityOptions) {
  const iso = (t = o.clock()) => new Date(t).toISOString();

  /**
   * Compares a read of the host's watched files with the last one, and records what changed. `complete` is false
   * when the agent stopped at its limit; then files missing from the read are not taken as deleted.
   */
  function snapshot(h: HostRow, b: Record<string, unknown>) {
    const paths = b.paths;
    if (!Array.isArray(paths) || paths.length > 256 || paths.some((p) => typeof p !== "string" || !p.startsWith("/") || p.length > 4096))
      throw bad("paths is the list of absolute paths the agent watches.");
    if (!Array.isArray(b.files) || b.files.length > MAX_FILES) throw bad(`files is a list of at most ${MAX_FILES} files.`);
    if (typeof b.complete !== "boolean") throw bad("complete says whether every watched file was read.");
    const read = new Map(b.files.map(parseState));
    const before = new Map(
      (db.prepare("SELECT path, state FROM files WHERE host_id = ?").all(h.id) as Array<{ path: string; state: string }>).map((r) => [
        r.path,
        JSON.parse(r.state) as FileState,
      ]),
    );
    const first = h.fim_scanned_at === null;
    const watched = JSON.parse(h.fim_paths) as string[];
    const at = iso();
    // Falco's events about a file are looked for since the read before, with a minute for the clocks of the two.
    const since = iso(Date.parse(h.fim_scanned_at ?? h.enrolled_at) - 60_000);
    const changes: Array<{ path: string; change: Change; before: FileState | null; after: FileState | null }> = [];
    for (const [path, state] of read) {
      const old = before.get(path);
      if (!old) {
        if (!first && covered(path, watched)) changes.push({ path, change: "created", before: null, after: state });
        continue;
      }
      const c = changeOf(old, state);
      if (c) changes.push({ path, change: c, before: old, after: state });
    }
    const gone = b.complete ? [...before.keys()].filter((p) => !read.has(p)) : [];
    for (const path of gone) if (covered(path, paths as string[])) changes.push({ path, change: "deleted", before: before.get(path)!, after: null });

    const recorded = runtime.tx(() => {
      const upsert = db.prepare(
        "INSERT INTO files (host_id, path, state, seen_at) VALUES (?, ?, ?, ?) ON CONFLICT (host_id, path) DO UPDATE SET state = excluded.state, seen_at = excluded.seen_at",
      );
      for (const [path, state] of read) upsert.run(h.id, path, JSON.stringify(state), at);
      const del = db.prepare("DELETE FROM files WHERE host_id = ? AND path = ?");
      for (const path of gone) del.run(h.id, path);
      db.prepare("UPDATE hosts SET fim_scanned_at = ?, fim_paths = ? WHERE id = ?").run(at, JSON.stringify(paths), h.id);
      return changes.map((c) => {
        const e = runtime.lastEventOnFile(h.id, c.path, since, at);
        const id = randomUUID();
        const by = e ? `${e.process ?? "?"}${e.user_name ? ` (${e.user_name})` : ""}` : null;
        db.prepare(
          "INSERT INTO file_changes (id, host_id, host, path, change, before, after, at, by_process, by_event_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ).run(id, h.id, h.name, c.path, c.change, c.before && JSON.stringify(c.before), c.after && JSON.stringify(c.after), at, by, e?.id ?? null);
        return toChange(db.prepare("SELECT * FROM file_changes WHERE id = ?").get(id) as unknown as ChangeRow);
      });
    });
    for (const c of recorded) o.onChange?.(c);
    return { files: read.size, changes: recorded.length, baseline: first };
  }

  function changes(q: URLSearchParams) {
    const where: string[] = [];
    const args: SQLInputValue[] = [];
    const host = q.get("host");
    if (host) (where.push("host = ?"), args.push(host));
    const review = q.get("review");
    if (review) {
      if (!REVIEWS.includes(review as Review)) throw bad(`review is one of ${REVIEWS.join(", ")}.`);
      (where.push("review = ?"), args.push(review));
    }
    const rows = db
      .prepare(`SELECT * FROM file_changes ${where.length ? `WHERE ${where.join(" AND ")}` : ""} ORDER BY at DESC LIMIT 1000`)
      .all(...args) as unknown as ChangeRow[];
    return rows.map(toChange);
  }

  /** Approved: an expected change, such as a package upgrade. Suspicious: someone looks into it. */
  function review(id: string, b: Record<string, unknown>, by: string) {
    only(b, ["review", "note"], "{ review, note }");
    if (!REVIEWS.includes(b.review as Review)) throw bad(`review is one of ${REVIEWS.join(", ")}.`);
    if (b.note !== undefined && typeof b.note !== "string") throw bad("note is text.");
    const note = typeof b.note === "string" ? b.note.trim().slice(0, 1000) || null : null;
    const done = b.review !== "unreviewed";
    if (
      !db
        .prepare("UPDATE file_changes SET review = ?, note = ?, reviewed_by = ?, reviewed_at = ? WHERE id = ?")
        .run(b.review as Review, note, done ? by : null, done ? iso() : null, id).changes
    )
      throw notFound("The file change");
    return toChange(db.prepare("SELECT * FROM file_changes WHERE id = ?").get(id) as unknown as ChangeRow);
  }

  return { snapshot, changes, review };
}

export type Integrity = ReturnType<typeof createIntegrity>;
