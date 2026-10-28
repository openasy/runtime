// What ran where, and what started it (ADR 0066). runtime-agent's Falco rule "OpenAsy process started" sees every
// program start; the agent counts them by program, parent and user instead of sending each one, and sends the counts
// with the latest start's fields. A host learns for its first days (RUNTIME_LEARNING_DAYS): everything it runs then
// is known. Afterwards a program never seen there is new, and a known program with a parent or user never seen with
// it is drift. A new program in a container raises the detection "New process in container": containers run the
// same image every time, so a program the image never ran is worth a look.
import { randomUUID } from "node:crypto";
import type { DatabaseSync, SQLInputValue } from "node:sqlite";
import type { HostRow } from "./agents.ts";
import { containerOf, FalcoError, processOf, type FalcoEvent, type Fields } from "./falco.ts";
import { bad, isObject, notFound, only } from "./problem.ts";
import type { Runtime } from "./runtime.ts";

export const NEW_PROCESS_RULE = "New process in container";
const MAX_PROCESSES = 5000;

type Baseline = "known" | "new" | "drift";

interface ProcessRow {
  id: string;
  host_id: string;
  host: string;
  image: string;
  exe: string;
  parent: string;
  user_name: string;
  cmdline: string;
  pid: number | null;
  ppid: number | null;
  container_name: string | null;
  namespace: string | null;
  count: number;
  first_seen_at: string;
  last_seen_at: string;
  baseline: Baseline;
}

const toProcess = (p: ProcessRow) => ({
  id: p.id,
  host: { id: p.host_id, name: p.host },
  image: p.image || null,
  container: p.container_name,
  namespace: p.namespace,
  exe: p.exe,
  parent: p.parent || null,
  user: p.user_name || null,
  cmdline: p.cmdline,
  pid: p.pid,
  ppid: p.ppid,
  count: p.count,
  firstSeenAt: p.first_seen_at,
  lastSeenAt: p.last_seen_at,
  baseline: p.baseline,
});

export function createInventory(db: DatabaseSync, runtime: Runtime, o: { clock: () => number }) {
  /** One counted program start from an agent: { fields, count, firstAt, lastAt }. */
  function parseStart(raw: unknown) {
    if (!isObject(raw)) throw new FalcoError("a process is { fields, count, firstAt, lastAt }.");
    const fields = raw.fields;
    if (!isObject(fields) || Object.keys(fields).length > 256) throw new FalcoError("fields is the latest start's output_fields.");
    for (const [k, v] of Object.entries(fields))
      if (
        k.length > 128 ||
        (v !== null && typeof v !== "string" && typeof v !== "number" && typeof v !== "boolean") ||
        (typeof v === "string" && v.length > 4096)
      )
        throw new FalcoError(`"${k.slice(0, 40)}" must be a Falco field with a short value.`);
    const count = raw.count ?? 1;
    if (typeof count !== "number" || !Number.isSafeInteger(count) || count < 1) throw new FalcoError("count is how many starts it stands for.");
    const last = typeof raw.lastAt === "string" ? Date.parse(raw.lastAt) : NaN;
    const first = typeof raw.firstAt === "string" ? Date.parse(raw.firstAt) : last;
    if (!Number.isFinite(last) || !Number.isFinite(first) || first > last) throw new FalcoError("firstAt and lastAt are RFC 3339 times, in order.");
    if (last > o.clock() + 5 * 60_000) throw new FalcoError("lastAt is more than five minutes ahead of Runtime's clock.");
    const f = fields as Fields;
    const p = processOf(f);
    if (!p.exe && !p.name) throw new FalcoError("fields has neither proc.exepath nor proc.name.");
    return { fields: f, count, firstAt: new Date(first).toISOString(), lastAt: new Date(last).toISOString() };
  }

  /** Counts the starts an agent sends, and raises a detection for a program a container never ran before. */
  function record(h: HostRow, raw: unknown) {
    if (raw === undefined) return { taken: 0, refused: [] };
    if (!Array.isArray(raw)) throw bad("processes is a list of counted program starts.");
    if (raw.length > MAX_PROCESSES) throw bad(`At most ${MAX_PROCESSES} processes in one call.`);
    const refused: Array<{ index: number; detail: string }> = [];
    let taken = 0;
    const learning = o.clock() < Date.parse(h.learning_until);
    runtime.tx(() =>
      raw.forEach((item, index) => {
        let s: ReturnType<typeof parseStart>;
        try {
          s = parseStart(item);
        } catch (err) {
          if (!(err instanceof FalcoError)) throw err;
          refused.push({ index, detail: err.message });
          return;
        }
        taken++;
        const p = processOf(s.fields);
        const c = containerOf(s.fields);
        const key = [h.id, c?.image ?? "", (p.exe ?? p.name)!, p.parent ?? "", p.user ?? ""] as const;
        const existing = db.prepare("SELECT id FROM processes WHERE host_id = ? AND image = ? AND exe = ? AND parent = ? AND user_name = ?").get(...key) as
          { id: string } | undefined;
        if (existing) {
          db.prepare(
            `UPDATE processes SET count = count + ?, first_seen_at = MIN(first_seen_at, ?),
               cmdline = CASE WHEN ? >= last_seen_at THEN ? ELSE cmdline END, pid = CASE WHEN ? >= last_seen_at THEN ? ELSE pid END,
               ppid = CASE WHEN ? >= last_seen_at THEN ? ELSE ppid END, last_seen_at = MAX(last_seen_at, ?) WHERE id = ?`,
          ).run(s.count, s.firstAt, s.lastAt, p.cmdline ?? key[2], s.lastAt, p.pid, s.lastAt, p.ppid, s.lastAt, existing.id);
          return;
        }
        const program = db.prepare("SELECT 1 FROM processes WHERE host_id = ? AND image = ? AND exe = ?").get(key[0], key[1], key[2]);
        const baseline: Baseline = learning ? "known" : program ? "drift" : "new";
        db.prepare(
          `INSERT INTO processes (id, host_id, image, exe, parent, user_name, cmdline, pid, ppid, container_name, namespace, count, first_seen_at,
             last_seen_at, baseline) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        ).run(randomUUID(), ...key, p.cmdline ?? key[2], p.pid, p.ppid, c?.name ?? null, c?.namespace ?? null, s.count, s.firstAt, s.lastAt, baseline);
        if (baseline === "new" && c) {
          const e: FalcoEvent = {
            time: s.firstAt,
            rule: NEW_PROCESS_RULE,
            priority: "notice",
            source: "runtime",
            tags: ["container", "process", "openasy"],
            output: `${p.cmdline ?? key[2]} started in container ${c.name}${c.image ? ` (${c.image})` : ""}, which never ran ${key[2]} before; parent ${p.parent ?? "unknown"}`,
            fields: s.fields,
          };
          runtime.keep(h, e);
        }
      }),
    );
    return { taken, refused };
  }

  function processes(q: URLSearchParams) {
    const where: string[] = [];
    const args: SQLInputValue[] = [];
    const host = q.get("host");
    if (host) (where.push("h.name = ?"), args.push(host));
    const baseline = q.get("baseline");
    if (baseline === "unusual") where.push("p.baseline != 'known'");
    else if (baseline) {
      if (!["known", "new", "drift"].includes(baseline)) throw bad("baseline is known, new, drift or unusual (new and drift).");
      (where.push("p.baseline = ?"), args.push(baseline));
    }
    const text = q.get("q")?.trim().toLowerCase();
    if (text) (where.push("(instr(lower(p.cmdline), ?) OR instr(lower(p.image), ?))"), args.push(text, text));
    const rows = db
      .prepare(
        `SELECT p.*, h.name AS host FROM processes p JOIN hosts h ON h.id = p.host_id ${where.length ? `WHERE ${where.join(" AND ")}` : ""}
         ORDER BY p.last_seen_at DESC LIMIT 2000`,
      )
      .all(...args) as unknown as ProcessRow[];
    return rows.map(toProcess);
  }

  /** Marks a new or drifted program as normal for its host or image, so it is known from now on. */
  function accept(id: string, b: Record<string, unknown>) {
    only(b, ["baseline"], '{ baseline: "known" }');
    if (b.baseline !== "known") throw bad('baseline is "known": a program is accepted as normal, never made new by hand.');
    if (!db.prepare("UPDATE processes SET baseline = 'known' WHERE id = ?").run(id).changes) throw notFound("The process");
    const row = db.prepare("SELECT p.*, h.name AS host FROM processes p JOIN hosts h ON h.id = p.host_id WHERE p.id = ?").get(id) as unknown as ProcessRow;
    return toProcess(row);
  }

  return { record, processes, accept };
}

export type Inventory = ReturnType<typeof createInventory>;
