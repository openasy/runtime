// Falco's alerts as its JSON output writes them (`json_output: true`), which is what runtime-agent receives from
// Falco's http_output and sends on (ADR 0066). Runtime has no sensor and no rule engine of its own: Falco watches the
// kernel with eBPF and matches its rules, and this module reads what it says into the fields Runtime keeps.
//
//   {"time":"2026-10-28T13:58:12.418093117Z","rule":"Terminal shell in container","priority":"Notice",
//    "source":"syscall","tags":["container","shell","T1059"],"output":"13:58:12.418093117: Notice A shell was ...",
//    "output_fields":{"proc.pid":30551,"proc.cmdline":"sh -c id","proc.ppid":4188,"proc.pcmdline":"node server.js",...}}

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Kind = "exec" | "network" | "file" | "kernel" | "other";

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];
export const PRIORITIES = ["emergency", "alert", "critical", "error", "warning", "notice", "informational", "debug"] as const;
export type Priority = (typeof PRIORITIES)[number];

/** Falco's priority as a severity, until a policy sets another for the rule. */
export function severityOf(priority: Priority): Severity {
  if (priority === "emergency" || priority === "alert" || priority === "critical") return "critical";
  if (priority === "error" || priority === "warning") return "high";
  if (priority === "notice") return "medium";
  return priority === "informational" ? "low" : "info";
}

export const SEVERITY_RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

/** The fields kept for an event: what the event holds, as Falco named it. */
export type Fields = Record<string, string | number | boolean | null>;

export interface FalcoEvent {
  time: string;
  rule: string;
  priority: Priority;
  source: string;
  tags: string[];
  output: string;
  fields: Fields;
}

/** Longest text value kept; longer command lines are cut, as Falco itself cuts them. */
export const MAX_VALUE = 4096;
const MAX_FIELDS = 256;
const MAX_TAGS = 64;
const FIELD = /^[A-Za-z][A-Za-z0-9_.]*(\[[A-Za-z0-9_./-]{1,64}\])?$/;

export class FalcoError extends Error {}

const cut = (s: string, n = MAX_VALUE) => (s.length > n ? s.slice(0, n - 1) + "…" : s);

/** Checks one alert. Anything that is not what Falco writes is refused with what is wrong, never guessed at. */
export function parseFalco(raw: unknown, now: number): FalcoEvent {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) throw new FalcoError("an event is a JSON object, as Falco's json_output writes it.");
  const r = raw as Record<string, unknown>;
  if (typeof r.rule !== "string" || !r.rule.trim() || r.rule.length > 200) throw new FalcoError("rule is the name of the Falco rule, up to 200 characters.");
  const priority = typeof r.priority === "string" ? r.priority.toLowerCase() : "";
  if (!(PRIORITIES as readonly string[]).includes(priority)) throw new FalcoError(`priority is one of Falco's: ${PRIORITIES.join(", ")}.`);
  const t = typeof r.time === "string" ? Date.parse(r.time) : NaN;
  if (!Number.isFinite(t)) throw new FalcoError("time is an RFC 3339 time.");
  if (t > now + 5 * 60_000) throw new FalcoError("time is more than five minutes ahead of Runtime's clock.");
  const tags = r.tags ?? [];
  if (!Array.isArray(tags) || tags.length > MAX_TAGS || tags.some((x) => typeof x !== "string" || x.length > 64))
    throw new FalcoError(`tags is a list of at most ${MAX_TAGS} short names.`);
  const of = r.output_fields ?? {};
  if (of === null || typeof of !== "object" || Array.isArray(of)) throw new FalcoError("output_fields is an object.");
  const entries = Object.entries(of as Record<string, unknown>);
  if (entries.length > MAX_FIELDS) throw new FalcoError(`output_fields has at most ${MAX_FIELDS} fields.`);
  const fields: Fields = {};
  for (const [k, v] of entries) {
    if (!FIELD.test(k) || k.length > 128) throw new FalcoError(`"${k.slice(0, 40)}" is not a Falco field name.`);
    if (v !== null && typeof v !== "string" && typeof v !== "number" && typeof v !== "boolean")
      throw new FalcoError(`"${k}" must be text, a number, true/false or null.`);
    fields[k] = typeof v === "string" ? cut(v) : v;
  }
  return {
    time: new Date(t).toISOString(),
    rule: r.rule.trim(),
    priority: priority as Priority,
    source: typeof r.source === "string" && r.source ? cut(r.source, 64) : "syscall",
    tags: [...new Set(tags as string[])],
    output: typeof r.output === "string" ? cut(r.output, 8192) : "",
    fields,
  };
}

const str = (f: Fields, k: string): string | null => {
  const v = f[k];
  return v === undefined || v === null || v === "" || v === "<NA>" ? null : String(v);
};
const num = (f: Fields, k: string): number | null => {
  const v = f[k];
  const n = typeof v === "number" ? v : typeof v === "string" && /^\d+$/.test(v) ? Number(v) : NaN;
  return Number.isSafeInteger(n) ? n : null;
};

/** Falco names the host itself as container "host"; Runtime calls that no container. */
export function containerOf(f: Fields) {
  const id = str(f, "container.id");
  if (!id || id === "host") return null;
  const repo = str(f, "container.image.repository");
  const tag = str(f, "container.image.tag");
  return {
    id,
    name: str(f, "container.name") ?? str(f, "k8s.pod.name") ?? id.slice(0, 12),
    image: repo ? (tag ? `${repo}:${tag}` : repo) : str(f, "container.image"),
    namespace: str(f, "k8s.ns.name"),
    pod: str(f, "k8s.pod.name"),
  };
}

export function processOf(f: Fields) {
  return {
    name: str(f, "proc.name"),
    exe: str(f, "proc.exepath") ?? str(f, "proc.exe"),
    cmdline: str(f, "proc.cmdline") ?? str(f, "proc.name"),
    pid: num(f, "proc.pid"),
    ppid: num(f, "proc.ppid"),
    parent: str(f, "proc.pname"),
    user: str(f, "user.name"),
  };
}

/** The file an event is about: an open, a rename's target or an unlink. */
export function fileOf(f: Fields): string | null {
  return str(f, "fs.path.target") ?? str(f, "fs.path.name") ?? str(f, "evt.arg.name") ?? (str(f, "fd.typechar") === "f" ? str(f, "fd.name") : null);
}

/** What kind of activity it was, for the Events page's tabs: by Falco's own tags first, then by its fields. */
export function kindOf(e: Pick<FalcoEvent, "tags" | "fields">): Kind {
  const tags = new Set(e.tags.map((t) => t.toLowerCase()));
  const type = str(e.fields, "evt.type") ?? "";
  if (/^(init_module|finit_module|delete_module|ptrace|bpf|kexec_load|mount|umount2?)$/.test(type) || tags.has("kernel")) return "kernel";
  if (tags.has("network") || str(e.fields, "fd.rip") || str(e.fields, "fd.sip") || str(e.fields, "fd.rport")) return "network";
  if (/^(execve|execveat)$/.test(type) || tags.has("process") || tags.has("shell")) return "exec";
  if (tags.has("filesystem") || fileOf(e.fields)) return "file";
  return "other";
}

/** MITRE ATT&CK technique ids among Falco's tags, such as T1059 or T1059.004. */
export const attackOf = (tags: string[]) => tags.filter((t) => /^T\d{4}(\.\d{3})?$/.test(t));

export interface ProcNode {
  pid: number | null;
  cmd: string;
  user: string | null;
  /** The process the rule matched. */
  flagged: boolean;
  children: ProcNode[];
}

/** Ancestors Falco is asked for with append_output (see runtime-agent's falco/runtime.yaml): proc.apid[2] to [7]. */
const ANCESTORS = [7, 6, 5, 4, 3, 2];

/**
 * The process tree of one event, as a chain from the oldest known ancestor to the process the rule matched: Falco
 * gives the process and its parent with their command lines, and older ancestors by name and pid.
 */
export function chainOf(f: Fields): ProcNode[] {
  const p = processOf(f);
  const chain: ProcNode[] = [];
  for (const i of ANCESTORS) {
    const name = str(f, `proc.aname[${i}]`);
    if (name) chain.push({ pid: num(f, `proc.apid[${i}]`), cmd: name, user: null, flagged: false, children: [] });
  }
  const parent = str(f, "proc.pcmdline") ?? p.parent;
  if (parent || p.ppid !== null) chain.push({ pid: p.ppid, cmd: parent ?? "?", user: null, flagged: false, children: [] });
  chain.push({ pid: p.pid, cmd: p.cmdline ?? "?", user: p.user, flagged: true, children: [] });
  return chain;
}

/** Most processes kept in one detection's tree; later events still count, their processes are not added. */
export const MAX_TREE_NODES = 64;

const size = (n: ProcNode): number => 1 + n.children.reduce((s, c) => s + size(c), 0);

/**
 * Adds an event's chain to a detection's tree. Processes are the same process when their pids match, so the shell
 * and the `id` it started, seen in two events, end up parent and child. A chain whose root is not in the tree is
 * added beside it.
 */
export function mergeTree(roots: ProcNode[], chain: ProcNode[]): ProcNode[] {
  if (roots.reduce((s, r) => s + size(r), 0) + chain.length > MAX_TREE_NODES) return roots;
  const out = structuredClone(roots);
  const find = (nodes: ProcNode[], pid: number | null): ProcNode | undefined => {
    if (pid === null) return undefined;
    for (const n of nodes) {
      if (n.pid === pid) return n;
      const hit = find(n.children, pid);
      if (hit) return hit;
    }
    return undefined;
  };
  // The deepest process of the chain already in the tree is where the rest hangs.
  let at = chain.length - 1;
  while (at >= 0 && !find(out, chain[at]!.pid)) at--;
  let parent: ProcNode | undefined;
  if (at >= 0) {
    parent = find(out, chain[at]!.pid)!;
    // What a later event knows better: the full command line instead of a name, and that the rule matched it.
    if (chain[at]!.cmd.length > parent.cmd.length) parent.cmd = chain[at]!.cmd;
    parent.user ??= chain[at]!.user;
    parent.flagged ||= chain[at]!.flagged;
  }
  for (const n of chain.slice(at + 1)) {
    const node = { ...n, children: [] };
    if (parent) parent.children.push(node);
    else out.push(node);
    parent = node;
  }
  return out;
}
