// Starts the app on a random port for tests, with a clock the tests move, and helpers that speak as an agent does.
import { createServer, type RequestListener, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { createAuth } from "@openasy/auth";
import { createAgents } from "./agents.ts";
import { createApp, type AppOptions } from "./app.ts";
import { openDb } from "./db.ts";
import { createIntegrity } from "./integrity.ts";
import { createInventory } from "./inventory.ts";
import { createRuntime } from "./runtime.ts";
import { createSiemLink } from "./siem.ts";

export const ADMIN_TOKEN = "test-admin-token";
export const T0 = Date.parse("2026-10-28T13:00:00Z");

export const report = (over: Record<string, unknown> = {}) => ({
  version: "0.1.0",
  os: "Ubuntu 24.04.1 LTS",
  kernel: "6.8.0-45-generic",
  arch: "x64",
  falco: { status: "ok", version: "0.41.3", detail: null },
  fimPaths: ["/etc/passwd", "/etc/ssh"],
  dropped: 0,
  ...over,
});

/** A Falco alert as json_output writes it: a shell in a container, started by Node.js. */
export const shell = (over: Record<string, unknown> = {}, fields: Record<string, unknown> = {}) => ({
  time: "2026-10-28T12:58:12.418093117Z",
  rule: "Terminal shell in container",
  priority: "Notice",
  source: "syscall",
  tags: ["container", "shell", "mitre_execution", "T1059"],
  output: "12:58:12.418093117: Notice A shell was spawned in a container with an attached terminal (user=app shell=sh parent=node cmdline=sh -c id)",
  output_fields: {
    "evt.type": "execve",
    "proc.pid": 30551,
    "proc.name": "sh",
    "proc.exepath": "/bin/sh",
    "proc.cmdline": "sh -c id; uname -a",
    "proc.ppid": 4188,
    "proc.pname": "node",
    "proc.pcmdline": "node /app/server.js",
    "proc.apid[2]": 4120,
    "proc.aname[2]": "containerd-shim",
    "user.name": "app",
    "container.id": "6f9c7d0a1b2c",
    "container.name": "orders-api",
    "container.image.repository": "registry.example.com/orders-api",
    "container.image.tag": "2.14.1",
    "k8s.ns.name": "orders",
    "k8s.pod.name": "orders-api-6f9c7d",
    ...fields,
  },
  hostname: "worker-prod-04",
  ...over,
});

export async function startApp(opts: Partial<AppOptions> & { version: string; siemUrl?: string; learningDays?: number }) {
  const db = openDb(":memory:");
  let now = T0;
  const clock = () => now;
  const { siemUrl, learningDays = 0, ...appOptions } = opts;
  const siem = siemUrl ? createSiemLink(db, { url: siemUrl, token: "siem-token", publicUrl: "https://runtime.example.com", clock }) : undefined;
  const runtime = createRuntime(db, { clock, retentionDays: 30, onDetection: siem && ((d, e) => siem.add(siem.detection(d, e))) });
  const agents = createAgents(db, { version: opts.version, learningDays, clock });
  const inventory = createInventory(db, runtime, { clock });
  const integrity = createIntegrity(db, runtime, { clock, onChange: siem && ((c) => siem.add(siem.fileChange(c))) });
  // The origin is known once the port is, so the handler is set after listening.
  let handler: RequestListener = (_req, res) => res.writeHead(503).end();
  const server: Server = createServer((req, res) => handler(req, res));
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const base = `http://localhost:${(server.address() as AddressInfo).port}`;
  const auth = createAuth({ db, product: "runtime", productName: "OpenAsy Runtime", origin: base });
  handler = createApp({ db, runtime, agents, inventory, integrity, siem, auth, adminToken: ADMIN_TOKEN, ...appOptions });
  const as =
    (token: string) =>
    (path: string, init: RequestInit = {}) =>
      fetch(base + path, { ...init, headers: { authorization: `Bearer ${token}`, "content-type": "application/json", ...init.headers } });
  const admin = as(ADMIN_TOKEN);
  const get = async (path: string) => (await (await admin(path)).json()) as any;
  const send = (method: string, path: string, body?: unknown) => admin(path, { method, ...(body !== undefined && { body: JSON.stringify(body) }) });

  /** Makes a token and enrols a host with it, as runtime-agent does on its first start. */
  async function enrol(name = "worker-prod-04", over: Record<string, unknown> = {}) {
    const { token } = (await (await send("POST", "/api/v1/enrollment-tokens", { name: `for ${name}` })).json()) as { token: string };
    const res = await fetch(`${base}/api/v1/agent/enroll`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ token, name, report: report(over) }),
    });
    const { hostId, secret } = (await res.json()) as { hostId: string; secret: string };
    const agent = as(secret);
    return {
      hostId,
      secret,
      events: (events: unknown[], processes?: unknown[]) =>
        agent("/api/v1/agent/events", { method: "POST", body: JSON.stringify({ report: report(over), events, ...(processes && { processes }) }) }),
      files: (files: unknown[], paths = ["/etc/passwd", "/etc/ssh"], complete = true) =>
        agent("/api/v1/agent/files", { method: "POST", body: JSON.stringify({ report: report(over), paths, files, complete }) }),
    };
  }
  const close = () => new Promise<void>((resolve) => server.close(() => resolve()));
  return { db, runtime, agents, inventory, integrity, siem, auth, base, admin, get, send, enrol, close, later: (ms: number) => (now += ms) };
}
