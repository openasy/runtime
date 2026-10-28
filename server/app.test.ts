import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { gzipSync } from "node:zlib";
import { report, shell, startApp } from "./test-app.ts";

let app: Awaited<ReturnType<typeof startApp>>;

beforeAll(async () => {
  app = await startApp({ version: "0.1.0" });
});
afterAll(() => app.close());

const enrollWith = (token: string, name: string, over: Record<string, unknown> = {}) =>
  fetch(`${app.base}/api/v1/agent/enroll`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ token, name, report: report(), ...over }),
  });

describe("enrolment", () => {
  it("trades a token for the host's own secret, once per use, and keeps only hashes", async () => {
    const res = await app.send("POST", "/api/v1/enrollment-tokens", { name: "workers", maxUses: 2, days: 1 });
    expect(res.status).toBe(201);
    const t = (await res.json()) as { token: string; id: string; state: string };
    expect(t).toMatchObject({ state: "active", token: expect.stringMatching(/^oie_/) });
    expect(JSON.stringify(await app.get("/api/v1/enrollment-tokens"))).not.toContain(t.token);

    const a = await enrollWith(t.token, "node-a");
    expect(a.status).toBe(200);
    const { secret } = (await a.json()) as { secret: string };
    expect(secret).toMatch(/^oia_/);
    expect(JSON.stringify(app.db.prepare("SELECT * FROM hosts").all())).not.toContain(secret);
    expect(JSON.stringify(app.db.prepare("SELECT * FROM enrollment_tokens").all())).not.toContain(t.token);

    // A fleet token enrols each name once: taking over a host that is enrolled is an admin's decision.
    expect((await enrollWith(t.token, "node-a")).status).toBe(409);
    expect((await enrollWith(t.token, "node-b")).status).toBe(200);
    expect((await enrollWith(t.token, "node-c")).status).toBe(401);
    expect((await app.get("/api/v1/enrollment-tokens")).tokens[0]).toMatchObject({ uses: 2, state: "used" });
  });

  it("refuses expired, deleted and unknown tokens, and bad names", async () => {
    const { token, id } = (await (await app.send("POST", "/api/v1/enrollment-tokens", { name: "one" })).json()) as { token: string; id: string };
    expect((await enrollWith(token, "../etc")).status).toBe(422);
    expect((await enrollWith(token, "x", { report: { version: "1" } })).status).toBe(422);
    expect((await app.send("DELETE", `/api/v1/enrollment-tokens/${id}`)).status).toBe(204);
    expect((await enrollWith(token, "node-d")).status).toBe(401);
    expect((await enrollWith("oie_nope", "node-d")).status).toBe(401);
    const { token: old } = (await (await app.send("POST", "/api/v1/enrollment-tokens", { name: "short", days: 1 })).json()) as { token: string };
    app.later(86_400_000 + 1);
    expect((await enrollWith(old, "node-d")).status).toBe(401);
    app.later(-(86_400_000 + 1));
  });

  it("needs an admin to make tokens", async () => {
    expect((await fetch(`${app.base}/api/v1/enrollment-tokens`, { method: "POST", body: "{}" })).status).toBe(401);
    expect((await app.send("POST", "/api/v1/enrollment-tokens", { name: "x", maxUses: 0 })).status).toBe(422);
    expect((await app.send("POST", "/api/v1/enrollment-tokens", { name: "x", uses: 3 })).status).toBe(422);
  });
});

describe("events in", () => {
  let agent: Awaited<ReturnType<typeof app.enrol>>;

  beforeAll(async () => {
    agent = await app.enrol("worker-prod-04");
  });

  it("need the agent's own secret, checked before the body is read", async () => {
    const res = await fetch(`${app.base}/api/v1/agent/events`, { method: "POST", headers: { authorization: "Bearer oia_wrong" }, body: "{}" });
    expect(res.status).toBe(401);
    const admin = await app.send("POST", "/api/v1/agent/events", { report: report(), events: [] });
    expect(admin.status).toBe(401);
  });

  it("open a detection with the process tree, and a later event of the same process joins it", async () => {
    const res = await agent.events([shell()]);
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ events: { taken: 1, refused: [] }, processes: { taken: 0 } });
    const second = shell({ time: "2026-10-28T12:58:12.420Z" }, { "proc.pid": 30553, "proc.cmdline": "sh -c uname -a", "proc.ppid": 4188 });
    await agent.events([second]);
    const [d] = (await app.get("/api/v1/detections")).detections;
    expect(d).toMatchObject({
      rule: "Terminal shell in container",
      severity: "medium",
      status: "open",
      count: 2,
      host: { name: "worker-prod-04" },
      container: { name: "orders-api", image: "registry.example.com/orders-api:2.14.1", namespace: "orders" },
      attack: ["T1059"],
    });
    const full = await app.get(`/api/v1/detections/${d.id}`);
    expect(full.tree[0].cmd).toBe("containerd-shim");
    expect(full.tree[0].children[0].children.map((c: { pid: number }) => c.pid)).toEqual([30551, 30553]);
    expect(full.events).toHaveLength(2);
  });

  it("are kept even when one in the batch is not Falco's, and gzipped", async () => {
    const body = gzipSync(JSON.stringify({ report: report(), events: [{ rule: "x" }, shell({ rule: "Read sensitive file untrusted", priority: "Warning" })] }));
    const res = await fetch(`${app.base}/api/v1/agent/events`, {
      method: "POST",
      headers: { authorization: `Bearer ${agent.secret}`, "content-type": "application/json", "content-encoding": "gzip" },
      body,
    });
    const r = (await res.json()) as { events: { taken: number; refused: Array<{ index: number; detail: string }> } };
    expect(r.events.taken).toBe(1);
    expect(r.events.refused).toEqual([{ index: 0, detail: expect.stringMatching(/priority/) }]);
    expect((await app.get("/api/v1/events?rule=Read%20sensitive%20file%20untrusted")).events[0]).toMatchObject({ severity: "high", result: "alerted" });
  });

  it("refuse a call without the agent's report", async () => {
    const res = await fetch(`${app.base}/api/v1/agent/events`, {
      method: "POST",
      headers: { authorization: `Bearer ${agent.secret}` },
      body: JSON.stringify({ events: [] }),
    });
    expect(res.status).toBe(422);
  });

  it("are searched and paged, newest first", async () => {
    const all = await app.get("/api/v1/events");
    expect(all.events).toHaveLength(3);
    const page = await app.get("/api/v1/events?limit=2");
    expect(page.events).toHaveLength(2);
    const rest = await app.get(`/api/v1/events?limit=2&before=${page.next}`);
    expect(rest).toMatchObject({ events: [{ id: all.events[2].id }], next: null });
    expect((await app.get("/api/v1/events?kind=exec&q=orders")).events.length).toBe(3);
    expect((await app.get("/api/v1/events?kind=kernel")).events).toEqual([]);
    expect((await app.send("GET", "/api/v1/events?kind=nope")).status).toBe(422);
  });
});

describe("policies", () => {
  it("are one per rule seen; off keeps the events and raises nothing", async () => {
    const agent = await app.enrol("api-prod-03");
    const rule = encodeURIComponent("Terminal shell in container");
    const p = (await app.get("/api/v1/policies")).policies.find((x: { rule: string }) => x.rule === "Terminal shell in container");
    expect(p).toMatchObject({ mode: "alert", severity: "medium", severityOverride: null, priority: "notice", hits7d: 2 });
    expect((await app.send("PUT", `/api/v1/policies/${rule}`, { mode: "loud" })).status).toBe(422);
    expect((await app.send("PUT", `/api/v1/policies/${rule}`, { severity: "high" })).status).toBe(200);
    await agent.events([shell({}, { "container.id": "aaaa11112222" })]);
    expect((await app.get("/api/v1/detections?host=api-prod-03")).detections[0].severity).toBe("high");

    await app.send("PUT", `/api/v1/policies/${rule}`, { mode: "off" });
    await agent.events([shell({}, { "container.id": "bbbb11112222" })]);
    expect((await app.get("/api/v1/detections?host=api-prod-03")).detections).toHaveLength(1);
    expect((await app.get("/api/v1/events?host=api-prod-03&result=kept")).events).toHaveLength(1);
    await app.send("PUT", `/api/v1/policies/${rule}`, { mode: "alert", severity: null });
    expect((await app.send("PUT", "/api/v1/policies/Nope", { mode: "off" })).status).toBe(404);
  });
});

describe("detections", () => {
  it("are worked to an end; a false positive needs a reason, and the next match is a new detection", async () => {
    const [d] = (await app.get("/api/v1/detections?host=worker-prod-04&q=shell")).detections;
    expect((await app.send("PUT", `/api/v1/detections/${d.id}`, { status: "false-positive" })).status).toBe(422);
    const res = await app.send("PUT", `/api/v1/detections/${d.id}`, { status: "false-positive", reason: "Our debug image" });
    expect(await res.json()).toMatchObject({ status: "false-positive", reason: "Our debug image", updatedBy: "admin token" });
    expect((await app.get("/api/v1/detections?status=active&host=worker-prod-04")).detections.map((x: { rule: string }) => x.rule)).toEqual([
      "Read sensitive file untrusted",
    ]);
    const agent = app.agents.hosts().find((h) => h.name === "worker-prod-04")!;
    expect(agent.eventsIn).toBe(3);
  });
});

describe("hosts", () => {
  it("are healthy while they report, silent when they stop, and outdated on another version", async () => {
    await app.enrol("edge-fra-02", { version: "0.0.9" });
    const hosts = (await app.get("/api/v1/hosts")).hosts as Array<{ name: string; status: string; falco: { version: string }; eventsPerHour: number[] }>;
    expect(hosts.find((h) => h.name === "edge-fra-02")!.status).toBe("outdated");
    const w = hosts.find((h) => h.name === "worker-prod-04")!;
    expect(w).toMatchObject({ status: "healthy", falco: { version: "0.41.3" } });
    expect(w.eventsPerHour.reduce((a, b) => a + b, 0)).toBe(3);
    app.later(3 * 60_000);
    expect((await app.get("/api/v1/hosts")).hosts.every((h: { status: string }) => h.status === "silent")).toBe(true);
    app.later(-3 * 60_000);
  });

  it("end their secret when removed", async () => {
    const agent = await app.enrol("temp-1");
    expect((await app.send("DELETE", `/api/v1/hosts/${agent.hostId}`)).status).toBe(204);
    expect((await agent.events([])).status).toBe(401);
  });
});

describe("the product", () => {
  it("names itself, sums up and has metrics for Prometheus", async () => {
    expect(await (await fetch(`${app.base}/api/v1/version`)).json()).toEqual({ product: "runtime", version: "0.1.0" });
    const s = await app.get("/api/v1/summary");
    expect(s.detections.active).toBe(2);
    expect(s.events.perHour).toHaveLength(24);
    expect(s.hosts.total).toBeGreaterThan(2);
    expect(s.siem).toEqual({ configured: false });
    const metrics = await (await fetch(`${app.base}/metrics`)).text();
    expect(metrics).toContain('openasy_build_info{product="runtime",version="0.1.0"} 1');
    expect(metrics).toContain('openasy_runtime_detections_active{severity="high"} 2');
    expect(metrics).toContain('openasy_runtime_hosts{status="outdated"} 1');
  });
});
