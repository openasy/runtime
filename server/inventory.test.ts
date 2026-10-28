import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { startApp } from "./test-app.ts";

let app: Awaited<ReturnType<typeof startApp>>;
const DAY = 86_400_000;

beforeAll(async () => {
  app = await startApp({ version: "0.1.0", learningDays: 7 });
});
afterAll(() => app.close());

/** A counted program start, as runtime-agent sends it from Falco's "OpenAsy process started". */
const start = (exe: string, parent: string, fields: Record<string, unknown> = {}, count = 1) => ({
  count,
  firstAt: new Date(Date.parse("2026-10-28T12:00:00Z")).toISOString(),
  lastAt: new Date(Date.parse("2026-10-28T12:30:00Z")).toISOString(),
  fields: {
    "proc.exepath": exe,
    "proc.name": exe.split("/").pop(),
    "proc.cmdline": `${exe.split("/").pop()} --serve`,
    "proc.pid": 2264,
    "proc.ppid": 2210,
    "proc.pname": parent,
    "user.name": "app",
    "container.id": "28831aaabbbb",
    "container.name": "reports-cron",
    "container.image.repository": "registry.example.com/reports",
    "container.image.tag": "1.4.0",
    "k8s.ns.name": "reports",
    ...fields,
  },
});

describe("the process inventory", () => {
  it("learns what a host runs in its first days, counting starts instead of keeping each", async () => {
    const agent = await app.enrol("worker-prod-09");
    const res = await agent.events([], [start("/usr/bin/python3", "sh", {}, 40), start("/bin/sh", "containerd-shim")]);
    expect(await res.json()).toMatchObject({ processes: { taken: 2, refused: [] } });
    await agent.events([], [start("/usr/bin/python3", "sh", { "proc.cmdline": "python3 -m reports", "proc.pid": 3000 }, 2)]);
    const list = (await app.get("/api/v1/processes?host=worker-prod-09")).processes;
    expect(list).toHaveLength(2);
    expect(list.find((p: { exe: string }) => p.exe === "/usr/bin/python3")).toMatchObject({
      baseline: "known",
      count: 42,
      image: "registry.example.com/reports",
      container: "reports-cron",
      parent: "sh",
      user: "app",
    });
    expect((await app.get("/api/v1/detections")).detections).toEqual([]);
  });

  it("after learning, names new programs and drift, and raises a detection for a new one in a container", async () => {
    const agent = await app.enrol("worker-prod-10");
    await agent.events([], [start("/tmp/.x/kworker", "curl")]);
    expect((await app.get("/api/v1/processes?host=worker-prod-10")).processes[0].baseline).toBe("known");
    app.later(8 * DAY);
    await agent.events(
      [],
      [
        start("/tmp/.x/kworker2", "curl", { "proc.cmdline": "/tmp/.x/kworker2 -o 198.51.100.201:3333", "proc.aname[2]": "sh", "proc.apid[2]": 2264 }),
        start("/tmp/.x/kworker", "bash"),
      ],
    );
    const unusual = (await app.get("/api/v1/processes?host=worker-prod-10&baseline=unusual")).processes;
    expect(unusual.map((p: { exe: string; baseline: string }) => [p.exe, p.baseline]).sort()).toEqual([
      ["/tmp/.x/kworker", "drift"],
      ["/tmp/.x/kworker2", "new"],
    ]);
    const [d] = (await app.get("/api/v1/detections")).detections;
    expect(d).toMatchObject({
      rule: "New process in container",
      severity: "medium",
      host: { name: "worker-prod-10" },
      process: "/tmp/.x/kworker2 -o 198.51.100.201:3333",
    });
    const tree = (await app.get(`/api/v1/detections/${d.id}`)).tree;
    expect(tree[0]).toMatchObject({ pid: 2264, cmd: "sh", children: [{ pid: 2210, cmd: "curl", children: [{ flagged: true }] }] });
    expect((await app.get("/api/v1/policies")).policies.find((p: { rule: string }) => p.rule === "New process in container")).toMatchObject({
      source: "runtime",
    });
  });

  it("learns a new image, and a new version of a known one, as it learns a host", async () => {
    const agent = await app.enrol("worker-prod-12");
    app.later(8 * DAY);
    const now = new Date(app.later(0)).toISOString();
    const at = (s: ReturnType<typeof start>) => ({ ...s, firstAt: now, lastAt: now });
    await agent.events([], [at(start("/usr/bin/redis-server", "containerd-shim", { "container.image.repository": "redis", "container.image.tag": "7" }))]);
    // The next version is the same workload: the same row, still known.
    await agent.events([], [at(start("/usr/bin/redis-server", "containerd-shim", { "container.image.repository": "redis", "container.image.tag": "8" }))]);
    const list = (await app.get("/api/v1/processes?host=worker-prod-12")).processes;
    expect(list.map((p: { image: string; baseline: string; count: number }) => [p.image, p.baseline, p.count])).toEqual([["redis", "known", 2]]);
    expect((await app.get("/api/v1/detections?host=worker-prod-12")).detections).toEqual([]);
  });

  it("accepts a new program as known, and only that way", async () => {
    const [p] = (await app.get("/api/v1/processes?baseline=new")).processes;
    expect((await app.send("PUT", `/api/v1/processes/${p.id}`, { baseline: "new" })).status).toBe(422);
    expect(await (await app.send("PUT", `/api/v1/processes/${p.id}`, { baseline: "known" })).json()).toMatchObject({ baseline: "known" });
    expect((await app.send("PUT", "/api/v1/processes/missing", { baseline: "known" })).status).toBe(404);
    expect((await app.send("GET", "/api/v1/processes?baseline=odd")).status).toBe(422);
  });

  it("leaves out starts that are not what the agent sends", async () => {
    const agent = await app.enrol("worker-prod-11");
    const res = await agent.events([], [{ fields: {} }, { count: 0, fields: { "proc.name": "x" }, lastAt: "2026-10-28T12:00:00Z" }, start("/bin/ls", "sh")]);
    const r = (await res.json()) as { processes: { taken: number; refused: Array<{ index: number }> } };
    expect(r.processes.taken).toBe(1);
    expect(r.processes.refused.map((x) => x.index)).toEqual([0, 1]);
  });
});
