import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { shell, startApp } from "./test-app.ts";

/** A stand-in for SIEM's POST /api/v1/events that keeps what it is sent, and can be made to refuse. */
async function fakeSiem() {
  const received: Array<{ auth: string | undefined; events: Array<Record<string, unknown>> }> = [];
  let status = 200;
  const server = createServer(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    if (status === 200) received.push({ auth: req.headers.authorization, events: JSON.parse(Buffer.concat(chunks).toString("utf8")) });
    res.writeHead(status, { "content-type": "application/json" }).end(JSON.stringify(status === 200 ? { taken: 1 } : { detail: "SIEM is busy" }));
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  return {
    received,
    url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
    fail: (s: number) => (status = s),
    close: () => new Promise<void>((r) => server.close(() => r())),
  };
}

let siem: Awaited<ReturnType<typeof fakeSiem>>;
let app: Awaited<ReturnType<typeof startApp>>;

beforeAll(async () => {
  siem = await fakeSiem();
  app = await startApp({ version: "0.1.0", siemUrl: siem.url });
});
afterAll(async () => {
  await app.close();
  await siem.close();
});

describe("detections on to SIEM", () => {
  it("go as flat events with SIEM's ingest token and a link back, once per detection", async () => {
    const agent = await app.enrol("worker-prod-04");
    await agent.events([shell(), shell({}, { "proc.pid": 30560 })]);
    await new Promise((r) => setTimeout(r, 0));
    expect(await app.siem!.flush()).toBe(1);
    const [call] = siem.received;
    expect(call!.auth).toBe("Bearer siem-token");
    const [e] = call!.events;
    expect(e).toMatchObject({
      host: "worker-prod-04",
      source: "runtime",
      rule: "Terminal shell in container",
      severity: "medium",
      "container.image": "registry.example.com/orders-api:2.14.1",
      "proc.cmdline": "sh -c id; uname -a",
      "mitre.technique": "T1059",
      "detection.url": expect.stringMatching(/^https:\/\/runtime\.example\.com\/detections\//),
    });
    expect(Object.values(e!).every((v) => v !== null && typeof v !== "object")).toBe(true);
  });

  it("wait in the outbox while SIEM refuses, and go when it takes them again", async () => {
    siem.fail(503);
    const agent = await app.enrol("db-prod-02");
    await agent.files([{ path: "/etc/passwd", kind: "file", sha256: "a".repeat(64), size: 1, mode: "0644", uid: 0, gid: 0, target: null }]);
    await agent.files([{ path: "/etc/passwd", kind: "file", sha256: "b".repeat(64), size: 1, mode: "0644", uid: 0, gid: 0, target: null }]);
    expect(await app.siem!.flush()).toBe(0);
    expect(app.siem!.status()).toMatchObject({ pending: 1, lastError: "SIEM answered 503: SIEM is busy" });
    expect((await app.get("/api/v1/summary")).siem).toMatchObject({ configured: true, pending: 1 });
    siem.fail(200);
    // Not before its time has come: a minute after the first refusal.
    expect(await app.siem!.flush()).toBe(0);
    app.later(61_000);
    expect(await app.siem!.flush()).toBe(1);
    expect(siem.received.at(-1)!.events[0]).toMatchObject({ rule: "File integrity change", "fim.change": "modified", "fim.path": "/etc/passwd" });
    expect(app.siem!.status()).toMatchObject({ pending: 0, lastError: null });
  });
});
