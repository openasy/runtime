import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { shell, startApp } from "./test-app.ts";

let app: Awaited<ReturnType<typeof startApp>>;
let agent: Awaited<ReturnType<typeof app.enrol>>;

const file = (path: string, sha: string, over: Record<string, unknown> = {}) => ({
  path,
  kind: "file",
  sha256: sha.repeat(64).slice(0, 64),
  size: 2048,
  mode: "0644",
  uid: 0,
  gid: 0,
  target: null,
  ...over,
});

beforeAll(async () => {
  app = await startApp({ version: "0.1.0" });
  agent = await app.enrol("db-prod-02");
});
afterAll(() => app.close());

describe("file integrity", () => {
  it("takes a host's first read as its baseline", async () => {
    const res = await agent.files([file("/etc/passwd", "a"), file("/etc/ssh/sshd_config", "b")]);
    expect(await res.json()).toEqual({ files: 2, changes: 0, baseline: true });
    const [h] = (await app.get("/api/v1/hosts")).hosts;
    expect(h.fim).toMatchObject({ paths: ["/etc/passwd", "/etc/ssh"], files: 2, scannedAt: expect.any(String) });
  });

  it("records what changed since, with the process Falco saw writing it", async () => {
    app.later(5 * 60_000);
    await agent.events([
      shell(
        { rule: "Write below etc", priority: "Error", tags: ["filesystem"], time: "2026-10-28T13:03:00Z" },
        { "fd.name": "/etc/passwd", "fd.typechar": "f", "proc.cmdline": "useradd -o -u 0 backup2", "user.name": "root", "container.id": "host" },
      ),
    ]);
    const res = await agent.files([file("/etc/passwd", "c"), file("/etc/ssh/sshd_config", "b", { mode: "0666" }), file("/etc/ssh/authorized_keys", "d")]);
    expect(await res.json()).toMatchObject({ changes: 3, baseline: false });
    const changes = (await app.get("/api/v1/file-changes")).changes as Array<{ path: string; change: string; by: string | null; before: any; after: any }>;
    const byPath = Object.fromEntries(changes.map((c) => [c.path, c]));
    expect(byPath["/etc/passwd"]).toMatchObject({ change: "modified", by: "useradd -o -u 0 backup2 (root)" });
    expect(byPath["/etc/passwd"]!.before.sha256).toMatch(/^a+$/);
    expect(byPath["/etc/ssh/sshd_config"]).toMatchObject({ change: "permissions", by: null, before: { mode: "0644" }, after: { mode: "0666" } });
    expect(byPath["/etc/ssh/authorized_keys"]).toMatchObject({ change: "created", before: null });
  });

  it("takes a file gone from a complete read as deleted, but not from one cut short", async () => {
    await agent.files([file("/etc/passwd", "c")], undefined, false);
    expect((await app.get("/api/v1/file-changes")).changes).toHaveLength(3);
    await agent.files([file("/etc/passwd", "c"), file("/etc/ssh/authorized_keys", "d")]);
    const deleted = (await app.get("/api/v1/file-changes")).changes.filter((c: { change: string }) => c.change === "deleted");
    expect(deleted.map((c: { path: string }) => c.path)).toEqual(["/etc/ssh/sshd_config"]);
  });

  it("learns a path watched only now, and forgets one no longer watched, without changes", async () => {
    const res = await agent.files(
      [file("/etc/passwd", "c"), file("/etc/ssh/authorized_keys", "d"), file("/etc/sudoers", "e")],
      ["/etc/passwd", "/etc/ssh", "/etc/sudoers"],
    );
    expect(await res.json()).toMatchObject({ changes: 0 });
    expect(await (await agent.files([file("/etc/sudoers", "e")], ["/etc/sudoers"])).json()).toMatchObject({ changes: 0, files: 1 });
  });

  it("is reviewed: approved, suspicious, or back to unreviewed", async () => {
    const [c] = (await app.get("/api/v1/file-changes?review=unreviewed")).changes;
    expect(await (await app.send("PUT", `/api/v1/file-changes/${c.id}`, { review: "approved", note: "CHG-2291" })).json()).toMatchObject({
      review: "approved",
      note: "CHG-2291",
      reviewedBy: "admin token",
    });
    expect((await app.send("PUT", `/api/v1/file-changes/${c.id}`, { review: "fine" })).status).toBe(422);
    expect((await app.send("PUT", "/api/v1/file-changes/missing", { review: "approved" })).status).toBe(404);
    expect((await app.get("/api/v1/summary")).files).toMatchObject({ changesLastDay: 4, unreviewed: 3 });
  });

  it("refuses reads that are not what the agent sends", async () => {
    expect((await agent.files([file("etc/passwd", "a")])).status).toBe(422);
    expect((await agent.files([file("/etc/passwd", "z")])).status).toBe(422);
    expect((await agent.files([file("/etc/passwd", "a", { mode: "rwx" })])).status).toBe(422);
  });
});
