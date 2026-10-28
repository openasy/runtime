import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { openDb } from "./db.ts";

describe("openDb", () => {
  it("uses WAL and migrates once", () => {
    const path = join(mkdtempSync(join(tmpdir(), "runtime-")), "nested", "runtime.db");
    const first = openDb(path);
    expect(first.prepare("PRAGMA journal_mode").get()).toEqual({ journal_mode: "wal" });
    first.close();
    const second = openDb(path);
    expect(second.prepare("SELECT COUNT(*) AS n FROM schema_migrations").get()).toEqual({ n: 1 });
    second.close();
  });

  it("keeps two hosts from sharing a name or a secret", () => {
    const db = openDb(":memory:");
    const insert = (id: string, name: string, secret: string) =>
      db
        .prepare("INSERT INTO hosts (id, name, secret_hash, version, enrolled_at, last_seen_at, learning_until) VALUES (?, ?, ?, '0.1.0', '', '', '')")
        .run(id, name, secret);
    insert("a", "node-a", "h1");
    expect(() => insert("b", "node-a", "h2")).toThrow(/UNIQUE/);
    expect(() => insert("c", "node-c", "h1")).toThrow(/UNIQUE/);
  });
});
