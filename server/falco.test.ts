import { describe, expect, it } from "vitest";
import { chainOf, containerOf, fileOf, kindOf, mergeTree, parseFalco, severityOf, MAX_TREE_NODES, type ProcNode } from "./falco.ts";
import { shell, T0 } from "./test-app.ts";

describe("Falco's alerts", () => {
  it("are read as json_output writes them, with nanoseconds and Falco's priority names", () => {
    const e = parseFalco(shell(), T0);
    expect(e).toMatchObject({ time: "2026-10-28T12:58:12.418Z", rule: "Terminal shell in container", priority: "notice", source: "syscall" });
    expect(e.fields["proc.cmdline"]).toBe("sh -c id; uname -a");
    expect(containerOf(e.fields)).toEqual({
      id: "6f9c7d0a1b2c",
      name: "orders-api",
      image: "registry.example.com/orders-api:2.14.1",
      namespace: "orders",
      pod: "orders-api-6f9c7d",
    });
  });

  it("are refused when they are not what Falco writes, and say why", () => {
    expect(() => parseFalco([], T0)).toThrow(/JSON object/);
    expect(() => parseFalco(shell({ rule: "" }), T0)).toThrow(/rule/);
    expect(() => parseFalco(shell({ priority: "Urgent" }), T0)).toThrow(/priority/);
    expect(() => parseFalco(shell({ time: "yesterday" }), T0)).toThrow(/RFC 3339/);
    expect(() => parseFalco(shell({ time: "2026-10-29T13:00:00Z" }), T0)).toThrow(/ahead/);
    expect(() => parseFalco(shell({ tags: "shell" }), T0)).toThrow(/tags/);
    expect(() => parseFalco(shell({}, { "proc.env": { PATH: "/bin" } }), T0)).toThrow(/text, a number/);
    expect(() => parseFalco(shell({}, { "bad key": 1 }), T0)).toThrow(/Falco field/);
  });

  it("cut long values instead of keeping them whole", () => {
    const e = parseFalco(shell({}, { "proc.cmdline": "x".repeat(10_000) }), T0);
    expect((e.fields["proc.cmdline"] as string).length).toBe(4096);
  });

  it("have a severity from Falco's priority", () => {
    expect(["emergency", "critical", "error", "warning", "notice", "informational", "debug"].map((p) => severityOf(p as never))).toEqual([
      "critical",
      "critical",
      "high",
      "high",
      "medium",
      "low",
      "info",
    ]);
  });

  it("are sorted into exec, network, file and kernel", () => {
    expect(kindOf({ tags: ["shell"], fields: { "evt.type": "execve" } })).toBe("exec");
    expect(kindOf({ tags: [], fields: { "fd.rip": "198.51.100.201", "fd.rport": 4444 } })).toBe("network");
    expect(kindOf({ tags: ["filesystem"], fields: { "fd.name": "/etc/passwd" } })).toBe("file");
    expect(kindOf({ tags: [], fields: { "evt.type": "finit_module" } })).toBe("kernel");
    expect(kindOf({ tags: [], fields: {} })).toBe("other");
  });

  it("name the file of an open, a rename or an unlink, but not of a socket", () => {
    expect(fileOf({ "fd.typechar": "f", "fd.name": "/etc/shadow" })).toBe("/etc/shadow");
    expect(fileOf({ "fs.path.target": "/etc/passwd", "fd.name": "/etc/passwd+" })).toBe("/etc/passwd");
    expect(fileOf({ "fd.typechar": "4", "fd.name": "10.0.0.1:443->10.0.0.2:5555" })).toBeNull();
  });

  it("treat the host as no container", () => {
    expect(containerOf({ "container.id": "host", "container.name": "host" })).toBeNull();
  });
});

describe("the process tree", () => {
  const node = (n: ProcNode): unknown => [n.pid, n.cmd, n.flagged, n.children.map(node)];

  it("is a chain from the oldest ancestor Falco names to the process the rule matched", () => {
    const chain = chainOf(parseFalco(shell(), T0).fields);
    expect(chain.map((n) => [n.pid, n.cmd, n.user, n.flagged])).toEqual([
      [4120, "containerd-shim", null, false],
      [4188, "node /app/server.js", null, false],
      [30551, "sh -c id; uname -a", "app", true],
    ]);
  });

  it("joins the chains of later events by pid, so a shell and what it ran are parent and child", () => {
    const first = chainOf(parseFalco(shell(), T0).fields);
    const second = chainOf(
      parseFalco(
        shell(
          {},
          { "proc.pid": 30552, "proc.cmdline": "id", "proc.ppid": 30551, "proc.pcmdline": "sh -c id; uname -a", "proc.aname[2]": "node", "proc.apid[2]": 4188 },
        ),
        T0,
      ).fields,
    );
    const tree = mergeTree(mergeTree([], first), second);
    expect(tree.map(node)).toEqual([
      [4120, "containerd-shim", false, [[4188, "node /app/server.js", false, [[30551, "sh -c id; uname -a", true, [[30552, "id", true, []]]]]]]],
    ]);
  });

  it("puts a chain from another root beside the first, and stops growing at its limit", () => {
    const a = chainOf({ "proc.pid": 1, "proc.cmdline": "a" });
    const b = chainOf({ "proc.pid": 2, "proc.cmdline": "b" });
    expect(mergeTree(mergeTree([], a), b)).toHaveLength(2);
    let tree: ProcNode[] = [];
    for (let i = 0; i < 100; i++) tree = mergeTree(tree, chainOf({ "proc.pid": 1000 + i, "proc.cmdline": `p${i}` }));
    expect(tree).toHaveLength(MAX_TREE_NODES);
  });
});
