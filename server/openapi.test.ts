import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Ajv2020 } from "ajv/dist/2020.js";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ADMIN_TOKEN, report, shell, startApp } from "./test-app.ts";

// Contract tests (ADR 0014): every response the API sends must match openapi.json.

type Spec = {
  info: { version: string };
  paths: Record<string, Record<string, { responses: Record<string, { $ref?: string; content?: Record<string, { schema: object }> }> }>>;
  components: { responses: Record<string, { content: Record<string, { schema: object }> }> };
};

const spec = JSON.parse(readFileSync(new URL("../openapi.json", import.meta.url), "utf8")) as Spec;
const { version } = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string };

const ajv = new Ajv2020({ strict: false, validateFormats: false });
ajv.addSchema(spec, "openapi");

const docsDir = mkdtempSync(join(tmpdir(), "runtime-docs-"));
writeFileSync(join(docsDir, "index.html"), "<!doctype html><title>API</title>");

let app: Awaited<ReturnType<typeof startApp>>;
let base: string;
const covered = new Set<string>();

beforeAll(async () => {
  app = await startApp({ version, openapi: spec, docsDir });
  base = app.base;
});

afterAll(() => app.close());

/** Calls the API and checks status, content type and body against the description. */
async function call(method: string, path: string, init: RequestInit = {}, concrete = path) {
  const res = await fetch(base + concrete, { ...init, method });
  const operation = spec.paths[path]?.[method.toLowerCase()];
  expect(operation, `${method} ${path} is not in openapi.json`).toBeDefined();
  covered.add(`${method} ${path}`);

  const declared = operation!.responses[String(res.status)];
  expect(declared, `${method} ${concrete} answered ${res.status}, which openapi.json does not list`).toBeDefined();
  // A response is either inline or a $ref to components/responses; build the JSON pointer to its schema either way.
  const shared = declared!.$ref?.split("/").pop();
  const response = shared ? spec.components.responses[shared]! : declared!;
  const at = shared
    ? `openapi#/components/responses/${shared}`
    : `openapi#/paths/${path.replaceAll("/", "~1")}/${method.toLowerCase()}/responses/${res.status}`;

  if (!response.content) {
    expect(res.headers.get("content-length") ?? "0", `${method} ${path} ${res.status} should have no body`).toBe("0");
    return { res, body: undefined };
  }
  const type = res.headers.get("content-type")!.split(";")[0]!;
  expect(response.content?.[type], `${method} ${path} ${res.status} sent ${type}, which openapi.json does not list`).toBeDefined();

  const body = type.endsWith("json") ? await res.json() : await res.text();
  const schema = `${at}/content/${type.replace("/", "~1")}/schema`;
  const validate = ajv.getSchema(schema)!;
  expect(validate, `no schema at ${schema}`).toBeDefined();
  expect(validate(body), JSON.stringify(validate.errors)).toBe(true);
  return { res, body: body as any };
}

const auth = (token: string, body?: unknown) => ({
  headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
  ...(body !== undefined && { body: typeof body === "string" ? body : JSON.stringify(body) }),
});
const admin = (body?: unknown) => auth(ADMIN_TOKEN, body);
const anyone = (body?: unknown) => ({ headers: { "content-type": "application/json" }, ...(body !== undefined && { body: JSON.stringify(body) }) });

describe("openapi.json", () => {
  it("has the version of this release", () => {
    expect(spec.info.version).toBe(version);
  });

  it("is served with the running version", async () => {
    const served = (await (await fetch(`${base}/api/openapi.json`)).json()) as Spec;
    expect(served.info.version).toBe(version);
    // Runtime's own operations, then sign-in from @openasy/auth (tested against its description in that package).
    expect(Object.keys(served.paths).filter((p) => !p.startsWith("/api/v1/auth/"))).toEqual(Object.keys(spec.paths));
    expect(served.paths["/api/v1/auth/login"]).toBeDefined();
  });

  it("serves the API reference at /api/docs/", async () => {
    expect((await fetch(`${base}/api/docs`, { redirect: "manual" })).headers.get("location")).toBe("/api/docs/");
    const res = await fetch(`${base}/api/docs/`);
    expect(res.headers.get("content-type")).toContain("text/html");
    expect((await fetch(`${base}/api/docs/../../package.json`)).status).not.toBe(200);
  });
});

describe("responses match openapi.json", () => {
  let secret = "";
  let tokenId = "";
  let hostId = "";
  const agent = (body: unknown) => auth(secret, body);

  it("product and health", async () => {
    await call("GET", "/api/v1/version");
    await call("GET", "/api/v1/products", admin());
    await call("GET", "/api/v1/products", {});
    await call("GET", "/healthz");
    await call("GET", "/readyz");
    await call("GET", "/metrics");
  });

  it("enrolment tokens and enrolment", async () => {
    const t = await call("POST", "/api/v1/enrollment-tokens", admin({ name: "workers", maxUses: 2 }));
    tokenId = t.body.id;
    await call("POST", "/api/v1/enrollment-tokens", admin({ name: "x", maxUses: -1 }));
    await call("POST", "/api/v1/enrollment-tokens", admin("nope"));
    await call("POST", "/api/v1/enrollment-tokens", anyone({ name: "x" }));
    await call("GET", "/api/v1/enrollment-tokens", admin());
    await call("GET", "/api/v1/enrollment-tokens", {});

    const e = await call("POST", "/api/v1/agent/enroll", anyone({ token: t.body.token, name: "worker-prod-04", report: report() }));
    secret = e.body.secret;
    hostId = e.body.hostId;
    await call("POST", "/api/v1/agent/enroll", anyone({ token: t.body.token, name: "worker-prod-04", report: report() }));
    await call("POST", "/api/v1/agent/enroll", anyone({ token: t.body.token, name: "bad name", report: report() }));
    await call("POST", "/api/v1/agent/enroll", anyone({ token: "oie_wrong", name: "x", report: report() }));
    await call("POST", "/api/v1/agent/enroll", { method: "POST", body: "{" });
  });

  it("what agents send", async () => {
    await call(
      "POST",
      "/api/v1/agent/events",
      agent({
        report: report(),
        events: [shell(), { rule: "broken" }],
        processes: [{ count: 1, lastAt: "2026-10-28T12:00:00Z", fields: { "proc.exepath": "/bin/sh" } }],
      }),
    );
    await call("POST", "/api/v1/agent/events", agent({ report: report(), events: "nope" }));
    await call("POST", "/api/v1/agent/events", agent({ events: [] }));
    await call("POST", "/api/v1/agent/events", agent("{"));
    await call("POST", "/api/v1/agent/events", auth("oia_wrong", { report: report(), events: [] }));
    await call("POST", "/api/v1/agent/events", { method: "POST", headers: { authorization: `Bearer ${secret}`, "content-encoding": "br" }, body: "{}" });
    await call("POST", "/api/v1/agent/events", {
      headers: { authorization: `Bearer ${secret}` },
      body: JSON.stringify({ report: report(), pad: "x".repeat(17 * 1024 * 1024) }),
    });
    const file = { path: "/etc/passwd", kind: "file", sha256: "a".repeat(64), size: 1, mode: "0644", uid: 0, gid: 0, target: null };
    await call("POST", "/api/v1/agent/files", agent({ report: report(), paths: ["/etc/passwd"], files: [file], complete: true }));
    await call(
      "POST",
      "/api/v1/agent/files",
      agent({ report: report(), paths: ["/etc/passwd"], files: [{ ...file, sha256: "b".repeat(64) }], complete: true }),
    );
    await call("POST", "/api/v1/agent/files", agent({ report: report(), paths: ["/etc/passwd"], files: [{ ...file, mode: "x" }], complete: true }));
    await call("POST", "/api/v1/agent/files", agent("{"));
    await call("POST", "/api/v1/agent/files", auth("oia_wrong", {}));
    await call("POST", "/api/v1/agent/files", { method: "POST", headers: { authorization: `Bearer ${secret}`, "content-encoding": "br" }, body: "{}" });
    await call("POST", "/api/v1/agent/files", { headers: { authorization: `Bearer ${secret}` }, body: "x".repeat(17 * 1024 * 1024) });
  });

  it("detections and events", async () => {
    const list = await call("GET", "/api/v1/detections", admin());
    await call("GET", "/api/v1/detections", admin(), "/api/v1/detections?status=active&severity=medium,high&host=worker-prod-04&q=shell");
    await call("GET", "/api/v1/detections", admin(), "/api/v1/detections?severity=loud");
    await call("GET", "/api/v1/detections", {});
    const id = list.body.detections[0].id;
    const d = "/api/v1/detections/{id}";
    await call("GET", d, admin(), `/api/v1/detections/${id}`);
    await call("GET", d, admin(), "/api/v1/detections/missing");
    await call("GET", d, {}, `/api/v1/detections/${id}`);
    await call("PUT", d, admin({ status: "investigating" }), `/api/v1/detections/${id}`);
    await call("PUT", d, admin({ status: "false-positive" }), `/api/v1/detections/${id}`);
    await call("PUT", d, admin("nope"), `/api/v1/detections/${id}`);
    await call("PUT", d, admin({ status: "resolved" }), "/api/v1/detections/missing");
    await call("PUT", d, anyone({ status: "resolved" }), `/api/v1/detections/${id}`);
    await call("GET", "/api/v1/events", admin());
    await call(
      "GET",
      "/api/v1/events",
      admin(),
      `/api/v1/events?kind=exec&host=worker-prod-04&result=alerted&since=2026-10-27T00:00:00Z&q=sh&limit=1&detection=${id}`,
    );
    await call("GET", "/api/v1/events", admin(), "/api/v1/events?before=abc");
    await call("GET", "/api/v1/events", {});
  });

  it("processes, files and policies", async () => {
    const p = await call("GET", "/api/v1/processes", admin(), "/api/v1/processes?host=worker-prod-04&baseline=new&q=sh");
    await call("GET", "/api/v1/processes", admin(), "/api/v1/processes?baseline=odd");
    await call("GET", "/api/v1/processes", {});
    const pp = "/api/v1/processes/{id}";
    await call("PUT", pp, admin({ baseline: "known" }), `/api/v1/processes/${p.body.processes[0].id}`);
    await call("PUT", pp, admin({ baseline: "new" }), `/api/v1/processes/${p.body.processes[0].id}`);
    await call("PUT", pp, admin("nope"), "/api/v1/processes/missing");
    await call("PUT", pp, admin({ baseline: "known" }), "/api/v1/processes/missing");
    await call("PUT", pp, anyone({ baseline: "known" }), "/api/v1/processes/missing");

    const c = await call("GET", "/api/v1/file-changes", admin());
    await call("GET", "/api/v1/file-changes", admin(), "/api/v1/file-changes?review=odd");
    await call("GET", "/api/v1/file-changes", {});
    const fc = "/api/v1/file-changes/{id}";
    await call("PUT", fc, admin({ review: "approved", note: "Upgrade" }), `/api/v1/file-changes/${c.body.changes[0].id}`);
    await call("PUT", fc, admin({ review: "fine" }), `/api/v1/file-changes/${c.body.changes[0].id}`);
    await call("PUT", fc, admin("nope"), "/api/v1/file-changes/missing");
    await call("PUT", fc, admin({ review: "approved" }), "/api/v1/file-changes/missing");
    await call("PUT", fc, anyone({ review: "approved" }), "/api/v1/file-changes/missing");

    await call("GET", "/api/v1/policies", admin());
    await call("GET", "/api/v1/policies", {});
    const pol = "/api/v1/policies/{rule}";
    const rule = encodeURIComponent("Terminal shell in container");
    await call("PUT", pol, admin({ mode: "off", severity: "high" }), `/api/v1/policies/${rule}`);
    await call("PUT", pol, admin({ severity: null }), `/api/v1/policies/${rule}`);
    await call("PUT", pol, admin({ mode: "loud" }), `/api/v1/policies/${rule}`);
    await call("PUT", pol, admin("nope"), `/api/v1/policies/${rule}`);
    await call("PUT", pol, admin({ mode: "off" }), "/api/v1/policies/Missing");
    await call("PUT", pol, anyone({ mode: "off" }), `/api/v1/policies/${rule}`);
    await call("GET", "/api/v1/summary", admin());
    await call("GET", "/api/v1/summary", {});
  });

  it("hosts", async () => {
    await call("GET", "/api/v1/hosts", admin());
    await call("GET", "/api/v1/hosts", {});
    const h = "/api/v1/hosts/{id}";
    await call("DELETE", h, anyone(), `/api/v1/hosts/${hostId}`);
    await call("DELETE", h, admin(), `/api/v1/hosts/${hostId}`);
    await call("DELETE", h, admin(), "/api/v1/hosts/missing");
    const t = "/api/v1/enrollment-tokens/{id}";
    await call("DELETE", t, anyone(), `/api/v1/enrollment-tokens/${tokenId}`);
    await call("DELETE", t, admin(), `/api/v1/enrollment-tokens/${tokenId}`);
    await call("DELETE", t, admin(), "/api/v1/enrollment-tokens/missing");
  });

  it("covers every operation in openapi.json", () => {
    const all = Object.entries(spec.paths).flatMap(([path, ops]) => Object.keys(ops).map((m) => `${m.toUpperCase()} ${path}`));
    expect([...covered].sort()).toEqual(all.sort());
  });
});
