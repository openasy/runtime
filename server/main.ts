import { existsSync, readFileSync } from "node:fs";
import { createServer } from "node:http";
import { createAuth, oidcFromEnv, readSecretsKey } from "@openasy/auth";
import { createAgents } from "./agents.ts";
import { createApp, createMetricsHandler } from "./app.ts";
import { openDb } from "./db.ts";
import { createIntegrity } from "./integrity.ts";
import { createInventory } from "./inventory.ts";
import { log } from "./log.ts";
import { parseProducts } from "./products.ts";
import { createRuntime } from "./runtime.ts";
import { createSiemLink } from "./siem.ts";

const { version } = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string };
const port = Number(process.env.PORT ?? 8080);
const dbPath = process.env.RUNTIME_DB ?? "/data/runtime.db";
const webDir = new URL("../dist/web", import.meta.url).pathname;
const docsDir = new URL("../dist/docs", import.meta.url).pathname;
const openapi = JSON.parse(readFileSync(new URL("../openapi.json", import.meta.url), "utf8")) as Record<string, unknown>;
const headless = process.env.RUNTIME_HEADLESS === "true";
// Set it to keep /metrics off the port that is published or behind an ingress (ADR 0026).
const metricsPort = process.env.RUNTIME_METRICS_PORT ? Number(process.env.RUNTIME_METRICS_PORT) : undefined;
const days = (name: string, fallback: number, max: number) => {
  const v = Number(process.env[name] ?? fallback);
  if (!Number.isInteger(v) || v < 0 || v > max) throw new Error(`${name} must be a whole number of days, 0 to ${max}`);
  return v;
};
const retentionDays = Math.max(1, days("RUNTIME_RETENTION_DAYS", 30, 3650));
const learningDays = days("RUNTIME_LEARNING_DAYS", 7, 365);

const db = openDb(dbPath);
// The address people open Runtime at, behind the TLS proxy (ADR 0026). Cookies, passkeys, OIDC redirects and the
// links in what goes to SIEM use it.
const publicUrl = (process.env.RUNTIME_PUBLIC_URL ?? `http://localhost:${port}`).replace(/\/$/, "");
const secretsKeyFile = process.env.RUNTIME_SECRETS_KEY_FILE ?? "/run/secrets/openasy-kek";
const secretsKey = readSecretsKey(secretsKeyFile);
const auth = createAuth({
  db,
  product: "runtime",
  productName: "OpenAsy Runtime",
  origin: publicUrl,
  // Locally the same Runtime is often opened as 127.0.0.1 too.
  trustedOrigins: publicUrl.startsWith("http://localhost:") ? [publicUrl.replace("localhost", "127.0.0.1")] : [],
  passwords: process.env.RUNTIME_PASSWORD_SIGN_IN !== "false",
  oidc: oidcFromEnv(process.env, "RUNTIME_"),
  secretsKey,
  // Audit log (ADR 0013): every sign-in, failure and change to members and tokens.
  onEvent: (event) => log(event.type === "sign-in-failed" ? "warn" : "info", "auth", { event }),
});
const products = parseProducts(process.env.OPENASY_PRODUCTS);
if (products.invalid.length) log("warn", "OPENASY_PRODUCTS: left out entries that are not id=https://address", { entries: products.invalid });

const clock = Date.now;
const siem =
  process.env.RUNTIME_SIEM_URL && process.env.RUNTIME_SIEM_TOKEN
    ? createSiemLink(db, { url: process.env.RUNTIME_SIEM_URL, token: process.env.RUNTIME_SIEM_TOKEN, publicUrl, clock })
    : undefined;
if (process.env.RUNTIME_SIEM_URL && !siem) log("warn", "RUNTIME_SIEM_URL is set without RUNTIME_SIEM_TOKEN: nothing is sent to SIEM");
const runtime = createRuntime(db, { clock, retentionDays, onDetection: siem && ((d, e) => siem.add(siem.detection(d, e))) });
const agents = createAgents(db, { version, learningDays, clock });
const inventory = createInventory(db, runtime, { clock, learningDays });
const integrity = createIntegrity(db, runtime, { clock, onChange: siem && ((c) => siem.add(siem.fileChange(c))) });

const server = createServer(
  createApp({
    db,
    runtime,
    agents,
    inventory,
    integrity,
    siem,
    version,
    auth,
    webDir: !headless && existsSync(webDir) ? webDir : undefined,
    docsDir: existsSync(docsDir) ? docsDir : undefined,
    openapi,
    serveMetrics: metricsPort === undefined,
    products: products.products,
  }),
);
const metricsServer = metricsPort !== undefined ? createServer(createMetricsHandler({ runtime, agents, siem }, version)) : undefined;
metricsServer?.listen(metricsPort, () => log("info", "metrics on their own port", { port: metricsPort }));

server.listen(port, () => log("info", "runtime started", { version, port, db: dbPath, headless, retentionDays, learningDays, siem: !!siem }));
if (!publicUrl.startsWith("https://") && !/^http:\/\/(localhost|127\.0\.0\.1)(:|$)/.test(publicUrl)) {
  log("warn", "RUNTIME_PUBLIC_URL is not https: browsers will not keep secure cookies or allow passkeys. Put runtime behind TLS (ADR 0026)", {
    url: publicUrl,
  });
}
if (!secretsKey)
  log("warn", "no secrets key: TOTP secrets are stored unencrypted. Mount a 32-byte key (openssl rand -hex 32)", {
    file: secretsKeyFile,
  });
const setup = auth.setupLink();
// No default password (ADR 0013): the first person to open this link becomes the owner.
if (setup) log("info", "no owner yet: open this link once to create the owner account", { url: setup });

// One send to SIEM at a time, so a slow SIEM never gets the same events twice.
let sending = false;
const send = () => {
  if (!siem || sending) return;
  sending = true;
  void siem
    .flush()
    .catch((err: unknown) => log("error", "siem link", { error: String(err) }))
    .finally(() => (sending = false));
};
runtime.purge();
const timers: NodeJS.Timeout[] = [setInterval(() => auth.purge(), 5 * 60_000), setInterval(() => runtime.purge(), 3_600_000), setInterval(send, 5_000)];

function shutdown(signal: string) {
  log("info", "shutting down", { signal });
  for (const t of timers) clearInterval(t);
  metricsServer?.close();
  server.close(() => {
    db.close();
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 10_000).unref();
}
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
