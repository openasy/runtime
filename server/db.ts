import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { DatabaseSync } from "node:sqlite";

// Forward-only migrations (ADR 0010): append new entries, never edit or remove old ones.
const MIGRATIONS = [
  `-- What an admin hands to hosts so their agents can enrol: for one host, or for a fleet such as a DaemonSet, up to
   -- max_uses hosts until it expires. Only the token's hash is kept (ADR 0066).
   CREATE TABLE enrollment_tokens (
     id TEXT PRIMARY KEY,
     name TEXT NOT NULL,
     token_hash TEXT NOT NULL UNIQUE,
     max_uses INTEGER NOT NULL CHECK (max_uses > 0),
     uses INTEGER NOT NULL DEFAULT 0,
     expires_at TEXT NOT NULL,
     created_by TEXT NOT NULL,
     created_at TEXT NOT NULL
   );
   -- A host with Falco and runtime-agent on it. The agent's secret is kept as its hash only; it speaks for this host
   -- and no other.
   CREATE TABLE hosts (
     id TEXT PRIMARY KEY,
     name TEXT NOT NULL UNIQUE,
     secret_hash TEXT NOT NULL UNIQUE,
     token_id TEXT,
     version TEXT NOT NULL,
     os TEXT,
     kernel TEXT,
     arch TEXT,
     falco_status TEXT NOT NULL DEFAULT 'unknown' CHECK (falco_status IN ('ok', 'down', 'unknown')),
     falco_version TEXT,
     falco_detail TEXT,
     -- What the agent watches for file integrity, as it reported last.
     fim_paths TEXT NOT NULL DEFAULT '[]',
     fim_scanned_at TEXT,
     events_in INTEGER NOT NULL DEFAULT 0,
     -- Events the agent could not hold while Runtime was out of reach, as it reported last.
     dropped INTEGER NOT NULL DEFAULT 0,
     last_event_at TEXT,
     enrolled_at TEXT NOT NULL,
     last_seen_at TEXT NOT NULL,
     -- Until then, every process seen on the host is learned as normal for it.
     learning_until TEXT NOT NULL
   );
   -- Every Falco rule seen, and the policy for it: alert raises detections, off keeps the events and raises none.
   CREATE TABLE rules (
     rule TEXT PRIMARY KEY,
     source TEXT NOT NULL,
     priority TEXT NOT NULL,
     tags TEXT NOT NULL DEFAULT '[]',
     mode TEXT NOT NULL DEFAULT 'alert' CHECK (mode IN ('alert', 'off')),
     severity TEXT CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
     first_seen_at TEXT NOT NULL,
     last_seen_at TEXT NOT NULL,
     updated_by TEXT,
     updated_at TEXT
   );
   -- One rule matching one process on one host or container, for as long as it is open: its events, counted, and
   -- the process tree they show.
   CREATE TABLE detections (
     id TEXT PRIMARY KEY,
     key TEXT NOT NULL,
     rule TEXT NOT NULL,
     host_id TEXT NOT NULL,
     host TEXT NOT NULL,
     severity TEXT NOT NULL,
     container_id TEXT,
     container_name TEXT,
     image TEXT,
     namespace TEXT,
     pod TEXT,
     process TEXT,
     user_name TEXT,
     output TEXT NOT NULL,
     tags TEXT NOT NULL,
     tree TEXT NOT NULL,
     count INTEGER NOT NULL,
     first_at TEXT NOT NULL,
     last_at TEXT NOT NULL,
     status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'investigating', 'resolved', 'false-positive')),
     reason TEXT,
     updated_by TEXT,
     updated_at TEXT
   );
   CREATE INDEX detections_key ON detections (key, status);
   CREATE INDEX detections_last ON detections (last_at);
   -- Falco's alerts, kept for the retention period. The columns are what the pages filter on; the rest is in fields.
   CREATE TABLE events (
     id INTEGER PRIMARY KEY,
     host_id TEXT NOT NULL,
     host TEXT NOT NULL,
     time TEXT NOT NULL,
     received_at TEXT NOT NULL,
     rule TEXT NOT NULL,
     priority TEXT NOT NULL,
     severity TEXT NOT NULL,
     source TEXT NOT NULL,
     kind TEXT NOT NULL,
     tags TEXT NOT NULL,
     output TEXT NOT NULL,
     fields TEXT NOT NULL,
     container_id TEXT,
     container_name TEXT,
     process TEXT,
     pid INTEGER,
     user_name TEXT,
     file TEXT,
     result TEXT NOT NULL CHECK (result IN ('alerted', 'kept')),
     detection_id TEXT
   );
   CREATE INDEX events_time ON events (time);
   CREATE INDEX events_detection ON events (detection_id);
   CREATE INDEX events_file ON events (host_id, file);
   -- What ran where: one row per program, its parent and user, on a host or in a container image, with how often.
   CREATE TABLE processes (
     id TEXT PRIMARY KEY,
     host_id TEXT NOT NULL,
     image TEXT NOT NULL DEFAULT '',
     exe TEXT NOT NULL,
     parent TEXT NOT NULL DEFAULT '',
     user_name TEXT NOT NULL DEFAULT '',
     cmdline TEXT NOT NULL,
     pid INTEGER,
     ppid INTEGER,
     container_name TEXT,
     namespace TEXT,
     count INTEGER NOT NULL,
     first_seen_at TEXT NOT NULL,
     last_seen_at TEXT NOT NULL,
     baseline TEXT NOT NULL CHECK (baseline IN ('known', 'new', 'drift')),
     UNIQUE (host_id, image, exe, parent, user_name)
   );
   CREATE INDEX processes_last ON processes (last_seen_at);
   -- The watched files of each host as the agent last read them.
   CREATE TABLE files (
     host_id TEXT NOT NULL,
     path TEXT NOT NULL,
     state TEXT NOT NULL,
     seen_at TEXT NOT NULL,
     PRIMARY KEY (host_id, path)
   );
   -- A watched file that changed between two reads, and what people decided about it.
   CREATE TABLE file_changes (
     id TEXT PRIMARY KEY,
     host_id TEXT NOT NULL,
     host TEXT NOT NULL,
     path TEXT NOT NULL,
     change TEXT NOT NULL CHECK (change IN ('created', 'modified', 'deleted', 'permissions')),
     before TEXT,
     after TEXT,
     at TEXT NOT NULL,
     by_process TEXT,
     by_event_id INTEGER,
     review TEXT NOT NULL DEFAULT 'unreviewed' CHECK (review IN ('unreviewed', 'approved', 'suspicious')),
     note TEXT,
     reviewed_by TEXT,
     reviewed_at TEXT
   );
   CREATE INDEX file_changes_at ON file_changes (at);
   -- What is waiting to go to SIEM, so that SIEM being down loses nothing (ADR 0040).
   CREATE TABLE outbox (
     id INTEGER PRIMARY KEY,
     event TEXT NOT NULL,
     attempts INTEGER NOT NULL DEFAULT 0,
     next_at TEXT NOT NULL,
     last_error TEXT
   )`,
];

/** Opens the product's single SQLite file in WAL mode (ADR 0011) and migrates it forward. */
export function openDb(path: string): DatabaseSync {
  if (path !== ":memory:") mkdirSync(dirname(path), { recursive: true });
  const db = new DatabaseSync(path);
  db.exec("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;");
  db.exec("CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)");
  const row = db.prepare("SELECT COALESCE(MAX(version), 0) AS v FROM schema_migrations").get() as { v: number };
  for (let v = row.v; v < MIGRATIONS.length; v++) {
    db.exec("BEGIN");
    try {
      db.exec(MIGRATIONS[v]!);
      db.prepare("INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)").run(v + 1, new Date().toISOString());
      db.exec("COMMIT");
    } catch (err) {
      db.exec("ROLLBACK");
      throw err;
    }
  }
  return db;
}
