# runtime

[![CI](https://github.com/openasy/runtime/actions/workflows/ci.yml/badge.svg)](https://github.com/openasy/runtime/actions/workflows/ci.yml)
[![Node.js 26 LTS](https://img.shields.io/badge/node-26%20LTS-339933?logo=nodedotjs&logoColor=white)](./.nvmrc)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue)](./LICENSE)

The [OpenAsy](https://github.com/openasy) Runtime product: **what processes actually do on your hosts and pods, as it
happens** (ADR 0066). [Falco](https://falco.org/) watches each Linux host and Kubernetes node with eBPF and matches
its rules; [runtime-agent](https://github.com/openasy/runtime-agent), next to it, sends what Falco sees and reads the
files that should never change. Runtime keeps it as detections with their process tree, the programs that ran where,
and changes to watched files, and sends new detections on to SIEM.

```
host or node ─────────────────────────────────────┐
  Falco (eBPF, its rules) ──http_output──▶ runtime-agent ──https──▶ runtime ──▶ detections, process tree
  /etc/passwd, /usr/bin… ◀──read-only── runtime-agent                  │     ──▶ programs, file changes
                                                                       └──────▶ SIEM (optional)
```

Runtime has no sensor and no rule engine of its own. Falco's eBPF probe and its rules are maintained and reviewed by
many; reimplementing kernel instrumentation would be worse and slower to trust.

## Detections

Every alert Falco sends is kept as an **event** for the retention period (30 days). Each Falco rule has a
**policy**, and every rule starts in alert mode:

- **Alert:** the event opens a **detection**, or joins the open one for the same rule, host, container and program,
  which counts it. The detection's **process tree** grows with each event: Falco names the process with its command
  line, its parent with its command line, and older ancestors by name and pid; processes with the same pid are the
  same process, so a shell and the `id` it ran end up parent and child.
- **Off:** the event is kept and searchable, and nothing is raised.

A policy can also set the severity; otherwise it follows Falco's priority (critical and above is critical, error and
warning are high, notice is medium, informational is low). Detections are **open**, **investigating**, **resolved**
or a **false positive**, which needs a reason; a resolved or false-positive detection stops collecting, so the next
match is a new detection and a new decision, as in SIEM.

## Processes

runtime-agent's Falco rule `OpenAsy process started` sees every program start. The agent counts them by program,
parent and user and sends the counts, not each start. A host **learns** for its first days (7 by default), and so
does each container image, by repository, from the first time the host runs it: everything run then is **known**, and
a new version of an image is the same workload. Afterwards a program never seen on that host or in that image is
**new**, and a known program with a parent or user never seen with it is **drift**. A new program in a container raises Runtime's one
rule of its own, **New process in container**: containers run the same image every time, so a program the image
never ran is worth a look. An editor accepts a program as known.

## File integrity

The agent reads the files it watches every five minutes, read-only: SHA-256, mode, owner and size, or a link's
target. Runtime compares each read with the one before: a file that appears, changes, changes permissions or goes is
a **change** to review (approved or suspicious, with a note). The first read of a host, and files under a path
watched only now, are its baseline. Which process changed a file comes from Falco: the newest event about that file
on that host since the read before.

## Hosts and agents

An admin makes an **enrolment token** under Hosts: for one host, or with more uses for a fleet such as a DaemonSet,
valid for up to 30 days (7 by default). runtime-agent trades it once for a **secret of its own**, which speaks for its
host only; Runtime keeps hashes of both. A host name enrolls once: enrolling it again, for a lost volume or a leaked
secret, means an admin removes it first, which ends its secret at once. A host is **silent** after two minutes
without a word, **Falco down** when its agent cannot reach Falco, and **outdated** when its agent's version is not
Runtime's.

Runtime never connects to an agent and sends it nothing to do. The agent reads, sends and is answered "taken"; it
cannot kill a process or isolate a host, by design.

## SIEM

With `RUNTIME_SIEM_URL` and `RUNTIME_SIEM_TOKEN` (SIEM's ingest token), each new detection and each file change goes
to [SIEM](https://github.com/openasy/siem) as a flat event with `source: runtime`, the rule, severity, host,
container, image, Kubernetes namespace and pod, command line, MITRE techniques and a link back. Sigma rules there can
match them, correlate them with logins and network events, and open incidents. They wait in an outbox in the database
while SIEM is down and go when it is back.

## Run

```bash
openssl rand -hex 32 > openasy-kek
docker compose up -d
docker compose logs runtime | grep 'no owner yet'
```

Open the link from the log once to create the owner account; there is no default password (ADR 0013). The UI and API
are on http://localhost:8080, the API reference at http://localhost:8080/api/docs/. Then, under Hosts, make an
enrolment token and start runtime-agent with it next to Falco on each host; Setup shows Falco's configuration.

| Variable | Default | |
| --- | --- | --- |
| `PORT` | `8080` | HTTP port |
| `RUNTIME_PUBLIC_URL` | `http://localhost:8080` | The address people and agents open, with `https://` behind your TLS proxy |
| `RUNTIME_LEARNING_DAYS` | `7` | Days after a host enrols, or a host first runs an image, during which every program is learned as known |
| `RUNTIME_RETENTION_DAYS` | `30` | Events older than this are deleted; closed detections and reviewed changes after a year |
| `RUNTIME_SIEM_URL`, `RUNTIME_SIEM_TOKEN` | | Send new detections and file changes to SIEM |
| `OPENASY_PRODUCTS` | | The install's other OpenAsy products, for the product switcher |
| `RUNTIME_SECRETS_KEY_FILE` | `/run/secrets/openasy-kek` | 32-byte key-encryption key |
| `RUNTIME_DB` | `/data/runtime.db` | SQLite file (WAL), on the `/data` volume |
| `RUNTIME_METRICS_PORT` | | Serve `/metrics` on this port only (ADR 0026) |
| `RUNTIME_HEADLESS` | `false` | `true` serves only the API |
| `RUNTIME_PASSWORD_SIGN_IN`, `OPENASY_OIDC_*` | | Sign-in, as in every OpenAsy product ([@openasy/auth](https://github.com/openasy/auth)) |

`/metrics` has `openasy_runtime_detections_active{severity}`, `openasy_runtime_hosts{status}`,
`openasy_runtime_events_received_total`, `openasy_runtime_file_changes_unreviewed` and, with SIEM set,
`openasy_runtime_siem_pending`. Watch `openasy_runtime_hosts{status="silent"}` from a system other than Runtime: a
host whose agent was stopped sends nothing, and only its silence says so.

The container runs as non-root with a read-only root filesystem, no capabilities and `no-new-privileges`.

## Roles

Viewers see everything; editors also work detections, review file changes and accept programs; admins also change
policies, make enrolment tokens, remove hosts, and manage members and API tokens (ADR 0003).

## Not yet

- **Response.** Killing a process, isolating a host and enforce-mode policies are not built; the agent only reads.
  Falco's own response tooling (Falco Talon) can act on the same alerts where a team wants it.
- **Policies beyond a rule's mode and severity:** exceptions for a workload, scopes, and writing Falco rules from the
  UI. Rules are Falco's files, deployed with Falco.
- **Change windows** for file changes, and opening an incident from a change directly (SIEM can, from its event).
- **Tetragon** as a second sensor, and Falco's gRPC output.
- A Kubernetes manifest or Helm values for running the agent in Falco's DaemonSet pod. runtime-agent's compose file
  runs both on a host; on Kubernetes the agent belongs in the same pod as Falco, so Falco reaches it on 127.0.0.1.

## Develop

```bash
npm install
npm test        # Falco's alerts, trees, policies, the inventory, file integrity, SIEM's outbox, and every API response against openapi.json
npm run dev     # the UI, with the API on :8080
```

## Licence

AGPL-3.0 (ADR 0008).
