import {
  AppShell,
  Badge,
  BrandProvider,
  Button,
  Callout,
  DataTable,
  Dialog,
  EmptyState,
  EntityChip,
  FacetFilter,
  FilterBar,
  KpiCard,
  KpiGrid,
  navigate,
  PageHeader,
  Panel,
  PRODUCT_IDS,
  QueryBar,
  SegmentedControl,
  SelectField,
  SEVERITY_META,
  SeverityBadge,
  Sparkline,
  StackedBarChart,
  StatusBadge,
  Switch,
  Tabs,
  TextField,
  toLocale,
  TONE_COLORS,
  useLocalePreference,
  usePath,
  useThemePreference,
  type Column,
  type ProductId,
  type Tone,
} from "@openasy/ui";
import { AccountSettings, AuthGate, MembersSettings, SignInSettings, TokensSettings, useAccountMenu, useAuth, useInstallBrand } from "@openasy/auth/react";
import colophon from "virtual:openasy-colophon";
import { Activity, Cpu, FileLock, KeyRound, LogIn, LogOut, Plus, ScrollText, Server, ShieldAlert, Trash2, UserRound, Users, Wrench } from "lucide-react";
import { Fragment, useCallback, useEffect, useMemo, useState, type FormEvent, type ReactNode } from "react";
import {
  api,
  MfaSetupRequired,
  Unauthorized,
  type Detection,
  type DetectionDetail,
  type DetectionStatus,
  type EnrollmentToken,
  type FileChange,
  type FileState,
  type Host,
  type HostStatus,
  type Kind,
  type Policy,
  type Process,
  type ProcNode,
  type ProductLink,
  type Review,
  type RtEvent,
  type Severity,
  type Summary,
} from "./api.ts";
import { useT } from "./i18n.ts";
import { search } from "./search.ts";

const PAGES = ["detections", "events", "processes", "file-integrity", "policies", "hosts", "setup", "account", "members", "signin", "tokens", "about"] as const;
type Page = (typeof PAGES)[number];
type Route = { page: Page; id?: string };
/** The first path segments that are pages of this UI, for followLinks. */
export const PATHS = [...PAGES];
function parseRoute(path: string): Route {
  const [page, id] = path.replace(/^\//, "").split("/");
  if ((PAGES as readonly string[]).includes(page ?? "")) return { page: page as Page, ...(id && { id: decodeURIComponent(id) }) };
  return { page: "detections" };
}

/** A query parameter of the address. */
const param = (name: string) => new URLSearchParams(window.location.search).get(name);

/** Data loading with the session; when it ends, the sign-in screen comes back. */
function useApi() {
  const { expired, refresh } = useAuth();
  return useCallback(
    async <T,>(path: string, init?: RequestInit): Promise<T> => {
      try {
        return await api<T>(path, init);
      } catch (err) {
        if (err instanceof Unauthorized) expired();
        if (err instanceof MfaSetupRequired) void refresh();
        throw err;
      }
    },
    [expired, refresh],
  );
}
type Call = ReturnType<typeof useApi>;

/** Loads a list, again when the path changes and on demand. */
function useList<T>(call: Call, path: string, key: string) {
  const [items, setItems] = useState<T[]>();
  const load = useCallback(
    () =>
      void call<Record<string, T[]>>(path).then(
        (r) => setItems(r[key]),
        () => setItems([]),
      ),
    [call, path, key],
  );
  useEffect(load, [load]);
  return [items, load] as const;
}

/** Runs a change and reports its error, the way every form here does. */
function useAction(after: () => void) {
  const [error, setError] = useState<string>();
  const run = useCallback(
    async (fn: () => Promise<unknown>) => {
      try {
        await fn();
        setError(undefined);
        after();
        return true;
      } catch (err) {
        setError((err as Error).message);
        return false;
      }
    },
    [after],
  );
  return [run, error] as const;
}

const when = (iso: string) => new Date(iso).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
const clock = (iso: string) => new Date(iso).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" });
const hour = (iso: string) => new Date(iso).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
const short = (sha: string | null) => (sha ? `${sha.slice(0, 8)}…${sha.slice(-4)}` : "–");
const SEVERITY_ORDER: Severity[] = ["info", "low", "medium", "high", "critical"];
const put = (body: unknown): RequestInit => ({ method: "PUT", body: JSON.stringify(body) });

const STATUS_TONE: Record<DetectionStatus, Tone> = { open: "danger", investigating: "warning", resolved: "success", "false-positive": "neutral" };
const KIND_TONE: Record<Kind, Tone> = { exec: "info", network: "neutral", file: "warning", kernel: "danger", other: "neutral" };
const BASELINE_TONE = { known: "neutral", new: "danger", drift: "warning" } as const;
const REVIEW_TONE: Record<Review, Tone> = { unreviewed: "warning", approved: "success", suspicious: "danger" };
const HOST_TONE: Record<HostStatus, Tone> = { healthy: "success", silent: "danger", "sensor-down": "danger", outdated: "warning" };

function ErrorText({ message }: { message?: string }) {
  return message ? <p className="m-0 text-xs text-danger">{message}</p> : null;
}

function Code({ children }: { children: ReactNode }) {
  return <pre className="m-0 overflow-x-auto rounded-md bg-subtle px-2.5 py-2 font-mono text-xs whitespace-pre-wrap text-fg">{children}</pre>;
}

function Facts({ items }: { items: Array<[ReactNode, ReactNode] | false | null | undefined | ""> }) {
  return (
    <dl className="runtime-facts text-sm">
      {items.filter(Boolean).map((item, i) => {
        const [k, v] = item as [ReactNode, ReactNode];
        return (
          <Fragment key={i}>
            <dt className="text-fg-muted">{k}</dt>
            <dd>{v}</dd>
          </Fragment>
        );
      })}
    </dl>
  );
}

// ---------------------------------------------------------------- Detections

function ProcessTree({ node }: { node: ProcNode }) {
  return (
    <li className="flex flex-col">
      <span className={node.flagged ? "flex items-start gap-2 rounded bg-danger-soft px-1.5 py-1 text-danger-text" : "flex items-start gap-2 px-1.5 py-1"}>
        <span className="w-12 shrink-0 font-mono text-2xs text-fg-muted">{node.pid ?? "?"}</span>
        <span className="min-w-0 grow font-mono text-xs break-all">{node.cmd}</span>
        {node.user && <span className="shrink-0 font-mono text-2xs text-fg-muted">{node.user}</span>}
      </span>
      {node.children.length > 0 && (
        <ul className="ml-3 flex flex-col border-l border-line pl-2">
          {node.children.map((c, i) => (
            <ProcessTree key={`${c.pid}-${i}`} node={c} />
          ))}
        </ul>
      )}
    </li>
  );
}

function Where({ host, container }: { host: string; container: { name: string | null; id: string } | null }) {
  return (
    <span className="flex flex-wrap gap-1">
      <EntityChip kind="host" value={host} hideKind />
      {container && <EntityChip kind="container" value={container.name ?? container.id.slice(0, 12)} hideKind />}
    </span>
  );
}

function DetectionPanel({ call, id, onChange }: { call: Call; id?: string; onChange: () => void }) {
  const t = useT();
  const { can } = useAuth();
  const [d, setD] = useState<DetectionDetail>();
  const [fp, setFp] = useState(false);
  const [reason, setReason] = useState("");
  const load = useCallback(() => {
    if (id) void call<DetectionDetail>(`/api/v1/detections/${encodeURIComponent(id)}`).then(setD, () => setD(undefined));
    else setD(undefined);
  }, [call, id]);
  useEffect(load, [load]);
  const [run, error] = useAction(() => (load(), onChange()));
  const set = (status: DetectionStatus, why?: string) => run(() => call(`/api/v1/detections/${encodeURIComponent(d!.id)}`, put({ status, reason: why })));

  if (!d)
    return (
      <Panel title={t("detectionsPage.tree")} aria-label={t("detectionsPage.tree")}>
        <p className="py-6 text-center text-sm text-fg-muted">{t("detectionsPage.select")}</p>
      </Panel>
    );
  return (
    <Panel
      title={t("detectionsPage.tree")}
      description={`${d.rule} · ${d.host.name}`}
      actions={<StatusBadge tone={STATUS_TONE[d.status]}>{t(`statuses.${d.status}`)}</StatusBadge>}
      aria-label={t("detectionsPage.tree")}
    >
      <div className="flex flex-col gap-2.5">
        <ul aria-label={t("detectionsPage.treeFor", { rule: d.rule })} className="m-0 flex list-none flex-col p-0 text-sm">
          {d.tree.map((n, i) => (
            <ProcessTree key={`${n.pid}-${i}`} node={n} />
          ))}
        </ul>
        <p className="m-0 font-mono text-xs break-all text-fg-muted">{d.output}</p>
        <Facts
          items={[
            [t("detectionsPage.host"), d.host.name],
            d.container && [
              t("detectionsPage.container"),
              `${d.container.name ?? d.container.id}${d.container.namespace ? ` · ${d.container.namespace}` : ""}`,
            ],
            d.container?.image && [
              t("detectionsPage.image"),
              <span key="v" className="font-mono text-xs">
                {d.container.image}
              </span>,
            ],
            d.user && [
              t("detectionsPage.user"),
              <span key="v" className="font-mono text-xs">
                {d.user}
              </span>,
            ],
            [t("detectionsPage.events"), t("detectionsPage.eventsBetween", { count: d.count, first: when(d.firstAt), last: when(d.lastAt) })],
            d.attack.length > 0 && [
              "ATT&CK",
              <span key="v" className="font-mono text-xs">
                {d.attack.join(", ")}
              </span>,
            ],
            d.reason && [t("detectionsPage.reason"), d.reason],
            d.updatedBy && [t("detectionsPage.updatedBy"), `${d.updatedBy}, ${when(d.updatedAt!)}`],
          ]}
        />
        <div className="flex flex-wrap gap-1.5 border-t border-line pt-2">
          {can("editor") && d.status !== "investigating" && (
            <Button size="sm" onClick={() => void set("investigating")}>
              {t("detectionsPage.investigate")}
            </Button>
          )}
          {can("editor") && (d.status === "open" || d.status === "investigating") && (
            <>
              <Button size="sm" variant="primary" onClick={() => void set("resolved")}>
                {t("detectionsPage.resolve")}
              </Button>
              <Button size="sm" variant="ghost" onClick={() => setFp(true)}>
                {t("detectionsPage.falsePositive")}
              </Button>
            </>
          )}
          <Button size="sm" variant="ghost" onClick={() => navigate(`/events?detection=${encodeURIComponent(d.id)}`)}>
            {t("detectionsPage.allEvents")}
          </Button>
        </div>
        <ErrorText message={error} />
      </div>
      <Dialog
        open={fp}
        onOpenChange={setFp}
        title={t("detectionsPage.falsePositive")}
        description={t("detectionsPage.falsePositiveDetail")}
        onSubmit={(e: FormEvent) => {
          e.preventDefault();
          void set("false-positive", reason).then((ok) => ok && (setFp(false), setReason("")));
        }}
        footer={
          <Button type="submit" variant="primary" disabled={!reason.trim()}>
            {t("detectionsPage.markFalsePositive")}
          </Button>
        }
      >
        <TextField label={t("detectionsPage.reason")} value={reason} onChange={(e) => setReason(e.target.value)} required />
      </Dialog>
    </Panel>
  );
}

function DetectionsPage({ call, summary, selected, reload }: { call: Call; summary: Summary; selected?: string; reload: () => void }) {
  const t = useT();
  const [status, setStatus] = useState<"active" | "all">("active");
  const [sev, setSev] = useState<string[]>([]);
  const [draft, setDraft] = useState("");
  const [q, setQ] = useState("");
  const path = `/api/v1/detections?${new URLSearchParams({ ...(status === "active" && { status }), ...(sev.length && { severity: sev.join(",") }), ...(q && { q }) })}`;
  const [rows, load] = useList<Detection>(call, path, "detections");
  const s = summary;
  const delta = s.detections.openedLastDay - s.detections.openedDayBefore;
  const columns: Column<Detection>[] = [
    {
      id: "sev",
      header: t("detectionsPage.severity"),
      width: "96px",
      sortValue: (d) => SEVERITY_META[d.severity].rank,
      cell: (d) => <SeverityBadge severity={d.severity} />,
    },
    {
      id: "rule",
      header: t("detectionsPage.detection"),
      width: "28%",
      sortValue: (d) => d.rule,
      cell: (d) => (
        <span className="flex min-w-0 flex-col">
          <span className="truncate font-medium">{d.rule}</span>
          <span className="truncate text-2xs text-fg-muted">
            {t(`statuses.${d.status}`)} · {t("detectionsPage.count", { count: d.count })}
          </span>
        </span>
      ),
    },
    { id: "where", header: t("detectionsPage.where"), cell: (d) => <Where host={d.host.name} container={d.container} /> },
    {
      id: "proc",
      header: t("detectionsPage.process"),
      width: "24%",
      cell: (d) => (
        <span className="block truncate font-mono text-xs" title={d.process ?? ""}>
          {d.process ?? "–"}
        </span>
      ),
    },
    { id: "time", header: t("detectionsPage.last"), align: "right", mono: true, sortValue: (d) => d.lastAt, cell: (d) => when(d.lastAt) },
  ];
  const critical = s.detections.bySeverity.critical;
  return (
    <>
      <PageHeader
        title={t("detectionsPage.title")}
        description={t("detectionsPage.description", { hosts: s.hosts.total, policies: s.policies.total })}
        meta={critical > 0 ? <StatusBadge tone="danger">{t("detectionsPage.criticalOpen", { count: critical })}</StatusBadge> : undefined}
      />
      {s.hosts.total === 0 && (
        <Callout
          tone="info"
          title={t("detectionsPage.noHosts")}
          action={
            <Button size="sm" variant="primary" onClick={() => navigate("/hosts")}>
              {t("product.hosts")}
            </Button>
          }
        >
          {t("detectionsPage.noHostsDetail")}
        </Callout>
      )}
      <KpiGrid>
        <KpiCard
          label={t("detectionsPage.active")}
          value={s.detections.active}
          unit={t("detectionsPage.openedToday", { count: s.detections.openedLastDay })}
          tone={s.detections.active ? "danger" : "success"}
          delta={
            delta
              ? {
                  label: t("detectionsPage.vsYesterday", { delta: delta > 0 ? `+${delta}` : String(delta) }),
                  direction: delta > 0 ? "up" : "down",
                  intent: delta > 0 ? "bad" : "good",
                }
              : undefined
          }
        />
        <KpiCard
          label={t("detectionsPage.events24h")}
          value={s.events.lastDay.toLocaleString()}
          unit={t("detectionsPage.alerted", { count: s.events.alertedLastDay })}
          href="/events"
        />
        <KpiCard
          label={t("detectionsPage.sensors")}
          value={s.hosts.healthy}
          unit={t("detectionsPage.ofHosts", { count: s.hosts.total })}
          tone={s.hosts.silent + s.hosts.sensorDown ? "warning" : undefined}
          delta={
            s.hosts.silent + s.hosts.sensorDown
              ? { label: t("detectionsPage.notReporting", { count: s.hosts.silent + s.hosts.sensorDown }), intent: "bad" }
              : undefined
          }
          href="/hosts"
        />
        <KpiCard
          label={t("detectionsPage.fim24h")}
          value={s.files.changesLastDay}
          unit={t("detectionsPage.files")}
          tone={s.files.unreviewed ? "warning" : undefined}
          delta={s.files.unreviewed ? { label: t("detectionsPage.unreviewed", { count: s.files.unreviewed }), intent: "bad" } : undefined}
          href="/file-integrity"
        />
      </KpiGrid>
      <Panel title={t("detectionsPage.perHour")} description={t("detectionsPage.perHourDetail")}>
        <StackedBarChart
          label={t("detectionsPage.perHour")}
          categories={s.events.perHour.map((h) => hour(h.hour))}
          segments={SEVERITY_ORDER.map((sv) => ({ id: sv, name: SEVERITY_META[sv].label, color: TONE_COLORS[SEVERITY_META[sv].tone] }))}
          values={s.events.perHour.map((h) => SEVERITY_ORDER.map((sv) => h[sv]))}
          height={150}
          xTicks={7}
        />
      </Panel>
      <FilterBar onClear={sev.length || q || status !== "active" ? () => (setSev([]), setQ(""), setDraft(""), setStatus("active")) : undefined}>
        <SegmentedControl
          label={t("detectionsPage.show")}
          value={status}
          onChange={setStatus}
          options={[
            { value: "active", label: t("detectionsPage.activeOnly") },
            { value: "all", label: t("detectionsPage.all") },
          ]}
        />
        <FacetFilter
          label={t("detectionsPage.severity")}
          selected={sev}
          onChange={setSev}
          options={(["critical", "high", "medium", "low", "info"] as Severity[]).map((v) => ({ value: v, label: SEVERITY_META[v].label }))}
        />
        <QueryBar
          value={draft}
          onChange={setDraft}
          onSubmit={setQ}
          placeholder={t("detectionsPage.search")}
          label={t("detectionsPage.search")}
          className="min-w-64 grow"
        />
      </FilterBar>
      <div className="grid gap-2.5 xl:grid-cols-[minmax(0,3fr)_minmax(340px,2fr)]">
        <Panel title={t("detectionsPage.title")} description={t("detectionsPage.selectRow")} flush>
          <DataTable
            label={t("detectionsPage.table")}
            columns={columns}
            rows={rows ?? []}
            loading={!rows}
            getRowId={(d) => d.id}
            onRowClick={(d) => navigate(`/detections/${encodeURIComponent(d.id)}`)}
            activeRowId={selected}
            defaultSort={{ id: "time", direction: "desc" }}
            minWidth={860}
            empty={<EmptyState title={t("detectionsPage.none")}>{t("detectionsPage.noneDetail")}</EmptyState>}
          />
        </Panel>
        <DetectionPanel call={call} id={selected ?? rows?.[0]?.id} onChange={() => (load(), reload())} />
      </div>
    </>
  );
}

// ---------------------------------------------------------------- Events

function EventsPage({ call }: { call: Call }) {
  const t = useT();
  const detection = param("detection");
  const [kind, setKind] = useState<"all" | Kind>("all");
  const [draft, setDraft] = useState("");
  const [q, setQ] = useState("");
  const [pages, setPages] = useState<RtEvent[][]>([]);
  const [next, setNext] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [active, setActive] = useState<string>();
  const query = useMemo(
    () => new URLSearchParams({ ...(kind !== "all" && { kind }), ...(q && { q }), ...(detection && { detection }), limit: "200" }),
    [kind, q, detection],
  );
  useEffect(() => {
    setLoading(true);
    void call<{ events: RtEvent[]; next: string | null }>(`/api/v1/events?${query}`)
      .then((r) => (setPages([r.events]), setNext(r.next), setActive(r.events[0]?.id)))
      .catch(() => setPages([]))
      .finally(() => setLoading(false));
  }, [call, query]);
  const more = () =>
    void call<{ events: RtEvent[]; next: string | null }>(`/api/v1/events?${query}&before=${next}`).then(
      (r) => (setPages((p) => [...p, r.events]), setNext(r.next)),
    );
  const rows = pages.flat();
  const cur = rows.find((e) => e.id === active);
  const cols: Column<RtEvent>[] = [
    {
      id: "ts",
      header: t("eventsPage.time"),
      mono: true,
      width: "150px",
      sortValue: (e) => e.time,
      cell: (e) => `${new Date(e.time).toLocaleDateString()} ${clock(e.time)}`,
    },
    { id: "kind", header: t("eventsPage.kind"), width: "90px", cell: (e) => <Badge tone={KIND_TONE[e.kind]}>{t(`kinds.${e.kind}`)}</Badge> },
    { id: "host", header: t("eventsPage.host"), cell: (e) => <EntityChip kind="host" value={e.host} hideKind /> },
    { id: "pid", header: "PID", mono: true, align: "right", width: "70px", cell: (e) => e.pid ?? "–" },
    {
      id: "summary",
      header: t("eventsPage.event"),
      width: "34%",
      cell: (e) => (
        <span className="flex min-w-0 flex-col">
          <span className="truncate text-xs font-medium">{e.rule}</span>
          <span className="truncate font-mono text-2xs text-fg-muted" title={e.process ?? ""}>
            {e.file ?? e.process ?? "–"}
          </span>
        </span>
      ),
    },
    {
      id: "result",
      header: t("eventsPage.result"),
      width: "90px",
      description: t("eventsPage.resultHelp"),
      cell: (e) => <Badge tone={e.result === "alerted" ? "warning" : "neutral"}>{t(`results.${e.result}`)}</Badge>,
    },
  ];
  return (
    <>
      <PageHeader title={t("eventsPage.title")} description={t("eventsPage.description")} />
      {detection && (
        <Callout
          tone="info"
          title={t("eventsPage.ofDetection")}
          action={
            <Button size="sm" onClick={() => navigate("/events")}>
              {t("eventsPage.allEvents")}
            </Button>
          }
        />
      )}
      <FilterBar onClear={q || kind !== "all" ? () => (setQ(""), setDraft(""), setKind("all")) : undefined}>
        <QueryBar
          value={draft}
          onChange={setDraft}
          onSubmit={setQ}
          placeholder={t("eventsPage.search")}
          label={t("eventsPage.search")}
          className="min-w-64 grow"
        />
      </FilterBar>
      <Tabs
        label={t("eventsPage.kind")}
        value={kind}
        onChange={setKind}
        items={(["all", "exec", "network", "file", "kernel", "other"] as const).map((k) => ({ value: k, label: t(`kinds.${k}`) }))}
      />
      <div className="grid gap-2.5 xl:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
        <Panel
          title={t("eventsPage.title")}
          description={t("eventsPage.shown", { count: rows.length })}
          flush
          footer={
            next && (
              <Button size="sm" onClick={more}>
                {t("eventsPage.more")}
              </Button>
            )
          }
        >
          <DataTable
            label={t("eventsPage.table")}
            columns={cols}
            rows={rows}
            loading={loading}
            getRowId={(e) => e.id}
            onRowClick={(e) => setActive(e.id)}
            activeRowId={active}
            defaultSort={{ id: "ts", direction: "desc" }}
            minWidth={820}
            empty={<EmptyState title={t("eventsPage.none")}>{t("eventsPage.noneDetail")}</EmptyState>}
          />
        </Panel>
        <Panel
          title={t("eventsPage.fields")}
          description={cur ? `${t(`kinds.${cur.kind}`)} · ${clock(cur.time)}` : undefined}
          aria-label={t("eventsPage.fields")}
        >
          {cur ? (
            <div className="flex flex-col gap-2">
              <p className="m-0 font-mono text-xs break-all">{cur.output}</p>
              <dl className="runtime-facts">
                <dt className="text-fg-muted">host</dt>
                <dd className="font-mono text-xs">{cur.host}</dd>
                <dt className="text-fg-muted">priority</dt>
                <dd className="font-mono text-xs">{cur.priority}</dd>
                {Object.entries(cur.fields).map(([k, v]) => (
                  <Fragment key={k}>
                    <dt className="font-mono text-xs text-fg-muted">{k}</dt>
                    <dd className="font-mono text-xs break-all">{String(v)}</dd>
                  </Fragment>
                ))}
              </dl>
              {cur.detectionId ? (
                <Callout
                  tone="warning"
                  title={t("eventsPage.matched", { rule: cur.rule })}
                  action={
                    <Button size="sm" onClick={() => navigate(`/detections/${encodeURIComponent(cur.detectionId!)}`)}>
                      {t("eventsPage.openDetection")}
                    </Button>
                  }
                />
              ) : (
                <p className="m-0 text-xs text-fg-muted">{t("eventsPage.kept")}</p>
              )}
            </div>
          ) : (
            <p className="py-6 text-center text-sm text-fg-muted">{t("eventsPage.select")}</p>
          )}
        </Panel>
      </div>
    </>
  );
}

// ---------------------------------------------------------------- Processes

function ProcessesPage({ call, hosts }: { call: Call; hosts: Host[] }) {
  const t = useT();
  const { can } = useAuth();
  const [host, setHost] = useState(param("host") ?? hosts[0]?.name ?? "");
  const [unusual, setUnusual] = useState(false);
  const [rows, load] = useList<Process>(call, `/api/v1/processes?${new URLSearchParams({ ...(host && { host }) })}`, "processes");
  const [run, error] = useAction(load);
  const all = rows ?? [];
  const shown = all.filter((p) => !unusual || p.baseline !== "known");
  const h = hosts.find((x) => x.name === host);
  const [now] = useState(() => Date.now());
  const learning = h && Date.parse(h.learningUntil) > now;
  const cols: Column<Process>[] = [
    { id: "pid", header: "PID", mono: true, align: "right", width: "70px", sortValue: (p) => p.pid ?? 0, cell: (p) => p.pid ?? "–" },
    { id: "ppid", header: "PPID", mono: true, align: "right", width: "70px", cell: (p) => p.ppid ?? "–" },
    {
      id: "cmd",
      header: t("processesPage.command"),
      width: "34%",
      cell: (p) => (
        <span className="flex min-w-0 flex-col">
          <span className="truncate font-mono text-xs" title={p.cmdline}>
            {p.cmdline}
          </span>
          <span className="truncate font-mono text-2xs text-fg-muted">
            {p.exe}
            {p.parent ? ` ← ${p.parent}` : ""}
          </span>
        </span>
      ),
    },
    { id: "user", header: t("processesPage.user"), mono: true, width: "80px", cell: (p) => p.user ?? "–" },
    {
      id: "container",
      header: t("processesPage.container"),
      cell: (p) =>
        p.container ? <EntityChip kind="container" value={p.container} hideKind /> : <span className="text-fg-subtle">{t("processesPage.onHost")}</span>,
    },
    { id: "count", header: t("processesPage.starts"), align: "right", mono: true, sortValue: (p) => p.count, cell: (p) => p.count.toLocaleString() },
    {
      id: "seen",
      header: t("processesPage.lastSeen"),
      align: "right",
      sortValue: (p) => p.lastSeenAt,
      cell: (p) => <span className="whitespace-nowrap text-fg-muted">{when(p.lastSeenAt)}</span>,
    },
    {
      id: "baseline",
      header: t("processesPage.baseline"),
      description: t("processesPage.baselineHelp"),
      sortValue: (p) => p.baseline,
      cell: (p) => <Badge tone={BASELINE_TONE[p.baseline]}>{t(`baselines.${p.baseline}`)}</Badge>,
    },
    {
      id: "act",
      header: "",
      width: "90px",
      hideable: false,
      cell: (p) =>
        p.baseline !== "known" && can("editor") ? (
          <Button
            size="xs"
            variant="ghost"
            onClick={() => void run(() => call(`/api/v1/processes/${p.id}`, put({ baseline: "known" })))}
            aria-label={t("processesPage.acceptOne", { exe: p.exe })}
          >
            {t("processesPage.accept")}
          </Button>
        ) : null,
    },
  ];
  return (
    <>
      <PageHeader title={t("processesPage.title")} description={t("processesPage.description")} />
      <FilterBar>
        <SelectField
          label={t("processesPage.host")}
          value={host}
          onChange={(e) => setHost(e.target.value)}
          options={hosts.map((x) => ({ value: x.name, label: x.name }))}
        />
        <Switch checked={unusual} onCheckedChange={setUnusual} label={t("processesPage.onlyUnusual")} />
      </FilterBar>
      {learning && (
        <Callout tone="info" title={t("processesPage.learning", { until: when(h.learningUntil) })}>
          {t("processesPage.learningDetail")}
        </Callout>
      )}
      <KpiGrid>
        <KpiCard label={t("processesPage.programs")} value={all.length} unit={t("processesPage.seen")} />
        <KpiCard
          label={t("processesPage.new")}
          value={all.filter((p) => p.baseline === "new").length}
          tone={all.some((p) => p.baseline === "new") ? "danger" : undefined}
        />
        <KpiCard
          label={t("processesPage.drift")}
          value={all.filter((p) => p.baseline === "drift").length}
          tone={all.some((p) => p.baseline === "drift") ? "warning" : undefined}
        />
        <KpiCard label={t("processesPage.inContainers")} value={all.filter((p) => p.container).length} />
      </KpiGrid>
      <ErrorText message={error} />
      <Panel title={t("processesPage.on", { host: host || "–" })} description={t("processesPage.shown", { count: shown.length })} flush>
        <DataTable
          label={t("processesPage.table")}
          columns={cols}
          rows={shown}
          loading={!rows}
          getRowId={(p) => p.id}
          defaultSort={{ id: "seen", direction: "desc" }}
          minWidth={1000}
          empty={<EmptyState title={t("processesPage.none")}>{t("processesPage.noneDetail")}</EmptyState>}
        />
      </Panel>
    </>
  );
}

// ---------------------------------------------------------------- File integrity

function StateText({ s }: { s: FileState | null }) {
  const t = useT();
  if (!s) return <span className="text-fg-muted">{t("filesPage.absent")}</span>;
  return (
    <span className="font-mono text-xs break-all">
      {s.kind === "link" ? `→ ${s.target ?? "?"}` : s.sha256 ? `sha256:${short(s.sha256)}` : t("filesPage.tooLarge")} · {s.mode} {s.uid}:{s.gid} ·{" "}
      {s.size.toLocaleString()} B
    </span>
  );
}

function FileIntegrityPage({ call, reload }: { call: Call; reload: () => void }) {
  const t = useT();
  const { can } = useAuth();
  const [onlyOpen, setOnlyOpen] = useState(false);
  const [rows, load] = useList<FileChange>(call, `/api/v1/file-changes${onlyOpen ? "?review=unreviewed" : ""}`, "changes");
  const [active, setActive] = useState<string | undefined>(param("change") ?? undefined);
  const [note, setNote] = useState("");
  const [done, setDone] = useState<string>();
  const [run, error] = useAction(() => (load(), reload()));
  const cur = rows?.find((c) => c.id === active) ?? rows?.[0];
  const review = (r: Review) =>
    void run(() => call(`/api/v1/file-changes/${cur!.id}`, put({ review: r, ...(note.trim() && { note }) }))).then(
      (ok) => ok && (setDone(t(`filesPage.done.${r}`)), setNote("")),
    );
  const cols: Column<FileChange>[] = [
    {
      id: "path",
      header: t("filesPage.path"),
      width: "32%",
      sortValue: (c) => c.path,
      cell: (c) => (
        <span className="block truncate font-mono text-xs" title={c.path}>
          {c.path}
        </span>
      ),
    },
    { id: "host", header: t("filesPage.host"), cell: (c) => <EntityChip kind="host" value={c.host.name} hideKind /> },
    { id: "change", header: t("filesPage.change"), cell: (c) => <Badge>{t(`changes.${c.change}`)}</Badge> },
    { id: "when", header: t("filesPage.when"), sortValue: (c) => c.at, cell: (c) => <span className="whitespace-nowrap">{when(c.at)}</span> },
    { id: "by", header: t("filesPage.by"), cell: (c) => <span className="block truncate font-mono text-2xs">{c.by ?? "–"}</span> },
    {
      id: "review",
      header: t("filesPage.review"),
      sortValue: (c) => c.review,
      cell: (c) => <Badge tone={REVIEW_TONE[c.review]}>{t(`reviews.${c.review}`)}</Badge>,
    },
  ];
  const all = rows ?? [];
  return (
    <>
      <PageHeader title={t("filesPage.title")} description={t("filesPage.description")} />
      <KpiGrid>
        <KpiCard label={t("filesPage.changes")} value={all.length} unit={t("filesPage.files")} />
        <KpiCard
          label={t("filesPage.unreviewed")}
          value={all.filter((c) => c.review === "unreviewed").length}
          tone={all.some((c) => c.review === "unreviewed") ? "warning" : "success"}
        />
        <KpiCard
          label={t("filesPage.suspicious")}
          value={all.filter((c) => c.review === "suspicious").length}
          tone={all.some((c) => c.review === "suspicious") ? "danger" : undefined}
        />
        <KpiCard label={t("filesPage.withProcess")} value={all.filter((c) => c.by).length} unit={t("filesPage.fromFalco")} />
      </KpiGrid>
      <FilterBar>
        <Switch checked={onlyOpen} onCheckedChange={setOnlyOpen} label={t("filesPage.onlyUnreviewed")} />
      </FilterBar>
      <div className="grid gap-2.5 xl:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
        <Panel title={t("filesPage.changes")} description={t("filesPage.shown", { count: all.length })} flush>
          <DataTable
            label={t("filesPage.table")}
            columns={cols}
            rows={all}
            loading={!rows}
            getRowId={(c) => c.id}
            onRowClick={(c) => (setActive(c.id), setDone(undefined))}
            activeRowId={cur?.id}
            defaultSort={{ id: "when", direction: "desc" }}
            minWidth={860}
            empty={<EmptyState title={t("filesPage.none")}>{t("filesPage.noneDetail")}</EmptyState>}
          />
        </Panel>
        <Panel title={t("filesPage.detail")} description={cur?.path} aria-label={t("filesPage.detail")}>
          {cur ? (
            <div className="flex flex-col gap-2 text-sm">
              <Facts
                items={[
                  [t("filesPage.host"), cur.host.name],
                  [
                    t("filesPage.changedBy"),
                    <span key="v" className="font-mono text-xs">
                      {cur.by ?? t("filesPage.unknownProcess")}
                    </span>,
                  ],
                  [t("filesPage.before"), <StateText key="v" s={cur.before} />],
                  [t("filesPage.after"), <StateText key="v" s={cur.after} />],
                  cur.note && [t("filesPage.note"), cur.note],
                  cur.reviewedBy && [t("filesPage.reviewedBy"), `${cur.reviewedBy}, ${when(cur.reviewedAt!)}`],
                ]}
              />
              {can("editor") && (
                <>
                  <TextField label={t("filesPage.note")} value={note} onChange={(e) => setNote(e.target.value)} placeholder={t("filesPage.notePlaceholder")} />
                  <div className="flex flex-wrap gap-1.5 border-t border-line pt-2">
                    <Button size="sm" variant="primary" disabled={cur.review === "approved"} onClick={() => review("approved")}>
                      {t("filesPage.approve")}
                    </Button>
                    <Button size="sm" variant="danger" disabled={cur.review === "suspicious"} onClick={() => review("suspicious")}>
                      {t("filesPage.markSuspicious")}
                    </Button>
                  </div>
                </>
              )}
              {done && (
                <p role="status" className="m-0 text-xs text-success">
                  {done}
                </p>
              )}
              <ErrorText message={error} />
            </div>
          ) : (
            <p className="py-6 text-center text-sm text-fg-muted">{t("filesPage.select")}</p>
          )}
        </Panel>
      </div>
    </>
  );
}

// ---------------------------------------------------------------- Policies

function PoliciesPage({ call, reload }: { call: Call; reload: () => void }) {
  const t = useT();
  const { can } = useAuth();
  const [rows, load] = useList<Policy>(call, "/api/v1/policies", "policies");
  const [active, setActive] = useState<string>();
  const [saved, setSaved] = useState<string>();
  const [run, error] = useAction(() => (load(), reload()));
  const cur = rows?.find((p) => p.rule === active) ?? rows?.[0];
  const save = (body: Record<string, unknown>, said: string) =>
    void run(() => call(`/api/v1/policies/${encodeURIComponent(cur!.rule)}`, put(body))).then((ok) => ok && setSaved(said));
  const cols: Column<Policy>[] = [
    {
      id: "rule",
      header: t("policiesPage.rule"),
      width: "36%",
      sortValue: (p) => p.rule,
      cell: (p) => (
        <span className="flex min-w-0 flex-col">
          <span className="truncate font-medium">{p.rule}</span>
          <span className="truncate font-mono text-2xs text-fg-muted">{p.source === "runtime" ? t("policiesPage.ownRule") : `falco · ${p.source}`}</span>
        </span>
      ),
    },
    { id: "sev", header: t("policiesPage.severity"), sortValue: (p) => SEVERITY_META[p.severity].rank, cell: (p) => <SeverityBadge severity={p.severity} /> },
    { id: "attack", header: "ATT&CK", cell: (p) => <span className="font-mono text-xs">{p.attack.join(", ") || "–"}</span> },
    { id: "hits", header: t("policiesPage.hits"), align: "right", mono: true, sortValue: (p) => p.hits7d, cell: (p) => p.hits7d.toLocaleString() },
    {
      id: "mode",
      header: t("policiesPage.mode"),
      description: t("policiesPage.modeHelp"),
      sortValue: (p) => p.mode,
      cell: (p) => <Badge tone={p.mode === "alert" ? "warning" : "neutral"}>{t(`modes.${p.mode}`)}</Badge>,
    },
  ];
  return (
    <>
      <PageHeader title={t("policiesPage.title")} description={t("policiesPage.description", { count: rows?.length ?? 0 })} />
      <Callout tone="info" title={t("policiesPage.falcoRules")}>
        {t("policiesPage.falcoRulesDetail")}
      </Callout>
      <div className="grid gap-2.5 xl:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
        <Panel title={t("policiesPage.title")} flush>
          <DataTable
            label={t("policiesPage.table")}
            columns={cols}
            rows={rows ?? []}
            loading={!rows}
            getRowId={(p) => p.rule}
            onRowClick={(p) => (setActive(p.rule), setSaved(undefined))}
            activeRowId={cur?.rule}
            defaultSort={{ id: "hits", direction: "desc" }}
            minWidth={760}
            empty={<EmptyState title={t("policiesPage.none")}>{t("policiesPage.noneDetail")}</EmptyState>}
          />
        </Panel>
        <Panel title={t("policiesPage.policy")} description={cur?.rule} aria-label={t("policiesPage.policy")}>
          {cur && (
            <div className="flex flex-col gap-2.5 text-sm">
              {can("admin") ? (
                <>
                  <SegmentedControl
                    label={t("policiesPage.mode")}
                    value={cur.mode}
                    onChange={(m) => save({ mode: m }, t("policiesPage.savedMode", { rule: cur.rule, mode: t(`modes.${m}`) }))}
                    options={[
                      { value: "alert", label: t("modes.alert") },
                      { value: "off", label: t("modes.off") },
                    ]}
                  />
                  <SelectField
                    label={t("policiesPage.severity")}
                    value={cur.severityOverride ?? ""}
                    onChange={(e) => save({ severity: e.target.value || null }, t("policiesPage.savedSeverity", { rule: cur.rule }))}
                    options={[
                      { value: "", label: t("policiesPage.fromPriority", { priority: cur.priority }) },
                      ...(["critical", "high", "medium", "low", "info"] as Severity[]).map((s) => ({ value: s, label: SEVERITY_META[s].label })),
                    ]}
                  />
                </>
              ) : (
                <p className="m-0 text-xs text-fg-muted">{t("policiesPage.adminsChange")}</p>
              )}
              <Facts
                items={[
                  [
                    t("policiesPage.priority"),
                    <span key="v" className="font-mono text-xs">
                      {cur.priority}
                    </span>,
                  ],
                  [
                    t("policiesPage.tags"),
                    <span key="v" className="font-mono text-xs">
                      {cur.tags.join(", ") || "–"}
                    </span>,
                  ],
                  [t("policiesPage.hits"), cur.hits7d.toLocaleString()],
                  [t("policiesPage.lastSeen"), when(cur.lastSeenAt)],
                  cur.updatedBy && [t("policiesPage.updatedBy"), `${cur.updatedBy}, ${when(cur.updatedAt!)}`],
                ]}
              />
              {saved && (
                <p role="status" className="m-0 text-xs text-success">
                  {saved}
                </p>
              )}
              <ErrorText message={error} />
            </div>
          )}
        </Panel>
      </div>
    </>
  );
}

// ---------------------------------------------------------------- Hosts

function TokensPanel({ call }: { call: Call }) {
  const t = useT();
  const [tokens, load] = useList<EnrollmentToken>(call, "/api/v1/enrollment-tokens", "tokens");
  const [name, setName] = useState("");
  const [uses, setUses] = useState("1");
  const [made, setMade] = useState<EnrollmentToken>();
  const [run, error] = useAction(load);
  const create = (e: FormEvent) => {
    e.preventDefault();
    void run(async () =>
      setMade(await call<EnrollmentToken>("/api/v1/enrollment-tokens", { method: "POST", body: JSON.stringify({ name, maxUses: Number(uses) }) })),
    ).then((ok) => ok && setName(""));
  };
  const cols: Column<EnrollmentToken>[] = [
    { id: "name", header: t("hostsPage.tokenName"), cell: (x) => x.name },
    { id: "uses", header: t("hostsPage.uses"), align: "right", mono: true, cell: (x) => `${x.uses} / ${x.maxUses}` },
    {
      id: "state",
      header: t("hostsPage.state"),
      cell: (x) => <Badge tone={x.state === "active" ? "success" : "neutral"}>{t(`tokenStates.${x.state}`)}</Badge>,
    },
    { id: "expires", header: t("hostsPage.expires"), cell: (x) => when(x.expiresAt) },
    {
      id: "act",
      header: "",
      width: "60px",
      hideable: false,
      cell: (x) => (
        <Button
          size="xs"
          variant="ghost"
          icon={<Trash2 />}
          aria-label={t("hostsPage.deleteToken", { name: x.name })}
          onClick={() => void run(() => call(`/api/v1/enrollment-tokens/${x.id}`, { method: "DELETE" }))}
        />
      ),
    },
  ];
  return (
    <Panel title={t("hostsPage.tokens")} description={t("hostsPage.tokensDetail")}>
      <div className="flex flex-col gap-2.5">
        <form className="runtime-token-form" onSubmit={create}>
          <TextField
            label={t("hostsPage.tokenName")}
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder={t("hostsPage.tokenNamePlaceholder")}
            required
          />
          <TextField
            label={t("hostsPage.maxUses")}
            type="number"
            min={1}
            max={10000}
            value={uses}
            onChange={(e) => setUses(e.target.value)}
            hint={t("hostsPage.maxUsesHint")}
          />
          <Button type="submit" variant="primary" icon={<Plus />}>
            {t("hostsPage.makeToken")}
          </Button>
        </form>
        <ErrorText message={error} />
        {made?.token && (
          <Callout tone="success" title={t("hostsPage.tokenOnce")} onDismiss={() => setMade(undefined)}>
            <Code>{`RUNTIME_ENROLL_TOKEN=${made.token}`}</Code>
          </Callout>
        )}
        <DataTable
          label={t("hostsPage.tokens")}
          columns={cols}
          rows={tokens ?? []}
          loading={!tokens}
          getRowId={(x) => x.id}
          minWidth={600}
          empty={<EmptyState title={t("hostsPage.noTokens")} />}
        />
      </div>
    </Panel>
  );
}

function HostsPage({ call, hosts, reload }: { call: Call; hosts: Host[]; reload: () => void }) {
  const t = useT();
  const { can } = useAuth();
  const [status, setStatus] = useState<string[]>([]);
  const [removing, setRemoving] = useState<Host>();
  const [run, error] = useAction(reload);
  const rows = hosts.filter((h) => status.length === 0 || status.includes(h.status));
  const silent = hosts.filter((h) => h.status === "silent" || h.status === "sensor-down");
  const cols: Column<Host>[] = [
    { id: "name", header: t("hostsPage.host"), pinned: "left", sortValue: (h) => h.name, cell: (h) => <EntityChip kind="host" value={h.name} hideKind /> },
    {
      id: "os",
      header: t("hostsPage.os"),
      cell: (h) => (
        <span className="flex flex-col">
          <span className="text-xs">{h.os ?? "–"}</span>
          <span className="font-mono text-2xs text-fg-muted">{h.kernel ?? ""}</span>
        </span>
      ),
    },
    {
      id: "sensor",
      header: t("hostsPage.sensor"),
      cell: (h) => (
        <span className="flex flex-col">
          <span className="font-mono text-xs">Falco {h.falco.version ?? "?"}</span>
          <span className="font-mono text-2xs text-fg-muted">agent {h.version}</span>
        </span>
      ),
    },
    {
      id: "status",
      header: t("hostsPage.status"),
      sortValue: (h) => h.status,
      cell: (h) => <StatusBadge tone={HOST_TONE[h.status]}>{t(`hostStatuses.${h.status}`)}</StatusBadge>,
    },
    { id: "fim", header: t("hostsPage.fim"), align: "right", mono: true, cell: (h) => h.fim.files.toLocaleString() },
    {
      id: "eps",
      header: t("hostsPage.eventsPerHour"),
      width: "150px",
      cell: (h) => <Sparkline data={h.eventsPerHour} label={t("hostsPage.eventsOn", { host: h.name })} height={24} />,
    },
    {
      id: "seen",
      header: t("hostsPage.lastSeen"),
      sortValue: (h) => h.lastSeenAt,
      cell: (h) => <span className="whitespace-nowrap">{when(h.lastSeenAt)}</span>,
    },
    {
      id: "act",
      header: "",
      width: "60px",
      hideable: false,
      cell: (h) =>
        can("admin") ? (
          <Button size="xs" variant="ghost" icon={<Trash2 />} aria-label={t("hostsPage.remove", { host: h.name })} onClick={() => setRemoving(h)} />
        ) : null,
    },
  ];
  return (
    <>
      <PageHeader
        title={t("hostsPage.title")}
        description={t("hostsPage.description")}
        actions={
          <Button icon={<Wrench />} onClick={() => navigate("/setup")}>
            {t("hostsPage.install")}
          </Button>
        }
      />
      {silent.map((h) => (
        <Callout
          key={h.id}
          tone="danger"
          title={t(h.status === "silent" ? "hostsPage.silentTitle" : "hostsPage.sensorDownTitle", { host: h.name, when: when(h.lastSeenAt) })}
        >
          {h.status === "silent" ? t("hostsPage.silentDetail") : (h.falco.detail ?? t("hostsPage.sensorDownDetail"))}
        </Callout>
      ))}
      <KpiGrid>
        <KpiCard label={t("hostsPage.hosts")} value={hosts.length} unit={t("hostsPage.withAgent")} />
        <KpiCard label={t("hostStatuses.healthy")} value={hosts.filter((h) => h.status === "healthy").length} tone="success" />
        <KpiCard
          label={t("hostStatuses.outdated")}
          value={hosts.filter((h) => h.status === "outdated").length}
          tone={hosts.some((h) => h.status === "outdated") ? "warning" : undefined}
        />
        <KpiCard label={t("hostsPage.notReporting")} value={silent.length} tone={silent.length ? "danger" : undefined} />
      </KpiGrid>
      <FilterBar onClear={status.length ? () => setStatus([]) : undefined}>
        <FacetFilter
          label={t("hostsPage.status")}
          selected={status}
          onChange={setStatus}
          options={(["healthy", "silent", "sensor-down", "outdated"] as const).map((s) => ({
            value: s,
            label: t(`hostStatuses.${s}`),
            count: hosts.filter((h) => h.status === s).length,
          }))}
        />
      </FilterBar>
      <ErrorText message={error} />
      <Panel title={t("hostsPage.hosts")} description={t("hostsPage.shown", { count: rows.length })} flush>
        <DataTable
          label={t("hostsPage.table")}
          columns={cols}
          rows={rows}
          getRowId={(h) => h.id}
          onRowClick={(h) => navigate(`/processes?host=${encodeURIComponent(h.name)}`)}
          minWidth={1000}
          empty={<EmptyState title={t("hostsPage.none")}>{t("hostsPage.noneDetail")}</EmptyState>}
        />
      </Panel>
      {can("admin") && <TokensPanel call={call} />}
      <Dialog
        open={!!removing}
        onOpenChange={(o) => !o && setRemoving(undefined)}
        title={t("hostsPage.removeTitle", { host: removing?.name ?? "" })}
        description={t("hostsPage.removeDetail")}
        footer={
          <Button
            variant="danger"
            onClick={() => void run(() => call(`/api/v1/hosts/${removing!.id}`, { method: "DELETE" })).then(() => setRemoving(undefined))}
          >
            {t("hostsPage.removeConfirm")}
          </Button>
        }
      />
    </>
  );
}

// ---------------------------------------------------------------- Setup

function SetupPage({ summary }: { summary: Summary }) {
  const t = useT();
  const origin = window.location.origin;
  return (
    <>
      <PageHeader title={t("setupPage.title")} description={t("setupPage.description")} />
      <Panel title={t("setupPage.falco")} description={t("setupPage.falcoDetail")}>
        <Code>{`# /etc/falco/config.d/openasy.yaml
json_output: true
json_include_output_property: true
json_include_tags_property: true
http_output:
  enabled: true
  url: http://127.0.0.1:2801/
webserver:
  enabled: true
  listen_port: 8765
append_output:
  - match: { source: syscall }
    extra_fields: [proc.exepath, proc.pcmdline, proc.apid[2], proc.aname[2], proc.apid[3], proc.aname[3],
      proc.apid[4], proc.aname[4], user.name, container.id, container.name, container.image.repository,
      container.image.tag, k8s.ns.name, k8s.pod.name, fd.name, fd.typechar, evt.type]`}</Code>
      </Panel>
      <Panel title={t("setupPage.agent")} description={t("setupPage.agentDetail")}>
        <Code>{`# Next to Falco, on the host's network so Falco reaches it on 127.0.0.1:2801
runtime-agent:
  image: ghcr.io/openasy/runtime-agent:0.1.0
  network_mode: host
  read_only: true
  cap_drop: [ALL]
  security_opt: ["no-new-privileges:true"]
  volumes:
    - runtime-agent-data:/data
    - /:/host:ro          # watched files, read-only
  secrets: [openasy-agent-kek]
  environment:
    RUNTIME_URL: ${origin}
    RUNTIME_ENROLL_TOKEN: <from Hosts, Enrolment tokens>`}</Code>
      </Panel>
      <Panel
        title={t("setupPage.siem")}
        description={summary.siem.configured ? t("setupPage.siemOn", { url: summary.siem.url ?? "" }) : t("setupPage.siemDetail")}
      >
        <Code>{`RUNTIME_SIEM_URL=http://siem:8080
RUNTIME_SIEM_TOKEN=<SIEM_INGEST_TOKEN>`}</Code>
        {summary.siem.lastError && <ErrorText message={summary.siem.lastError} />}
      </Panel>
    </>
  );
}

// ---------------------------------------------------------------- Shell

/** Account, Members, Sign-in and API tokens: the screens come from @openasy/auth. */
function SettingsPage({ page }: { page: "account" | "members" | "signin" | "tokens" }) {
  const t = useT();
  const { signOut, can } = useAuth();
  if (page !== "account" && !can("admin")) return <EmptyState title={t("settingsPage.adminsOnly")}>{t("settingsPage.askAnAdmin")}</EmptyState>;
  return (
    <>
      <PageHeader
        title={t(`settingsPage.${page}.title`)}
        description={t(`settingsPage.${page}.description`)}
        actions={
          page === "account" && (
            <Button icon={<LogOut />} onClick={() => void signOut()}>
              {t("settingsPage.signOut")}
            </Button>
          )
        }
      />
      {page === "account" ? <AccountSettings /> : page === "members" ? <MembersSettings /> : page === "signin" ? <SignInSettings /> : <TokensSettings />}
    </>
  );
}

function Product() {
  const msg = useT();
  const [theme, setTheme] = useThemePreference();
  const [, setLocale] = useLocalePreference();
  const { me, can } = useAuth();
  const account = useAccountMenu();
  const route = parseRoute(usePath());
  const [summary, setSummary] = useState<Summary>();
  const [hosts, setHosts] = useState<Host[]>();
  const [products, setProducts] = useState<Array<ProductLink & { id: ProductId }>>([]);
  const call = useApi();
  const onSearch = useMemo(() => search(call, msg), [call, msg]);

  // The install's other products (OPENASY_PRODUCTS), for the switcher; ids this UI does not know are left out.
  useEffect(() => {
    void call<{ products: ProductLink[] }>("/api/v1/products").then(
      (r) =>
        setProducts(r.products.filter((p): p is ProductLink & { id: ProductId } => p.id !== "runtime" && (PRODUCT_IDS as readonly string[]).includes(p.id))),
      () => {},
    );
  }, [call]);

  const reload = useCallback(() => {
    void call<Summary>("/api/v1/summary").then(setSummary, () => {});
    void call<{ hosts: Host[] }>("/api/v1/hosts").then(
      (r) => setHosts(r.hosts),
      () => {},
    );
  }, [call]);
  useEffect(() => {
    reload();
    const t = setInterval(reload, 15_000);
    return () => clearInterval(t);
  }, [reload]);

  const nav = [
    { id: "detections", label: msg("product.detections"), icon: ShieldAlert, count: summary?.detections.active || undefined },
    { id: "events", label: msg("product.events"), icon: Activity },
    { id: "processes", label: msg("product.processes"), icon: Cpu, count: summary?.processes.new || undefined },
    { id: "file-integrity", label: msg("product.files"), icon: FileLock, count: summary?.files.unreviewed || undefined },
    { id: "policies", label: msg("product.policies"), icon: ScrollText, count: summary?.policies.total || undefined },
    { id: "hosts", label: msg("product.hosts"), icon: Server },
    { id: "setup", label: msg("product.setup"), icon: Wrench },
  ];
  const footerNav = [
    ...(can("admin")
      ? [
          { id: "members", label: msg("product.members"), icon: Users },
          { id: "signin", label: msg("product.signIn"), icon: LogIn },
          { id: "tokens", label: msg("product.apiTokens"), icon: KeyRound },
        ]
      : []),
    { id: "account", label: msg("product.account"), icon: UserRound },
  ];
  const roleName = me.user.role.charAt(0).toUpperCase() + me.user.role.slice(1);
  const settings = route.page === "account" || route.page === "members" || route.page === "signin" || route.page === "tokens";

  return (
    <AppShell
      product="runtime"
      onSearch={onSearch}
      about={colophon}
      nav={nav}
      activeNav={route.page}
      onNavigate={(id) => navigate(`/${id}`)}
      connectedProducts={products.map((p) => p.id)}
      onSwitchProduct={(id) => {
        const to = products.find((p) => p.id === id);
        if (to) window.location.assign(to.url);
      }}
      footerNav={account.settings(footerNav)}
      setup
      user={{ name: me.user.name, role: roleName, ...account.user }}
      theme={theme}
      onThemeChange={setTheme}
      onLanguageChange={(code) => setLocale(toLocale(code))}
    >
      {settings ? (
        <SettingsPage page={route.page as "account" | "members" | "signin" | "tokens"} />
      ) : !summary || !hosts ? (
        <EmptyState title={msg("product.loading")} icon={<ShieldAlert />}>
          {msg("product.reading")}
        </EmptyState>
      ) : route.page === "events" ? (
        <EventsPage key={window.location.search} call={call} />
      ) : route.page === "processes" ? (
        <ProcessesPage key={window.location.search} call={call} hosts={hosts} />
      ) : route.page === "file-integrity" ? (
        <FileIntegrityPage call={call} reload={reload} />
      ) : route.page === "policies" ? (
        <PoliciesPage call={call} reload={reload} />
      ) : route.page === "hosts" ? (
        <HostsPage call={call} hosts={hosts} reload={reload} />
      ) : route.page === "setup" ? (
        <SetupPage summary={summary} />
      ) : (
        <DetectionsPage call={call} summary={summary} selected={route.id} reload={reload} />
      )}
    </AppShell>
  );
}

export function App() {
  const installBrand = useInstallBrand();
  const [theme] = useThemePreference();
  const [locale] = useLocalePreference();
  return (
    // The install's brand from config/brand.env (ADR 0053); OpenAsy's own look where it sets none.
    <BrandProvider theme={theme} locale={locale} brand={{ name: "OpenAsy", organization: undefined, ...installBrand }} className="min-h-screen">
      <AuthGate product="OpenAsy Runtime">
        <Product />
      </AuthGate>
    </BrandProvider>
  );
}
