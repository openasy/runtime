// What the search window (Cmd+K) finds in Runtime: detections by their rule, host, container or process, and hosts by
// name. The API filters detections; hosts are read whole and filtered here.
import type { SearchFn, SearchResult } from "@openasy/ui";
import { Server, ShieldAlert } from "lucide-react";
import type { Detection, Host } from "./api.ts";
import type { T } from "./i18n.ts";

type Call = <R>(path: string, init?: RequestInit) => Promise<R>;

export function search(call: Call, t: T): SearchFn {
  return async (q, signal) => {
    const [{ detections }, { hosts }] = await Promise.all([
      call<{ detections: Detection[] }>(`/api/v1/detections?${new URLSearchParams({ q, limit: "6" })}`, { signal }),
      call<{ hosts: Host[] }>("/api/v1/hosts", { signal }),
    ]);
    return [
      ...detections.map((d): SearchResult => ({
        id: `detection:${d.id}`,
        label: d.rule,
        detail: [d.host.name, d.container?.name, d.process].filter(Boolean).join(" · "),
        kind: t("search.detection"),
        icon: ShieldAlert,
        severity: d.severity,
        href: `/detections/${encodeURIComponent(d.id)}`,
      })),
      ...hosts
        .filter((h) => h.name.toLowerCase().includes(q))
        .slice(0, 4)
        .map((h): SearchResult => ({
          id: `host:${h.id}`,
          label: h.name,
          detail: t(`hostStatuses.${h.status}`),
          kind: t("search.host"),
          icon: Server,
          href: `/processes?host=${encodeURIComponent(h.name)}`,
        })),
    ];
  };
}
