"use client";

import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { useResource } from "@/lib/useResource";
import type { Alert, Page } from "@/lib/types";
import { fmtDate } from "@/lib/format";
import { NeedProject, PageTitle } from "@/components/page";
import { Badge, Card, CardHeader, EmptyState, ErrorState, Spinner, Table } from "@/components/ui";

export default function AlertsPage() {
  const { project, hasPerm } = useAuth();
  const { data, error, loading, reload } = useResource<Page<Alert>>(
    () => api(`/projects/${project!.id}/alerts?page_size=100`),
    [project?.id],
  );

  if (!project) return <NeedProject />;

  async function update(a: Alert, status: string) {
    await api(`/alerts/${a.id}`, { method: "PATCH", body: { status } });
    reload();
  }

  return (
    <>
      <PageTitle title="Alerts" subtitle="Detection-engine alerts correlated from security events." />
      <Card>
        <CardHeader title="Open alerts" action={<button onClick={reload} className="text-sm text-muted hover:text-fg">Refresh</button>} />
        {loading && <Spinner />}
        {error && <ErrorState message={error} onRetry={reload} />}
        {data && data.items.length === 0 && <EmptyState title="No alerts" hint="Ingest security events to trigger detection rules." />}
        {data && data.items.length > 0 && (
          <Table head={["Severity", "Alert", "State", "Entity", "Events", "Techniques", "Last seen", ""]}>
            {data.items.map((a) => (
              <tr key={a.id} className="border-b border-border/60 last:border-0">
                <td className="px-4 py-3"><Badge severity={a.severity}>{a.severity}</Badge></td>
                <td className="px-4 py-3 text-fg">{a.title}</td>
                <td className="px-4 py-3"><Badge>{a.state}</Badge></td>
                <td className="px-4 py-3 font-mono text-xs text-sky-300">{a.entity || "—"}</td>
                <td className="px-4 py-3 tabular-nums">{a.event_count}</td>
                <td className="px-4 py-3 font-mono text-xs text-muted">{a.mitre_technique_ids.join(", ") || "—"}</td>
                <td className="px-4 py-3 text-muted">{fmtDate(a.last_seen)}</td>
                <td className="px-4 py-3 text-right">
                  {hasPerm("alert.manage") && a.status === "OPEN" && (
                    <div className="flex justify-end gap-2">
                      <button onClick={() => update(a, "ACKNOWLEDGED")} className="text-accent hover:underline">Ack</button>
                      <button onClick={() => update(a, "RESOLVED")} className="text-ok hover:underline">Resolve</button>
                    </div>
                  )}
                  {a.status !== "OPEN" && <span className="text-xs text-muted">{a.status}</span>}
                </td>
              </tr>
            ))}
          </Table>
        )}
      </Card>
    </>
  );
}
