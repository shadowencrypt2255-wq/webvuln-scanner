"use client";

import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { useResource } from "@/lib/useResource";
import type { Page } from "@/lib/types";
import { fmtDate } from "@/lib/format";
import { PageTitle } from "@/components/page";
import { Card, CardHeader, EmptyState, ErrorState, Spinner, Table } from "@/components/ui";

interface AuditLog {
  id: number;
  created_at: string;
  actor_id: number | null;
  action: string;
  resource_type: string;
  resource_id: string;
  result: string;
  ip: string;
}

export default function AuditPage() {
  const { org, hasPerm } = useAuth();
  const { data, error, loading, reload } = useResource<Page<AuditLog>>(
    () => api(`/organizations/${org!.id}/audit?page_size=100`),
    [org?.id],
  );

  if (!hasPerm("audit.read")) {
    return (
      <>
        <PageTitle title="Audit Log" />
        <EmptyState title="Insufficient permissions" hint="Your role does not include audit.read." />
      </>
    );
  }

  return (
    <>
      <PageTitle title="Audit Log" subtitle="Security-sensitive actions across your organization." />
      <Card>
        <CardHeader title="Recent activity" />
        {loading && <Spinner />}
        {error && <ErrorState message={error} onRetry={reload} />}
        {data && data.items.length === 0 && <EmptyState title="No audit entries" />}
        {data && data.items.length > 0 && (
          <Table head={["Time", "Action", "Resource", "Actor", "Result", "IP"]}>
            {data.items.map((l) => (
              <tr key={l.id} className="border-b border-border/60 last:border-0">
                <td className="px-4 py-3 text-muted">{fmtDate(l.created_at)}</td>
                <td className="px-4 py-3 font-mono text-xs text-accent">{l.action}</td>
                <td className="px-4 py-3 text-muted">{l.resource_type}{l.resource_id ? `:${l.resource_id}` : ""}</td>
                <td className="px-4 py-3 text-muted">{l.actor_id ?? "—"}</td>
                <td className={`px-4 py-3 ${l.result === "success" ? "text-ok" : "text-high"}`}>{l.result}</td>
                <td className="px-4 py-3 font-mono text-xs text-muted">{l.ip || "—"}</td>
              </tr>
            ))}
          </Table>
        )}
      </Card>
    </>
  );
}
