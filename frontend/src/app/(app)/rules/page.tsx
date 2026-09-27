"use client";

import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { useResource } from "@/lib/useResource";
import type { Severity } from "@/lib/types";
import { PageTitle } from "@/components/page";
import { Badge, Card, CardHeader, ErrorState, Spinner, Table } from "@/components/ui";

interface Rule {
  id: number;
  organization_id: number | null;
  key: string;
  name: string;
  description: string;
  severity: Severity;
  event_type: string;
  threshold: number;
  window_seconds: number;
  mitre_technique_ids: string[];
  enabled: boolean;
}

export default function RulesPage() {
  const { org } = useAuth();
  const { data, error, loading, reload } = useResource<Rule[]>(
    () => api(`/organizations/${org!.id}/detection-rules`),
    [org?.id],
  );

  return (
    <>
      <PageTitle title="Detection Rules" subtitle="Global and organization-scoped rules evaluated against events." />
      <Card>
        <CardHeader title="Rules" subtitle={data ? `${data.length} rules` : undefined} />
        {loading && <Spinner />}
        {error && <ErrorState message={error} onRetry={reload} />}
        {data && (
          <Table head={["Key", "Name", "Severity", "Event", "Threshold", "Window", "Techniques", "Scope", "Enabled"]}>
            {data.map((r) => (
              <tr key={r.id} className="border-b border-border/60 last:border-0">
                <td className="px-4 py-3 font-mono text-xs text-accent">{r.key}</td>
                <td className="px-4 py-3">{r.name}</td>
                <td className="px-4 py-3"><Badge severity={r.severity}>{r.severity}</Badge></td>
                <td className="px-4 py-3 text-muted">{r.event_type || "—"}</td>
                <td className="px-4 py-3 tabular-nums">{r.threshold}</td>
                <td className="px-4 py-3 tabular-nums text-muted">{r.window_seconds}s</td>
                <td className="px-4 py-3 font-mono text-xs text-muted">{r.mitre_technique_ids.join(", ") || "—"}</td>
                <td className="px-4 py-3 text-xs text-muted">{r.organization_id ? "Org" : "Global"}</td>
                <td className="px-4 py-3">{r.enabled ? <span className="text-ok">Enabled</span> : <span className="text-muted">Disabled</span>}</td>
              </tr>
            ))}
          </Table>
        )}
      </Card>
    </>
  );
}
