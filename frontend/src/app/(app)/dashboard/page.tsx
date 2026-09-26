"use client";

import Link from "next/link";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { useResource } from "@/lib/useResource";
import type { Dashboard } from "@/lib/types";
import { SeverityBar, TypeDonut } from "@/components/charts";
import { NeedProject, PageTitle } from "@/components/page";
import { Badge, Card, CardHeader, ErrorState, Spinner, StatTile, Table } from "@/components/ui";

export default function DashboardPage() {
  const { project } = useAuth();
  const { data, error, loading, reload } = useResource<Dashboard>(
    () => api(`/projects/${project!.id}/dashboard`),
    [project?.id],
  );

  if (!project) return <NeedProject />;

  return (
    <>
      <PageTitle title="Security Overview" subtitle={`Live metrics for ${project.name}`} />
      {loading && <Spinner />}
      {error && <ErrorState message={error} onRetry={reload} />}
      {data && (
        <div className="space-y-6">
          <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
            <StatTile label="Authorized assets" value={`${data.authorized_assets}/${data.total_assets}`} />
            <StatTile label="Open findings" value={data.open_findings} />
            <StatTile label="Critical" value={data.critical_findings} tone="crit" />
            <StatTile label="Active alerts" value={data.active_alerts} tone="high" />
          </div>

          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <Card>
              <CardHeader title="Findings by severity" />
              <div className="p-4">
                <SeverityBar counts={data.findings_by_severity} />
              </div>
            </Card>
            <Card>
              <CardHeader title="Attack surface by asset type" />
              <div className="p-4">
                <TypeDonut data={data.assets_by_type} />
              </div>
            </Card>
          </div>

          <Card>
            <CardHeader title="Top risk findings" subtitle="Ranked by explainable risk score" />
            {data.top_risk_findings.length === 0 ? (
              <p className="px-5 py-8 text-center text-sm text-muted">No findings recorded yet.</p>
            ) : (
              <Table head={["Severity", "Finding", "Risk", "Status", ""]}>
                {data.top_risk_findings.map((f) => (
                  <tr key={f.id} className="border-b border-border/60 last:border-0">
                    <td className="px-4 py-3">
                      <Badge severity={f.severity}>{f.severity}</Badge>
                    </td>
                    <td className="px-4 py-3 text-fg">{f.title}</td>
                    <td className="px-4 py-3 font-mono tabular-nums">{f.risk_score}</td>
                    <td className="px-4 py-3 text-muted">{f.status}</td>
                    <td className="px-4 py-3 text-right">
                      <Link href={`/findings/${f.id}`} className="text-accent hover:underline">
                        View
                      </Link>
                    </td>
                  </tr>
                ))}
              </Table>
            )}
          </Card>
          <p className="text-right text-xs text-muted">
            Generated {new Date(data.generated_at).toLocaleString()}
          </p>
        </div>
      )}
    </>
  );
}
