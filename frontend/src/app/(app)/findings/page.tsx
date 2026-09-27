"use client";

import { useState } from "react";
import Link from "next/link";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { useResource } from "@/lib/useResource";
import type { Finding, Page, Severity } from "@/lib/types";
import { NeedProject, PageTitle } from "@/components/page";
import { Badge, Card, CardHeader, EmptyState, ErrorState, Select, Spinner, Table } from "@/components/ui";

const SEVERITIES = ["", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
const STATUSES = ["", "OPEN", "CONFIRMED", "IN_PROGRESS", "MITIGATED", "ACCEPTED_RISK", "FALSE_POSITIVE", "RESOLVED"];

export default function FindingsPage() {
  const { project } = useAuth();
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");

  const query = new URLSearchParams({ page_size: "200" });
  if (severity) query.set("severity", severity);
  if (status) query.set("status", status);

  const { data, error, loading, reload } = useResource<Page<Finding>>(
    () => api(`/projects/${project!.id}/findings?${query.toString()}`),
    [project?.id, severity, status],
  );

  if (!project) return <NeedProject />;

  return (
    <>
      <PageTitle title="Findings" subtitle="Normalized vulnerabilities and misconfigurations." />

      <Card className="mb-6 p-4">
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
          <Select label="Severity" value={severity} onChange={setSeverity} options={SEVERITIES.map((s) => ({ value: s, label: s || "All severities" }))} />
          <Select label="Status" value={status} onChange={setStatus} options={STATUSES.map((s) => ({ value: s, label: s || "All statuses" }))} />
        </div>
      </Card>

      <Card>
        <CardHeader title="Results" subtitle={data ? `${data.total} findings` : undefined} />
        {loading && <Spinner />}
        {error && <ErrorState message={error} onRetry={reload} />}
        {data && data.items.length === 0 && <EmptyState title="No findings match these filters" />}
        {data && data.items.length > 0 && (
          <Table head={["Severity", "Finding", "Category", "CWE", "Risk", "Status", ""]}>
            {data.items.map((f) => (
              <tr key={f.id} className="border-b border-border/60 last:border-0">
                <td className="px-4 py-3"><Badge severity={f.severity as Severity}>{f.severity}</Badge></td>
                <td className="px-4 py-3 text-fg">{f.title}</td>
                <td className="px-4 py-3 text-muted">{f.category}</td>
                <td className="px-4 py-3 font-mono text-xs text-muted">{f.cwe || "—"}</td>
                <td className="px-4 py-3 font-mono tabular-nums">{f.risk_score}</td>
                <td className="px-4 py-3 text-muted">{f.status}</td>
                <td className="px-4 py-3 text-right">
                  <Link href={`/findings/${f.id}`} className="text-accent hover:underline">View</Link>
                </td>
              </tr>
            ))}
          </Table>
        )}
      </Card>
    </>
  );
}
