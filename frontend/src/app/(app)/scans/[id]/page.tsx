"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { api } from "@/lib/api";
import { useResource } from "@/lib/useResource";
import type { Finding, Scan } from "@/lib/types";
import { fmtDate, STATUS_CLASS } from "@/lib/format";
import { PageTitle } from "@/components/page";
import { Badge, Card, CardHeader, EmptyState, ErrorState, Spinner, Table } from "@/components/ui";

export default function ScanDetailPage() {
  const params = useParams();
  const id = Number(params.id);
  const scan = useResource<Scan>(() => api(`/scans/${id}`), [id]);
  const findings = useResource<Finding[]>(() => api(`/scans/${id}/findings`), [id]);

  return (
    <>
      <PageTitle title={`Scan #${id}`} subtitle="Scan configuration, status and results." />
      {scan.loading && <Spinner />}
      {scan.error && <ErrorState message={scan.error} onRetry={scan.reload} />}
      {scan.data && (
        <div className="space-y-6">
          <Card>
            <CardHeader title="Details" />
            <dl className="grid grid-cols-2 gap-4 p-5 text-sm sm:grid-cols-4">
              <div>
                <dt className="text-xs uppercase text-muted">Status</dt>
                <dd className={`mt-1 font-medium ${STATUS_CLASS[scan.data.status] || ""}`}>{scan.data.status}</dd>
              </div>
              <div>
                <dt className="text-xs uppercase text-muted">Type</dt>
                <dd className="mt-1">{scan.data.scan_type}</dd>
              </div>
              <div>
                <dt className="text-xs uppercase text-muted">Pages crawled</dt>
                <dd className="mt-1 tabular-nums">{scan.data.stats?.pages_crawled ?? "—"}</dd>
              </div>
              <div>
                <dt className="text-xs uppercase text-muted">Findings</dt>
                <dd className="mt-1 tabular-nums">{scan.data.stats?.findings ?? "—"}</dd>
              </div>
              <div className="col-span-2">
                <dt className="text-xs uppercase text-muted">Target</dt>
                <dd className="mt-1 break-all font-mono text-xs text-sky-300">{scan.data.target}</dd>
              </div>
              <div>
                <dt className="text-xs uppercase text-muted">Started</dt>
                <dd className="mt-1 text-muted">{fmtDate(scan.data.started_at)}</dd>
              </div>
              <div>
                <dt className="text-xs uppercase text-muted">Finished</dt>
                <dd className="mt-1 text-muted">{fmtDate(scan.data.finished_at)}</dd>
              </div>
              {scan.data.error && (
                <div className="col-span-full rounded-md border border-high/40 bg-high/10 px-3 py-2 text-red-300">
                  {scan.data.error}
                </div>
              )}
            </dl>
          </Card>

          <Card>
            <CardHeader title="Findings from this scan" />
            {findings.loading && <Spinner />}
            {findings.data && findings.data.length === 0 && <EmptyState title="No findings from this scan" />}
            {findings.data && findings.data.length > 0 && (
              <Table head={["Severity", "Finding", "Risk", ""]}>
                {findings.data.map((f) => (
                  <tr key={f.id} className="border-b border-border/60 last:border-0">
                    <td className="px-4 py-3"><Badge severity={f.severity}>{f.severity}</Badge></td>
                    <td className="px-4 py-3">{f.title}</td>
                    <td className="px-4 py-3 font-mono tabular-nums">{f.risk_score}</td>
                    <td className="px-4 py-3 text-right">
                      <Link href={`/findings/${f.id}`} className="text-accent hover:underline">View</Link>
                    </td>
                  </tr>
                ))}
              </Table>
            )}
          </Card>
        </div>
      )}
    </>
  );
}
