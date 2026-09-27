"use client";

import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { useResource } from "@/lib/useResource";
import type { GraphData } from "@/lib/types";
import { NeedProject, PageTitle } from "@/components/page";
import { Card, CardHeader, EmptyState, ErrorState, Spinner } from "@/components/ui";

const KIND_ORDER = ["project", "asset", "finding", "technique", "alert"];
const KIND_COLOR: Record<string, string> = {
  project: "#38bdf8",
  asset: "#16a34a",
  finding: "#dc2626",
  technique: "#d97706",
  alert: "#a21caf",
};

export default function GraphPage() {
  const { project } = useAuth();
  const { data, error, loading, reload } = useResource<GraphData>(
    () => api(`/projects/${project!.id}/graph`),
    [project?.id],
  );

  if (!project) return <NeedProject />;

  const columns: Record<string, string[]> = {};
  const pos: Record<string, { x: number; y: number }> = {};
  if (data) {
    for (const k of KIND_ORDER) columns[k] = [];
    for (const n of data.nodes) (columns[n.kind] ??= []).push(n.id);
    const colWidth = 220;
    const rowHeight = 46;
    Object.entries(columns).forEach(([kind, ids], ci) => {
      const kindIndex = KIND_ORDER.indexOf(kind);
      const x = 90 + (kindIndex >= 0 ? kindIndex : ci) * colWidth;
      ids.forEach((id, ri) => {
        pos[id] = { x, y: 50 + ri * rowHeight };
      });
    });
  }
  const maxRows = data ? Math.max(1, ...Object.values(columns).map((c) => c.length)) : 1;
  const height = 60 + maxRows * 46;
  const width = 90 + KIND_ORDER.length * 220;
  const label = (id: string) => data?.nodes.find((n) => n.id === id)?.label ?? id;

  return (
    <>
      <PageTitle title="Security Graph" subtitle="Relationships between assets, findings, techniques and alerts." />
      <Card>
        <CardHeader
          title="Relationship graph"
          action={
            <div className="flex flex-wrap gap-3 text-xs">
              {KIND_ORDER.map((k) => (
                <span key={k} className="flex items-center gap-1.5 text-muted">
                  <span className="h-2.5 w-2.5 rounded-full" style={{ background: KIND_COLOR[k] }} />
                  {k}
                </span>
              ))}
            </div>
          }
        />
        {loading && <Spinner />}
        {error && <ErrorState message={error} onRetry={reload} />}
        {data && data.nodes.length <= 1 && <EmptyState title="Not enough data to graph" hint="Add assets and run scans to build the graph." />}
        {data && data.nodes.length > 1 && (
          <div className="overflow-auto p-4">
            <svg width={width} height={height} className="min-w-full">
              {data.edges.map((e, i) => {
                const s = pos[e.source];
                const t = pos[e.target];
                if (!s || !t) return null;
                return (
                  <line key={i} x1={s.x} y1={s.y} x2={t.x} y2={t.y} stroke="#1f2937" strokeWidth={1} />
                );
              })}
              {data.nodes.map((n) => {
                const p = pos[n.id];
                if (!p) return null;
                return (
                  <g key={n.id}>
                    <circle cx={p.x} cy={p.y} r={6} fill={KIND_COLOR[n.kind] || "#9ca3af"} />
                    <text x={p.x + 10} y={p.y + 4} fontSize={11} fill="#e5e7eb">
                      {label(n.id).length > 22 ? label(n.id).slice(0, 22) + "…" : label(n.id)}
                    </text>
                  </g>
                );
              })}
            </svg>
          </div>
        )}
      </Card>

      {data && data.edges.some((e) => e.reason) && (
        <Card className="mt-6">
          <CardHeader title="Correlation reasons" subtitle="Why entities are related" />
          <ul className="space-y-2 p-5 text-sm">
            {data.edges
              .filter((e) => e.reason)
              .map((e, i) => (
                <li key={i} className="text-muted">
                  <span className="font-mono text-xs text-accent">{e.relation}</span> — {e.reason}
                </li>
              ))}
          </ul>
        </Card>
      )}
    </>
  );
}
