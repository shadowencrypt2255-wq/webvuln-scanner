"use client";

import { useParams } from "next/navigation";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { useResource } from "@/lib/useResource";
import type { Finding } from "@/lib/types";
import { fmtDate, riskBand } from "@/lib/format";
import { PageTitle } from "@/components/page";
import { Badge, Card, CardHeader, ErrorState, Select, Spinner } from "@/components/ui";

interface Technique {
  technique_id: string;
  relationship_kind: string;
  confidence: string;
  evidence: string;
}

const STATUSES = ["OPEN", "CONFIRMED", "IN_PROGRESS", "MITIGATED", "ACCEPTED_RISK", "FALSE_POSITIVE", "RESOLVED"];

export default function FindingDetailPage() {
  const params = useParams();
  const id = Number(params.id);
  const { hasPerm } = useAuth();
  const { data, error, loading, reload } = useResource<Finding>(() => api(`/findings/${id}`), [id]);
  const techs = useResource<Technique[]>(() => api(`/findings/${id}/techniques`), [id]);

  async function setStatus(status: string) {
    await api(`/findings/${id}`, { method: "PATCH", body: { status } });
    reload();
  }

  return (
    <>
      <PageTitle title="Finding detail" />
      {loading && <Spinner />}
      {error && <ErrorState message={error} onRetry={reload} />}
      {data && (
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
          <div className="space-y-6 lg:col-span-2">
            <Card className="p-5">
              <div className="mb-3 flex flex-wrap items-center gap-2">
                <Badge severity={data.severity}>{data.severity}</Badge>
                <span className="text-xs text-muted">{data.category}</span>
                {data.cwe && <span className="rounded border border-border px-1.5 py-0.5 text-xs text-muted">{data.cwe}</span>}
                <span className="rounded border border-border px-1.5 py-0.5 text-xs text-muted">Confidence: {data.confidence}</span>
              </div>
              <h2 className="text-lg font-semibold text-fg">{data.title}</h2>
              <p className="mt-2 whitespace-pre-wrap text-sm text-muted">{data.description}</p>
              {data.parameter && (
                <p className="mt-3 text-sm">
                  <span className="text-muted">Parameter: </span>
                  <span className="font-mono text-sky-300">{data.parameter}</span>
                </p>
              )}
              {data.evidence && (
                <div className="mt-4">
                  <p className="mb-1 text-xs uppercase text-muted">Evidence</p>
                  <pre className="overflow-x-auto rounded-md border border-border bg-surface2 p-3 text-xs text-fg">{data.evidence}</pre>
                </div>
              )}
            </Card>

            <Card>
              <CardHeader title="Remediation" />
              <div className="p-5 text-sm text-muted">
                <p className="whitespace-pre-wrap">{data.remediation || "Review vendor guidance."}</p>
                {data.references.length > 0 && (
                  <ul className="mt-3 list-inside list-disc space-y-1">
                    {data.references.map((r) => (
                      <li key={r}>
                        <a href={r} target="_blank" rel="noreferrer" className="text-accent hover:underline">{r}</a>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </Card>

            <Card>
              <CardHeader title="MITRE ATT&CK techniques" subtitle="Potential techniques this vulnerability may enable" />
              <div className="p-5">
                {techs.data && techs.data.length === 0 && <p className="text-sm text-muted">No techniques mapped.</p>}
                {techs.data && techs.data.length > 0 && (
                  <div className="flex flex-wrap gap-2">
                    {techs.data.map((t) => (
                      <span key={t.technique_id} className="rounded-md border border-border bg-surface2 px-2.5 py-1 text-xs">
                        <span className="font-mono text-accent">{t.technique_id}</span>{" "}
                        <span className="text-muted">({t.relationship_kind})</span>
                      </span>
                    ))}
                  </div>
                )}
              </div>
            </Card>
          </div>

          <div className="space-y-6">
            <Card>
              <CardHeader title="Risk" subtitle={data.risk_explanation?.summary} />
              <div className="p-5">
                <div className="mb-4 flex items-baseline gap-2">
                  <span className="text-4xl font-bold tabular-nums text-fg">{data.risk_score}</span>
                  <span className="text-sm text-muted">/100 · {riskBand(data.risk_score)}</span>
                </div>
                <div className="space-y-2">
                  {data.risk_explanation?.factors &&
                    Object.entries(data.risk_explanation.factors).map(([name, f]) => (
                      <div key={name}>
                        <div className="flex justify-between text-xs">
                          <span className="capitalize text-muted">{name.replace(/_/g, " ")}</span>
                          <span className="tabular-nums text-fg">{f.contribution}</span>
                        </div>
                        <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-surface2">
                          <div className="h-full bg-accent" style={{ width: `${Math.min(100, f.normalized * 100)}%` }} />
                        </div>
                      </div>
                    ))}
                </div>
              </div>
            </Card>

            <Card>
              <CardHeader title="Status" />
              <div className="space-y-3 p-5 text-sm">
                {hasPerm("vulnerability.manage") ? (
                  <Select value={data.status} onChange={setStatus} options={STATUSES.map((s) => ({ value: s, label: s }))} />
                ) : (
                  <p className="text-muted">{data.status}</p>
                )}
                <p className="text-xs text-muted">First seen {fmtDate(data.first_seen)}</p>
              </div>
            </Card>
          </div>
        </div>
      )}
    </>
  );
}
