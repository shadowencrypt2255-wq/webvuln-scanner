"use client";

import { api } from "@/lib/api";
import { useResource } from "@/lib/useResource";
import type { MitreTechnique } from "@/lib/types";
import { PageTitle } from "@/components/page";
import { Card, CardHeader, ErrorState, Spinner, Table } from "@/components/ui";

export default function MitrePage() {
  const { data, error, loading, reload } = useResource<MitreTechnique[]>(
    () => api(`/mitre/techniques`),
    [],
  );

  return (
    <>
      <PageTitle title="MITRE ATT&CK" subtitle="Reference techniques mapped to findings and detections." />
      <Card>
        <CardHeader title="Techniques" subtitle={data ? `${data.length} techniques` : undefined} />
        {loading && <Spinner />}
        {error && <ErrorState message={error} onRetry={reload} />}
        {data && (
          <Table head={["ID", "Name", "Tactic", "Description"]}>
            {data.map((t) => (
              <tr key={t.technique_id} className="border-b border-border/60 last:border-0">
                <td className="px-4 py-3">
                  <a href={t.url} target="_blank" rel="noreferrer" className="font-mono text-accent hover:underline">{t.technique_id}</a>
                </td>
                <td className="px-4 py-3 text-fg">{t.name}</td>
                <td className="px-4 py-3 text-muted">{t.tactic}</td>
                <td className="px-4 py-3 text-xs text-muted">{t.description}</td>
              </tr>
            ))}
          </Table>
        )}
      </Card>
    </>
  );
}
