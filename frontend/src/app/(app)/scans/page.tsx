"use client";

import { useState } from "react";
import Link from "next/link";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { useResource } from "@/lib/useResource";
import type { Asset, Page, Scan } from "@/lib/types";
import { fmtDate, STATUS_CLASS } from "@/lib/format";
import { NeedProject, PageTitle } from "@/components/page";
import { Badge, Button, Card, CardHeader, EmptyState, ErrorState, Select, Spinner, Table } from "@/components/ui";

const SCAN_TYPES = ["FULL", "DISCOVERY", "WEB_VULN", "TLS_HTTP"];

export default function ScansPage() {
  const { project, hasPerm } = useAuth();
  const { data, error, loading, reload } = useResource<Page<Scan>>(
    () => api(`/projects/${project!.id}/scans?page_size=100`),
    [project?.id],
  );
  const { data: assets } = useResource<Page<Asset>>(
    () => api(`/projects/${project!.id}/assets?authorization_status=AUTHORIZED&page_size=200`),
    [project?.id],
  );
  const [assetId, setAssetId] = useState("");
  const [scanType, setScanType] = useState("FULL");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");

  if (!project) return <NeedProject />;

  async function launch(e: React.FormEvent) {
    e.preventDefault();
    setMsg("");
    if (!assetId) {
      setMsg("Select an authorized asset.");
      return;
    }
    setBusy(true);
    try {
      await api(`/projects/${project!.id}/scans`, {
        method: "POST",
        body: { asset_id: Number(assetId), scan_type: scanType },
      });
      reload();
    } catch (err) {
      setMsg(err instanceof Error ? err.message : "Failed to start scan");
    } finally {
      setBusy(false);
    }
  }

  async function cancel(s: Scan) {
    await api(`/scans/${s.id}/cancel`, { method: "POST" });
    reload();
  }

  const authorized = assets?.items ?? [];

  return (
    <>
      <PageTitle title="Scans" subtitle="Authorized discovery and web-vulnerability scans." />

      {hasPerm("scan.create") && (
        <Card className="mb-6 p-5">
          <form onSubmit={launch} className="grid grid-cols-1 gap-4 sm:grid-cols-3">
            <Select
              label="Authorized asset"
              value={assetId}
              onChange={setAssetId}
              options={[{ value: "", label: authorized.length ? "Select…" : "No authorized assets" }, ...authorized.map((a) => ({ value: String(a.id), label: `${a.type}: ${a.value}` }))]}
            />
            <Select label="Scan type" value={scanType} onChange={setScanType} options={SCAN_TYPES.map((t) => ({ value: t, label: t }))} />
            <div className="flex items-end">
              <Button type="submit" disabled={busy || authorized.length === 0}>
                {busy ? "Starting…" : "Start scan"}
              </Button>
            </div>
            {msg && <p className="text-sm text-red-300 sm:col-span-3">{msg}</p>}
          </form>
        </Card>
      )}

      <Card>
        <CardHeader title="Scan history" action={<Button variant="ghost" onClick={reload}>Refresh</Button>} />
        {loading && <Spinner />}
        {error && <ErrorState message={error} onRetry={reload} />}
        {data && data.items.length === 0 && <EmptyState title="No scans yet" />}
        {data && data.items.length > 0 && (
          <Table head={["ID", "Type", "Status", "Target", "Findings", "Started", ""]}>
            {data.items.map((s) => (
              <tr key={s.id} className="border-b border-border/60 last:border-0">
                <td className="px-4 py-3 font-mono text-muted">#{s.id}</td>
                <td className="px-4 py-3"><Badge>{s.scan_type}</Badge></td>
                <td className={`px-4 py-3 font-medium ${STATUS_CLASS[s.status] || ""}`}>{s.status}</td>
                <td className="max-w-[16rem] truncate px-4 py-3 font-mono text-xs text-sky-300">{s.target}</td>
                <td className="px-4 py-3 tabular-nums">{s.stats?.findings ?? "—"}</td>
                <td className="px-4 py-3 text-muted">{fmtDate(s.started_at)}</td>
                <td className="px-4 py-3 text-right">
                  <div className="flex justify-end gap-2">
                    <Link href={`/scans/${s.id}`} className="text-accent hover:underline">View</Link>
                    {hasPerm("scan.cancel") && (s.status === "QUEUED" || s.status === "RUNNING") && (
                      <button onClick={() => cancel(s)} className="text-high hover:underline">Cancel</button>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </Table>
        )}
      </Card>
    </>
  );
}
