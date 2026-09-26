"use client";

import { useState } from "react";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { useResource } from "@/lib/useResource";
import type { Asset, Page } from "@/lib/types";
import { fmtDate, STATUS_CLASS } from "@/lib/format";
import { NeedProject, PageTitle } from "@/components/page";
import { Badge, Button, Card, CardHeader, EmptyState, ErrorState, Input, Select, Spinner, Table } from "@/components/ui";

const ASSET_TYPES = ["URL", "DOMAIN", "SUBDOMAIN", "IP", "HOST", "SERVICE", "API_ENDPOINT", "CERTIFICATE", "CLOUD"];
const CRITICALITY = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];

export default function AssetsPage() {
  const { project, hasPerm } = useAuth();
  const { data, error, loading, reload } = useResource<Page<Asset>>(
    () => api(`/projects/${project!.id}/assets?page_size=200`),
    [project?.id],
  );
  const [showForm, setShowForm] = useState(false);
  const [type, setType] = useState("URL");
  const [value, setValue] = useState("");
  const [crit, setCrit] = useState("MEDIUM");
  const [busy, setBusy] = useState(false);
  const [formError, setFormError] = useState("");

  if (!project) return <NeedProject />;

  async function create(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setFormError("");
    try {
      await api(`/projects/${project!.id}/assets`, {
        method: "POST",
        body: { type, value, criticality: crit },
      });
      setValue("");
      setShowForm(false);
      reload();
    } catch (err) {
      setFormError(err instanceof Error ? err.message : "Failed to create asset");
    } finally {
      setBusy(false);
    }
  }

  async function toggleAuth(a: Asset) {
    const authorize = a.authorization_status !== "AUTHORIZED";
    const note = authorize
      ? window.prompt("Authorization note (confirm you own or are authorized to test this asset):", "") ?? ""
      : "revoked";
    if (authorize && note === "") return;
    await api(`/assets/${a.id}/authorize`, { method: "POST", body: { authorize, note } });
    reload();
  }

  async function remove(a: Asset) {
    if (!window.confirm(`Delete asset ${a.value}?`)) return;
    await api(`/assets/${a.id}`, { method: "DELETE" });
    reload();
  }

  return (
    <>
      <PageTitle
        title="Assets"
        subtitle="Authorized attack-surface inventory. Only authorized assets can be scanned."
        action={
          hasPerm("asset.create") ? (
            <Button onClick={() => setShowForm((v) => !v)}>{showForm ? "Cancel" : "+ Add asset"}</Button>
          ) : undefined
        }
      />

      {showForm && (
        <Card className="mb-6 p-5">
          <form onSubmit={create} className="grid grid-cols-1 gap-4 sm:grid-cols-4">
            <Select label="Type" value={type} onChange={setType} options={ASSET_TYPES.map((t) => ({ value: t, label: t }))} />
            <div className="sm:col-span-2">
              <Input label="Value" value={value} onChange={setValue} required placeholder="https://app.example.com" />
            </div>
            <Select label="Criticality" value={crit} onChange={setCrit} options={CRITICALITY.map((c) => ({ value: c, label: c }))} />
            {formError && <p className="text-sm text-red-300 sm:col-span-4">{formError}</p>}
            <div className="sm:col-span-4">
              <Button type="submit" disabled={busy}>
                {busy ? "Saving…" : "Create asset"}
              </Button>
            </div>
          </form>
        </Card>
      )}

      <Card>
        <CardHeader title="Inventory" subtitle={data ? `${data.total} assets` : undefined} />
        {loading && <Spinner />}
        {error && <ErrorState message={error} onRetry={reload} />}
        {data && data.items.length === 0 && <EmptyState title="No assets yet" hint="Add an asset to begin." />}
        {data && data.items.length > 0 && (
          <Table head={["Type", "Value", "Criticality", "Authorization", "Last seen", ""]}>
            {data.items.map((a) => (
              <tr key={a.id} className="border-b border-border/60 last:border-0">
                <td className="px-4 py-3"><Badge>{a.type}</Badge></td>
                <td className="max-w-xs truncate px-4 py-3 font-mono text-xs text-sky-300">{a.value}</td>
                <td className="px-4 py-3">{a.criticality}</td>
                <td className={`px-4 py-3 font-medium ${STATUS_CLASS[a.authorization_status] || ""}`}>
                  {a.authorization_status}
                </td>
                <td className="px-4 py-3 text-muted">{fmtDate(a.last_seen)}</td>
                <td className="px-4 py-3 text-right">
                  <div className="flex justify-end gap-2">
                    {hasPerm("asset.authorize") && (
                      <button onClick={() => toggleAuth(a)} className="text-accent hover:underline">
                        {a.authorization_status === "AUTHORIZED" ? "Revoke" : "Authorize"}
                      </button>
                    )}
                    {hasPerm("asset.delete") && (
                      <button onClick={() => remove(a)} className="text-high hover:underline">
                        Delete
                      </button>
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
