"use client";

import { useState } from "react";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { useResource } from "@/lib/useResource";
import type { Role } from "@/lib/types";
import { PageTitle } from "@/components/page";
import { Button, Card, CardHeader, ErrorState, Input, Select, Spinner, Table } from "@/components/ui";

interface Membership {
  id: number;
  user_id: number;
  organization_id: number;
  role: Role;
}
interface Prefs {
  on_critical_finding: boolean;
  on_new_exposed_asset: boolean;
  on_scan_failure: boolean;
  on_important_alert: boolean;
}

export default function SettingsPage() {
  const { org, hasPerm, refreshProjects } = useAuth();
  const [projName, setProjName] = useState("");
  const [projMsg, setProjMsg] = useState("");

  const members = useResource<Membership[]>(
    () => api(`/organizations/${org!.id}/members`),
    [org?.id],
  );
  const prefs = useResource<Prefs>(() => api(`/me/notification-preferences`), []);
  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteRole, setInviteRole] = useState<Role>("VIEWER");
  const [inviteMsg, setInviteMsg] = useState("");

  async function createProject(e: React.FormEvent) {
    e.preventDefault();
    setProjMsg("");
    try {
      await api(`/organizations/${org!.id}/projects`, { method: "POST", body: { name: projName } });
      setProjName("");
      await refreshProjects();
      setProjMsg("Project created.");
    } catch (err) {
      setProjMsg(err instanceof Error ? err.message : "Failed");
    }
  }

  async function invite(e: React.FormEvent) {
    e.preventDefault();
    setInviteMsg("");
    try {
      await api(`/organizations/${org!.id}/members`, { method: "POST", body: { email: inviteEmail, role: inviteRole } });
      setInviteEmail("");
      members.reload();
      setInviteMsg("Member added.");
    } catch (err) {
      setInviteMsg(err instanceof Error ? err.message : "Failed (the user must already have an account).");
    }
  }

  async function savePref(key: keyof Prefs, value: boolean) {
    await api(`/me/notification-preferences`, { method: "PUT", body: { [key]: value } });
    prefs.reload();
  }

  return (
    <>
      <PageTitle title="Settings" subtitle={org ? `Organization: ${org.name}` : undefined} />
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {hasPerm("project.manage") && (
          <Card>
            <CardHeader title="Create project" />
            <form onSubmit={createProject} className="space-y-3 p-5">
              <Input label="Project name" value={projName} onChange={setProjName} required placeholder="Production Web" />
              <Button type="submit">Create</Button>
              {projMsg && <p className="text-sm text-muted">{projMsg}</p>}
            </form>
          </Card>
        )}

        <Card>
          <CardHeader title="Notification preferences" />
          <div className="space-y-3 p-5">
            {prefs.loading && <Spinner />}
            {prefs.data &&
              (Object.keys(prefs.data) as (keyof Prefs)[]).map((k) => (
                <label key={k} className="flex items-center justify-between text-sm">
                  <span className="capitalize text-muted">{k.replace(/_/g, " ").replace("on ", "")}</span>
                  <input
                    type="checkbox"
                    checked={prefs.data![k]}
                    onChange={(e) => savePref(k, e.target.checked)}
                    className="h-4 w-4 accent-sky-400"
                  />
                </label>
              ))}
          </div>
        </Card>

        {hasPerm("user.manage") && (
          <Card className="lg:col-span-2">
            <CardHeader title="Team members" subtitle="Role-based access control" />
            <form onSubmit={invite} className="grid grid-cols-1 gap-3 p-5 sm:grid-cols-3">
              <div className="sm:col-span-1">
                <Input label="Invite by email" value={inviteEmail} onChange={setInviteEmail} placeholder="teammate@company.com" />
              </div>
              <Select label="Role" value={inviteRole} onChange={(v) => setInviteRole(v as Role)} options={[{ value: "VIEWER", label: "Viewer" }, { value: "SECURITY_ANALYST", label: "Security Analyst" }, { value: "ADMIN", label: "Admin" }]} />
              <div className="flex items-end">
                <Button type="submit">Add member</Button>
              </div>
              {inviteMsg && <p className="text-sm text-muted sm:col-span-3">{inviteMsg}</p>}
            </form>
            {members.error && <ErrorState message={members.error} onRetry={members.reload} />}
            {members.data && (
              <Table head={["User ID", "Role"]}>
                {members.data.map((m) => (
                  <tr key={m.id} className="border-b border-border/60 last:border-0">
                    <td className="px-4 py-3 font-mono text-muted">{m.user_id}</td>
                    <td className="px-4 py-3">{m.role}</td>
                  </tr>
                ))}
              </Table>
            )}
          </Card>
        )}
      </div>
    </>
  );
}
