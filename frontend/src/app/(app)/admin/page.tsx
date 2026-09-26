"use client";

import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { useResource } from "@/lib/useResource";
import { fmtDate } from "@/lib/format";
import { PageTitle } from "@/components/page";
import { Card, CardHeader, EmptyState, ErrorState, Spinner, Table } from "@/components/ui";

interface AdminUser {
  id: number;
  email: string;
  full_name: string;
  is_active: boolean;
  is_superuser: boolean;
  last_login_at: string | null;
  created_at: string;
}

export default function AdminPage() {
  const { me } = useAuth();
  const { data, error, loading, reload } = useResource<AdminUser[]>(() => api(`/admin/users`), []);

  if (!me?.is_superuser) {
    return (
      <>
        <PageTitle title="Administration" />
        <EmptyState title="Superuser only" hint="This area is restricted to platform superusers." />
      </>
    );
  }

  async function toggle(u: AdminUser) {
    const action = u.is_active ? "deactivate" : "activate";
    await api(`/admin/users/${u.id}/${action}`, { method: "POST" });
    reload();
  }

  return (
    <>
      <PageTitle title="Administration" subtitle="Platform user management." />
      <Card>
        <CardHeader title="Users" subtitle={data ? `${data.length} users` : undefined} />
        {loading && <Spinner />}
        {error && <ErrorState message={error} onRetry={reload} />}
        {data && (
          <Table head={["ID", "Email", "Name", "Superuser", "Active", "Last login", ""]}>
            {data.map((u) => (
              <tr key={u.id} className="border-b border-border/60 last:border-0">
                <td className="px-4 py-3 font-mono text-muted">{u.id}</td>
                <td className="px-4 py-3 text-fg">{u.email}</td>
                <td className="px-4 py-3 text-muted">{u.full_name || "—"}</td>
                <td className="px-4 py-3">{u.is_superuser ? "Yes" : "—"}</td>
                <td className={`px-4 py-3 ${u.is_active ? "text-ok" : "text-high"}`}>{u.is_active ? "Active" : "Disabled"}</td>
                <td className="px-4 py-3 text-muted">{fmtDate(u.last_login_at)}</td>
                <td className="px-4 py-3 text-right">
                  <button onClick={() => toggle(u)} className={u.is_active ? "text-high hover:underline" : "text-ok hover:underline"}>
                    {u.is_active ? "Deactivate" : "Activate"}
                  </button>
                </td>
              </tr>
            ))}
          </Table>
        )}
      </Card>
    </>
  );
}
