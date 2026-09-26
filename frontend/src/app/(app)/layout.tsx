"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth";
import { Spinner } from "@/components/ui";

const NAV = [
  { href: "/dashboard", label: "Dashboard" },
  { href: "/assets", label: "Assets" },
  { href: "/scans", label: "Scans" },
  { href: "/findings", label: "Findings" },
  { href: "/alerts", label: "Alerts" },
  { href: "/rules", label: "Detection Rules" },
  { href: "/mitre", label: "MITRE ATT&CK" },
  { href: "/graph", label: "Security Graph" },
  { href: "/reports", label: "Reports" },
  { href: "/ai", label: "AI Analyst" },
  { href: "/audit", label: "Audit Log" },
  { href: "/settings", label: "Settings" },
];

export default function AppLayout({ children }: { children: React.ReactNode }) {
  const { me, loading, org, project, projects, setOrg, setProject, logout } = useAuth();
  const router = useRouter();
  const pathname = usePathname();
  const [open, setOpen] = useState(false);

  useEffect(() => {
    if (!loading && !me) router.replace("/login");
  }, [loading, me, router]);

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <Spinner label="Loading SentinelX…" />
      </div>
    );
  }
  if (!me) return null;

  const nav = [...NAV];
  if (me.is_superuser) nav.push({ href: "/admin", label: "Administration" });

  return (
    <div className="flex min-h-screen">
      {/* Sidebar */}
      <aside
        className={`${open ? "block" : "hidden"} fixed inset-y-0 left-0 z-30 w-64 border-r border-border bg-surface md:sticky md:top-0 md:block md:h-screen`}
      >
        <div className="flex h-14 items-center border-b border-border px-5">
          <span className="text-lg font-bold tracking-tight">
            Sentinel<span className="text-accent">X</span>
          </span>
        </div>
        <nav className="flex flex-col gap-0.5 p-3">
          {nav.map((item) => {
            const active = pathname === item.href || pathname.startsWith(item.href + "/");
            return (
              <Link
                key={item.href}
                href={item.href}
                onClick={() => setOpen(false)}
                className={`rounded-md px-3 py-2 text-sm transition-colors ${
                  active ? "bg-surface2 text-fg" : "text-muted hover:bg-surface2 hover:text-fg"
                }`}
              >
                {item.label}
              </Link>
            );
          })}
        </nav>
      </aside>

      {/* Main */}
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-20 flex h-14 items-center gap-3 border-b border-border bg-bg/95 px-4 backdrop-blur">
          <button
            className="rounded-md border border-border px-2 py-1 text-sm text-muted md:hidden"
            onClick={() => setOpen((v) => !v)}
            aria-label="Toggle navigation"
          >
            ☰
          </button>
          <div className="flex flex-1 items-center gap-2 overflow-x-auto">
            <select
              className="rounded-md border border-border bg-surface2 px-2 py-1.5 text-sm"
              value={org?.id ?? ""}
              onChange={(e) => setOrg(Number(e.target.value))}
            >
              {me.organizations.map((o) => (
                <option key={o.id} value={o.id}>
                  {o.name}
                </option>
              ))}
            </select>
            <select
              className="rounded-md border border-border bg-surface2 px-2 py-1.5 text-sm"
              value={project?.id ?? ""}
              onChange={(e) => {
                const p = projects.find((x) => x.id === Number(e.target.value)) || null;
                setProject(p);
              }}
            >
              {projects.length === 0 && <option value="">No projects</option>}
              {projects.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}
                </option>
              ))}
            </select>
            {org && (
              <span className="hidden rounded-full border border-border px-2 py-0.5 text-[11px] text-muted sm:inline">
                {org.role}
              </span>
            )}
          </div>
          <div className="flex items-center gap-3">
            <span className="hidden text-xs text-muted sm:inline">{me.user.email}</span>
            <button onClick={logout} className="rounded-md border border-border px-2.5 py-1.5 text-sm text-muted hover:text-fg">
              Sign out
            </button>
          </div>
        </header>

        <main className="mx-auto w-full max-w-7xl flex-1 px-4 py-6 sm:px-6">{children}</main>
      </div>
    </div>
  );
}
