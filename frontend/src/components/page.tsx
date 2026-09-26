"use client";

import type { ReactNode } from "react";
import { EmptyState } from "./ui";

export function PageTitle({ title, subtitle, action }: { title: string; subtitle?: string; action?: ReactNode }) {
  return (
    <div className="mb-6 flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
      <div>
        <h1 className="text-xl font-semibold tracking-tight text-fg">{title}</h1>
        {subtitle && <p className="mt-1 text-sm text-muted">{subtitle}</p>}
      </div>
      {action}
    </div>
  );
}

export function NeedProject() {
  return (
    <EmptyState
      title="No project selected"
      hint="Create or select a project from the top bar to continue. Assets, scans and findings are scoped to a project."
    />
  );
}
