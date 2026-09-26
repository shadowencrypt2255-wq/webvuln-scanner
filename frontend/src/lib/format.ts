import type { Severity } from "./types";

export const SEVERITY_CLASS: Record<Severity, string> = {
  CRITICAL: "bg-crit/20 text-fuchsia-300 border-crit/40",
  HIGH: "bg-high/20 text-red-300 border-high/40",
  MEDIUM: "bg-med/20 text-amber-300 border-med/40",
  LOW: "bg-low/20 text-blue-300 border-low/40",
  INFO: "bg-info/20 text-gray-300 border-info/40",
};

export const SEVERITY_HEX: Record<Severity, string> = {
  CRITICAL: "#a21caf",
  HIGH: "#dc2626",
  MEDIUM: "#d97706",
  LOW: "#2563eb",
  INFO: "#6b7280",
};

export const STATUS_CLASS: Record<string, string> = {
  COMPLETED: "text-ok",
  RUNNING: "text-accent",
  QUEUED: "text-muted",
  FAILED: "text-high",
  TIMEOUT: "text-med",
  CANCELLED: "text-muted",
  OPEN: "text-high",
  RESOLVED: "text-ok",
  AUTHORIZED: "text-ok",
  UNAUTHORIZED: "text-med",
  REVOKED: "text-high",
};

export function fmtDate(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function riskBand(score: number): string {
  if (score >= 80) return "Critical";
  if (score >= 60) return "High";
  if (score >= 35) return "Medium";
  if (score >= 15) return "Low";
  return "Informational";
}
