"use client";

import {
  Bar,
  BarChart,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { SEVERITY_HEX } from "@/lib/format";
import type { Severity } from "@/lib/types";

const AXIS = "#9ca3af";
const TOOLTIP_STYLE = {
  background: "#0f1620",
  border: "1px solid #1f2937",
  borderRadius: 8,
  color: "#e5e7eb",
  fontSize: 12,
};

const SEV_ORDER: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

export function SeverityBar({ counts }: { counts: Record<Severity, number> }) {
  const data = SEV_ORDER.map((s) => ({ name: s, value: counts[s] ?? 0 }));
  return (
    <ResponsiveContainer width="100%" height={240}>
      <BarChart data={data} margin={{ top: 8, right: 8, bottom: 0, left: -20 }}>
        <XAxis dataKey="name" stroke={AXIS} fontSize={11} tickLine={false} />
        <YAxis stroke={AXIS} fontSize={11} allowDecimals={false} tickLine={false} axisLine={false} />
        <Tooltip contentStyle={TOOLTIP_STYLE} cursor={{ fill: "#1f2937", opacity: 0.4 }} />
        <Bar dataKey="value" radius={[4, 4, 0, 0]}>
          {data.map((d) => (
            <Cell key={d.name} fill={SEVERITY_HEX[d.name as Severity]} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

const PIE_COLORS = ["#38bdf8", "#a21caf", "#16a34a", "#d97706", "#2563eb", "#dc2626", "#9ca3af"];

export function TypeDonut({ data }: { data: Record<string, number> }) {
  const entries = Object.entries(data).map(([name, value]) => ({ name, value }));
  if (entries.length === 0) {
    return <div className="flex h-[240px] items-center justify-center text-sm text-muted">No assets yet</div>;
  }
  return (
    <ResponsiveContainer width="100%" height={240}>
      <PieChart>
        <Pie data={entries} dataKey="value" nameKey="name" innerRadius={55} outerRadius={90} paddingAngle={2}>
          {entries.map((e, i) => (
            <Cell key={e.name} fill={PIE_COLORS[i % PIE_COLORS.length]} />
          ))}
        </Pie>
        <Tooltip contentStyle={TOOLTIP_STYLE} />
      </PieChart>
    </ResponsiveContainer>
  );
}
