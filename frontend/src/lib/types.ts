export type Role = "ADMIN" | "SECURITY_ANALYST" | "VIEWER";

export interface MeOrganization {
  id: number;
  name: string;
  slug: string;
  role: Role;
  permissions: string[];
}

export interface Me {
  user: { id: number; email: string; full_name: string; is_superuser: boolean };
  organizations: MeOrganization[];
  is_superuser: boolean;
}

export interface Project {
  id: number;
  organization_id: number;
  name: string;
  description: string;
  created_at: string;
}

export type Severity = "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type AuthorizationStatus = "UNAUTHORIZED" | "AUTHORIZED" | "REVOKED";

export interface Asset {
  id: number;
  project_id: number;
  name: string;
  type: string;
  value: string;
  authorization_status: AuthorizationStatus;
  authorization_note: string;
  lifecycle: string;
  criticality: string;
  environment: string;
  tags: string[];
  first_seen: string;
  last_seen: string;
}

export interface Scan {
  id: number;
  project_id: number;
  asset_id: number;
  scan_type: string;
  status: string;
  target: string;
  stats: Record<string, number>;
  error: string;
  started_at: string | null;
  finished_at: string | null;
  created_at: string;
}

export interface Finding {
  id: number;
  asset_id: number;
  scan_id: number | null;
  title: string;
  description: string;
  category: string;
  severity: Severity;
  confidence: string;
  evidence: string;
  parameter: string;
  cwe: string;
  cve: string;
  remediation: string;
  references: string[];
  status: string;
  risk_score: number;
  risk_explanation: {
    score: number;
    summary?: string;
    factors?: Record<string, { normalized: number; weight: number; contribution: number }>;
  };
  first_seen: string;
}

export interface Alert {
  id: number;
  title: string;
  severity: Severity;
  state: string;
  status: string;
  entity: string;
  event_count: number;
  evidence: Record<string, unknown>;
  mitre_technique_ids: string[];
  risk_score: number;
  first_seen: string;
  last_seen: string;
}

export interface Dashboard {
  total_assets: number;
  authorized_assets: number;
  open_findings: number;
  critical_findings: number;
  high_findings: number;
  active_alerts: number;
  recent_scans: number;
  findings_by_severity: Record<Severity, number>;
  assets_by_type: Record<string, number>;
  top_risk_findings: Array<{
    id: number;
    title: string;
    severity: Severity;
    risk_score: number;
    status: string;
  }>;
  generated_at: string;
}

export interface Page<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
}

export interface GraphData {
  nodes: Array<{ id: string; kind: string; label: string; meta: Record<string, unknown> }>;
  edges: Array<{ source: string; target: string; relation: string; reason: string }>;
}

export interface MitreTechnique {
  technique_id: string;
  name: string;
  tactic: string;
  description: string;
  url: string;
}

export interface AiAnswer {
  answer: string;
  facts: string[];
  provider: string;
  disclaimer: string;
}
