// D-P6-001: thin fetch wrapper around the existing NsureGRC auth/tenant API. The Vite dev proxy
// (vite.config.ts) makes this same-origin from the browser's perspective, so the existing
// cookie-session + CSRF setup works unmodified - no bearer tokens, no CORS.
const BASE = "/api/v1";

let csrfToken: string | null = null;

async function getCsrfToken(): Promise<string> {
  if (csrfToken) return csrfToken;
  const res = await fetch(`${BASE}/auth/csrf/`, { credentials: "same-origin" });
  const data = await res.json();
  csrfToken = data.csrfToken;
  return csrfToken!;
}

export class ApiError extends Error {
  status: number;
  body: unknown;
  constructor(status: number, body: unknown) {
    super(`API error ${status}`);
    this.status = status;
    this.body = body;
  }
}

async function request<T>(method: "GET" | "POST", path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (method !== "GET") headers["X-CSRFToken"] = await getCsrfToken();
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers,
    credentials: "same-origin",
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const data = res.status === 204 ? null : await res.json().catch(() => null);
  if (!res.ok) throw new ApiError(res.status, data);
  return data as T;
}

export const api = {
  get: <T,>(path: string) => request<T>("GET", path),
  post: <T,>(path: string, body?: unknown) => request<T>("POST", path, body),
  // the CSRF token issued before login is tied to the pre-login session; the login response rotates
  // the session cookie, so the next unsafe request needs a freshly-fetched token
  refreshCsrf: () => {
    csrfToken = null;
  },
};

// ---- response shapes for the endpoints this app calls (mirrors ngrc/iam/views.py, ngrc/reporting/views.py)
export type LoginStage = "enroll_mfa" | "password_ok" | "active";

export interface LoginResponse {
  stage: LoginStage;
  methods: string[];
}

export interface SessionResponse {
  stage: LoginStage;
  account: { id: string; email: string; display_name: string };
  tenant_id: string | null;
  expires_at: string;
  auth_methods: string[];
}

export interface TenantSummary {
  tenant_id: string;
  slug: string;
  name: string;
  role: string;
}

export interface EnrollBeginResponse {
  secret: string;
  otpauth_uri: string;
}

export interface FinishMfaResponse {
  stage: LoginStage;
  recovery_codes?: string[];
}

export interface MetricRow {
  [key: string]: unknown;
}

export interface DashboardResponse {
  posture: { posture_pct: number | null; scored_count: number; excluded_count: number };
  high_finding_ageing: { count: number; oldest_age_days: number | null; findings: MetricRow[] };
  overdue_tasks: { count: number; most_overdue_days: number | null; tasks: MetricRow[] };
  audit_bottlenecks: { count: number; oldest_age_days: number | null; audits: MetricRow[] };
  control_health: Record<string, MetricRow>;
  evidence_coverage: Record<string, MetricRow>;
  framework_coverage: Record<string, MetricRow>;
}

// ---- ngrc.reporting (D-P7-003 Calendar - read-only aggregation, no new model)
export interface Deadline {
  date: string;
  domain: "controls" | "risk" | "governance" | "privacy";
  object_type: string;
  object_id: string;
  title: string;
  overdue: boolean;
}

export interface CalendarResponse {
  deadlines: Deadline[];
}

// ---- ngrc.controls (CommonControl/ImplementationControl/ControlAssertion/Finding/Task)
export interface CommonControl {
  id: string;
  key: string;
  name: string;
  objective: string;
  category: string;
  lifecycle: string;
  owner: string | null;
  created_at: string;
}

export interface ImplementationControl {
  id: string;
  common_control_id: string;
  common_control_name: string;
  name: string;
  description: string;
  owner: string | null;
  reviewer: string | null;
  due_date: string | null;
  lifecycle: string;
  created_at: string;
}

export interface ControlAssertion {
  id: string;
  framework_urn: string;
  requirement_urn: string;
  coverage: number | null;
  satisfaction_state: string;
  review_state: string;
}

export interface Finding {
  id: string;
  implementation_control_id: string;
  title: string;
  description: string;
  source: string;
  severity: "low" | "medium" | "high" | "critical";
  status: "open" | "in_remediation" | "pending_verification" | "closed";
  remediation_notes: string;
  owner: string | null;
  created_at: string;
}

export interface Task {
  id: string;
  implementation_control_id: string;
  title: string;
  description: string;
  assigned_to: string | null;
  due_date: string | null;
  status: "open" | "in_progress" | "done";
  created_at: string;
}

export interface ImplementationControlDetail extends ImplementationControl {
  assertions: ControlAssertion[];
  findings: Finding[];
  tasks: Task[];
}

// ---- ngrc.evidence
export interface EvidenceItem {
  id: string;
  title: string;
  description: string;
  data_class: "C" | "R";
  created_at: string;
}

export interface EvidenceRevisionItem {
  id: string;
  revision_no: number;
  filename: string;
  detected_type: string;
  size_bytes: number;
  sha256: string;
  state: "scan_pending" | "collected" | "quarantined";
  created_at: string;
}

export interface EvidenceDetail extends EvidenceItem {
  revisions: EvidenceRevisionItem[];
}

export async function uploadEvidenceRevision(evidenceId: string, file: File): Promise<EvidenceRevisionItem> {
  const token = await (async () => {
    const res = await fetch(`${BASE}/auth/csrf/`, { credentials: "same-origin" });
    return (await res.json()).csrfToken as string;
  })();
  const res = await fetch(`${BASE}/tenant/evidence/${evidenceId}/revisions/`, {
    method: "POST",
    credentials: "same-origin",
    headers: {
      "X-CSRFToken": token,
      "Content-Type": file.type || "application/octet-stream",
      "X-Filename": encodeURIComponent(file.name),
    },
    body: file,
  });
  const data = await res.json();
  if (!res.ok) throw new ApiError(res.status, data);
  return data as EvidenceRevisionItem;
}

// ---- ngrc.risk
export interface RiskAssessment {
  id: string;
  name: string;
  description: string;
  status: "draft" | "in_progress" | "completed";
  owner: string | null;
  created_at: string;
}

export interface RiskScenario {
  id: string;
  risk_assessment_id: string;
  name: string;
  description: string;
  threat: string;
  vulnerability: string;
  likelihood: number;
  impact: number;
  risk_level: string;
  treatment: "mitigate" | "avoid" | "transfer" | "accept" | null;
  status: "open" | "treating" | "accepted" | "closed";
  owner: string | null;
  asset_id: string | null;
  created_at: string;
}

// ---- ngrc.governance
export interface Policy {
  id: string;
  title: string;
  description: string;
  status: "draft" | "active" | "retired";
  owner: string | null;
  effective_date: string | null;
  next_review_date: string | null;
  created_at: string;
}

export interface Objective {
  id: string;
  title: string;
  description: string;
  status: "open" | "achieved" | "missed";
  owner: string | null;
  target_date: string | null;
  created_at: string;
}

export interface Issue {
  id: string;
  title: string;
  description: string;
  severity: "low" | "medium" | "high" | "critical";
  status: "open" | "in_progress" | "resolved" | "closed";
  owner: string | null;
  due_date: string | null;
  created_at: string;
}

// ---- ngrc.compliance_audit
export interface Audit {
  id: string;
  framework_urn: string;
  name: string;
  description: string;
  status: "draft" | "assigned" | "in_progress" | "submitted" | "review" | "changes_requested" | "accepted" | "signoff" | "locked";
  assigned_to: string | null;
  reviewer: string | null;
  locked_at: string | null;
  created_at: string;
}

export interface AuditItem {
  id: string;
  audit_id: string;
  requirement_urn: string;
  control_assertion_id: string | null;
  result: "not_assessed" | "compliant" | "partially_compliant" | "non_compliant" | "not_applicable";
  observation: string;
  created_at: string;
}

export interface AuditDetail extends Audit {
  items: AuditItem[];
}

// ---- ngrc.privacy
export interface ProcessingActivity {
  id: string;
  name: string;
  description: string;
  role: "controller" | "processor";
  status: "draft" | "active" | "retired";
  owner: string | null;
  created_at: string;
}

export interface RightsRequest {
  id: string;
  requester_reference: string;
  request_type: "access" | "rectification" | "erasure" | "restriction" | "portability" | "objection";
  status: "received" | "in_progress" | "fulfilled" | "rejected" | "closed";
  due_date: string | null;
  owner: string | null;
  created_at: string;
}

export interface Breach {
  id: string;
  title: string;
  description: string;
  severity: "low" | "medium" | "high" | "critical";
  status: "open" | "investigating" | "contained" | "notified" | "closed";
  discovered_at: string;
  notified_authority_at: string | null;
  notified_subjects_at: string | null;
  affected_data_subjects_estimate: number | null;
  owner: string | null;
  created_at: string;
}

// ---- D-P7-001: Third Parties
export type ThirdPartyCriticality = "low" | "medium" | "high" | "critical";

export interface ThirdPartyEntity {
  id: string;
  name: string;
  category: "vendor" | "processor" | "partner" | "other";
  criticality: ThirdPartyCriticality;
  status: "active" | "inactive";
  description: string;
  created_at: string;
}

export interface ThirdPartyEntityDetail extends ThirdPartyEntity {
  representatives: ThirdPartyRepresentative[];
  solutions: ThirdPartySolution[];
  assessments: ThirdPartyAssessment[];
}

export interface ThirdPartyRepresentative {
  id: string;
  entity_id: string;
  name: string;
  email: string;
  role: string;
  phone: string;
  created_at: string;
}

export interface ThirdPartySolution {
  id: string;
  entity_id: string;
  name: string;
  description: string;
  data_classification_note: string;
  created_at: string;
}

export interface ThirdPartyAssessment {
  id: string;
  entity_id: string;
  solution_id: string | null;
  scope: string;
  risk_rating: ThirdPartyCriticality | "";
  status: "draft" | "in_progress" | "completed";
  assessor: string | null;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
}

// ---- D-P7-002: Assets + BIA
export interface Asset {
  id: string;
  name: string;
  asset_type: "hardware" | "software" | "data" | "facility" | "personnel" | "service" | "other";
  criticality: ThirdPartyCriticality;
  owner: string | null;
  description: string;
  created_at: string;
}

export interface AssetDetail extends Asset {
  bias: AssetBia[];
  risk_scenarios: RiskScenario[];
  incidents: Incident[];
}

export interface AssetBia {
  id: string;
  asset_id: string;
  recovery_time_objective_hours: number | null;
  recovery_point_objective_hours: number | null;
  impact_rating: ThirdPartyCriticality;
  notes: string;
  assessor: string | null;
  assessed_at: string | null;
  created_at: string;
}

export interface Incident {
  id: string;
  title: string;
  description: string;
  severity: ThirdPartyCriticality;
  status: "detected" | "investigating" | "contained" | "resolved" | "closed";
  detected_at: string;
  resolved_at: string | null;
  closed_at: string | null;
  owner: string | null;
  risk_scenario_id: string | null;
  implementation_control_id: string | null;
  asset_id: string | null;
  created_at: string;
}
