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
