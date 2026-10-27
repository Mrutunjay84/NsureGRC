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
