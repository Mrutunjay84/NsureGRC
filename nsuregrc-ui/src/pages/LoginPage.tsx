import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { api, ApiError } from "@/lib/api";
import type { EnrollBeginResponse, FinishMfaResponse, LoginResponse, TenantSummary } from "@/lib/api";

// D-P6-001: the real login flow, not a simplified stand-in - every customer account in this system goes
// through password -> MFA (enroll on first use, verify after) -> active (ngrc/authn/flow.py). There is no
// backend path that skips MFA, so a "password-only" screen would never reach the dashboard for real.
type Step = { kind: "password" } | { kind: "enroll"; secret: string; otpauthUri: string } | { kind: "verify" };

export function LoginPage({ onReady }: { onReady: () => void }) {
  const [step, setStep] = useState<Step>({ kind: "password" });
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function afterActive() {
    const { tenants } = await api.get<{ tenants: TenantSummary[] }>("/auth/tenants/");
    if (tenants.length === 1) {
      await api.post("/auth/tenants/select/", { tenant_id: tenants[0].tenant_id });
      api.refreshCsrf();
    }
    onReady();
  }

  async function submitPassword(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const res = await api.post<LoginResponse>("/auth/login/", { email, password });
      api.refreshCsrf();
      if (res.stage === "enroll_mfa") {
        const begin = await api.post<EnrollBeginResponse>("/auth/mfa/totp/enroll/begin/");
        setStep({ kind: "enroll", secret: begin.secret, otpauthUri: begin.otpauth_uri });
      } else {
        setStep({ kind: "verify" });
      }
    } catch (err) {
      setError(describeError(err));
    } finally {
      setBusy(false);
    }
  }

  async function submitEnrollConfirm(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const res = await api.post<FinishMfaResponse>("/auth/mfa/totp/enroll/confirm/", { code });
      api.refreshCsrf();
      if (res.recovery_codes) {
        setRecoveryCodes(res.recovery_codes);
      } else {
        await afterActive();
      }
    } catch (err) {
      setError(describeError(err));
    } finally {
      setBusy(false);
    }
  }

  async function submitVerify(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      await api.post<FinishMfaResponse>("/auth/mfa/totp/verify/", { code });
      api.refreshCsrf();
      await afterActive();
    } catch (err) {
      setError(describeError(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex min-h-svh items-center justify-center bg-background p-4">
      <Card className="w-full max-w-sm">
        <CardHeader>
          <CardTitle>NsureGRC</CardTitle>
          <CardDescription>
            {step.kind === "password" && "Sign in"}
            {step.kind === "enroll" && "Set up two-factor authentication"}
            {step.kind === "verify" && "Enter your authenticator code"}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {step.kind === "password" && (
            <form onSubmit={submitPassword} className="space-y-3">
              <input className="w-full rounded-md border px-3 py-2 text-sm" type="email" placeholder="Email"
                     value={email} onChange={(e) => setEmail(e.target.value)} required />
              <input className="w-full rounded-md border px-3 py-2 text-sm" type="password" placeholder="Password"
                     value={password} onChange={(e) => setPassword(e.target.value)} required />
              {error && <p className="text-sm text-destructive">{error}</p>}
              <Button type="submit" className="w-full" disabled={busy}>Sign in</Button>
            </form>
          )}

          {step.kind === "enroll" && !recoveryCodes && (
            <form onSubmit={submitEnrollConfirm} className="space-y-3">
              <p className="text-sm text-muted-foreground">
                Add this key to your authenticator app, then enter the 6-digit code it shows.
              </p>
              <code className="block break-all rounded-md bg-muted p-2 text-xs">{step.secret}</code>
              <input className="w-full rounded-md border px-3 py-2 text-sm" inputMode="numeric" placeholder="6-digit code"
                     value={code} onChange={(e) => setCode(e.target.value)} required />
              {error && <p className="text-sm text-destructive">{error}</p>}
              <Button type="submit" className="w-full" disabled={busy}>Confirm</Button>
            </form>
          )}

          {step.kind === "enroll" && recoveryCodes && (
            <div className="space-y-3">
              <p className="text-sm text-muted-foreground">
                Save these recovery codes - each one is shown only once.
              </p>
              <ul className="space-y-1">
                {recoveryCodes.map((c) => (
                  <li key={c}><code className="text-xs">{c}</code></li>
                ))}
              </ul>
              <Button className="w-full" onClick={() => void afterActive()}>Continue</Button>
            </div>
          )}

          {step.kind === "verify" && (
            <form onSubmit={submitVerify} className="space-y-3">
              <input className="w-full rounded-md border px-3 py-2 text-sm" inputMode="numeric" placeholder="6-digit code"
                     value={code} onChange={(e) => setCode(e.target.value)} required />
              {error && <p className="text-sm text-destructive">{error}</p>}
              <Button type="submit" className="w-full" disabled={busy}>Verify</Button>
            </form>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function describeError(err: unknown): string {
  if (err instanceof ApiError) {
    const body = err.body as { error?: string } | null;
    return body?.error ?? `Request failed (${err.status})`;
  }
  return "Something went wrong";
}
