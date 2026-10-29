import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import {
  CheckSquare,
  ClipboardCheck,
  FileWarning,
  Gauge,
  ShieldCheck,
  Sparkles,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { PageContainer, PageHeader } from "@/components/layout/PageHeader";
import { api } from "@/lib/api";
import type { DashboardResponse } from "@/lib/api";

const SEVERITY_ORDER = ["critical", "high"] as const;
const SEVERITY_DOT: Record<string, string> = { critical: "bg-red-500", high: "bg-orange-500" };

export function DashboardPage() {
  const [data, setData] = useState<DashboardResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .get<DashboardResponse>("/tenant/reporting/dashboard/")
      .then(setData)
      .catch(() => setError("Could not load the dashboard"));
  }, []);

  if (error) {
    return (
      <>
        <PageHeader title="Dashboard" description="Tenant-wide posture and compliance metrics" />
        <PageContainer><p className="text-sm text-destructive">{error}</p></PageContainer>
      </>
    );
  }
  if (!data) return null;

  const controlCount = Object.keys(data.control_health).length;
  const frameworkCount = Object.keys(data.framework_coverage).length;
  const isEmpty = data.posture.posture_pct === null && controlCount === 0 && data.high_finding_ageing.count === 0
    && data.overdue_tasks.count === 0 && data.audit_bottlenecks.count === 0;

  const severityCounts = SEVERITY_ORDER.map((sev) => ({
    severity: sev,
    count: data.high_finding_ageing.findings.filter((f) => f.severity === sev).length,
  }));

  return (
    <>
      <PageHeader title="Dashboard" description="Tenant-wide posture and compliance metrics" />
      <PageContainer>
        <div className="space-y-6">
          {isEmpty && <GettingStarted />}

          <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
            <PostureCard pct={data.posture.posture_pct} scored={data.posture.scored_count} excluded={data.posture.excluded_count} />

            <Card>
              <CardHeader className="flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium text-muted-foreground">High-severity findings</CardTitle>
                <FileWarning className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <p className="text-3xl font-semibold">{data.high_finding_ageing.count}</p>
                {data.high_finding_ageing.count === 0 ? (
                  <CardDescription>none open</CardDescription>
                ) : (
                  <div className="mt-2 space-y-1">
                    {severityCounts.filter((s) => s.count > 0).map((s) => (
                      <div key={s.severity} className="flex items-center gap-1.5 text-xs text-muted-foreground">
                        <span className={`h-1.5 w-1.5 rounded-full ${SEVERITY_DOT[s.severity]}`} />
                        {s.count} {s.severity}
                      </div>
                    ))}
                    <p className="text-xs text-muted-foreground">
                      oldest {data.high_finding_ageing.oldest_age_days}d open
                    </p>
                  </div>
                )}
                <Button asChild variant="link" className="h-auto p-0 text-xs"><Link to="/findings">View findings →</Link></Button>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium text-muted-foreground">Overdue tasks</CardTitle>
                <CheckSquare className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <p className="text-3xl font-semibold">{data.overdue_tasks.count}</p>
                <CardDescription>
                  {data.overdue_tasks.most_overdue_days != null ? `up to ${data.overdue_tasks.most_overdue_days}d overdue` : "none overdue"}
                </CardDescription>
                <Button asChild variant="link" className="h-auto p-0 text-xs"><Link to="/tasks">View tasks →</Link></Button>
              </CardContent>
            </Card>
          </div>

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
            <MiniMetric icon={ClipboardCheck} title="Audit bottlenecks" value={data.audit_bottlenecks.count}
                        detail={data.audit_bottlenecks.oldest_age_days != null ? `oldest ${data.audit_bottlenecks.oldest_age_days}d waiting` : "none waiting"}
                        to="/audits" warn={data.audit_bottlenecks.count > 0} />
            <MiniMetric icon={ShieldCheck} title="Controls tracked" value={controlCount}
                        detail="with a health rollup" to="/controls" />
            <MiniMetric icon={Gauge} title="Frameworks activated" value={frameworkCount}
                        detail="with a requirement resolved" />
          </div>
        </div>
      </PageContainer>
    </>
  );
}

function PostureCard({ pct, scored, excluded }: { pct: number | null; scored: number; excluded: number }) {
  const value = pct ?? 0;
  const color = pct == null ? "stroke-muted" : pct >= 80 ? "stroke-emerald-500" : pct >= 50 ? "stroke-amber-500" : "stroke-red-500";
  const circumference = 2 * Math.PI * 40;
  const offset = circumference - (value / 100) * circumference;

  return (
    <Card className="lg:col-span-1">
      <CardHeader><CardTitle className="text-sm font-medium text-muted-foreground">Overall posture</CardTitle></CardHeader>
      <CardContent className="flex items-center gap-4">
        <svg width="96" height="96" viewBox="0 0 96 96" className="shrink-0 -rotate-90">
          <circle cx="48" cy="48" r="40" fill="none" strokeWidth="8" className="stroke-muted" />
          {pct != null && (
            <circle cx="48" cy="48" r="40" fill="none" strokeWidth="8" strokeLinecap="round" className={color}
                    strokeDasharray={circumference} strokeDashoffset={offset} />
          )}
        </svg>
        <div>
          <p className="text-3xl font-semibold">{pct == null ? "—" : `${pct.toFixed(0)}%`}</p>
          <CardDescription>{scored} assertion(s) scored, {excluded} excluded</CardDescription>
        </div>
      </CardContent>
    </Card>
  );
}

function MiniMetric({ icon: Icon, title, value, detail, to, warn }: {
  icon: React.ElementType; title: string; value: number; detail: string; to?: string; warn?: boolean;
}) {
  const content = (
    <Card className={to ? "transition-shadow hover:shadow-md" : undefined}>
      <CardContent className="flex items-center gap-3 pt-6">
        <div className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-md ${warn ? "bg-orange-50 dark:bg-orange-950" : "bg-muted"}`}>
          <Icon className={`h-4 w-4 ${warn ? "text-orange-600 dark:text-orange-400" : "text-muted-foreground"}`} />
        </div>
        <div className="min-w-0">
          <p className="text-xl font-semibold">{value}</p>
          <p className="truncate text-xs text-muted-foreground">{title} · {detail}</p>
        </div>
      </CardContent>
    </Card>
  );
  return to ? <Link to={to}>{content}</Link> : content;
}

function GettingStarted() {
  return (
    <Card className="border-dashed bg-muted/30">
      <CardContent className="flex items-start gap-3 pt-6">
        <Sparkles className="mt-0.5 h-5 w-5 shrink-0 text-primary" />
        <div>
          <p className="font-medium">Nothing tracked yet</p>
          <p className="mt-1 text-sm text-muted-foreground">
            Every number below is a real, live query against this tenant's data - they're zero because
            nothing has been created yet, not because the dashboard isn't working. Start with a common
            control, then an implementation control, then assert it against a framework requirement.
          </p>
          <div className="mt-3 flex gap-2">
            <Button asChild size="sm"><Link to="/controls">Add your first control</Link></Button>
            <Button asChild size="sm" variant="outline"><Link to="/risk">Start a risk assessment</Link></Button>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
