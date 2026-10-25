import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { PageContainer, PageHeader } from "@/components/layout/PageHeader";
import { api } from "@/lib/api";
import type { DashboardResponse } from "@/lib/api";

export function DashboardPage() {
  const [data, setData] = useState<DashboardResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .get<DashboardResponse>("/tenant/reporting/dashboard/")
      .then(setData)
      .catch(() => setError("Could not load the dashboard"));
  }, []);

  return (
    <>
      <PageHeader title="Dashboard" description="Tenant-wide posture and compliance metrics" />
      <PageContainer>
        {error && <p className="text-sm text-destructive">{error}</p>}
        {data && (
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
            <Metric title="Posture" value={pct(data.posture.posture_pct)}
                    detail={`${data.posture.scored_count} assertion(s) scored, ${data.posture.excluded_count} excluded`} />
            <Metric title="High-finding ageing" value={String(data.high_finding_ageing.count)}
                    detail={data.high_finding_ageing.oldest_age_days != null
                      ? `oldest ${data.high_finding_ageing.oldest_age_days}d open` : "none open"}
                    to="/findings" />
            <Metric title="Overdue tasks" value={String(data.overdue_tasks.count)}
                    detail={data.overdue_tasks.most_overdue_days != null
                      ? `up to ${data.overdue_tasks.most_overdue_days}d overdue` : "none overdue"}
                    to="/tasks" />
            <Metric title="Audit bottlenecks" value={String(data.audit_bottlenecks.count)}
                    detail={data.audit_bottlenecks.oldest_age_days != null
                      ? `oldest ${data.audit_bottlenecks.oldest_age_days}d waiting` : "none waiting"}
                    to="/audits" />
            <Metric title="Controls tracked" value={String(Object.keys(data.control_health).length)}
                    detail="implementation controls with a health rollup" to="/controls" />
            <Metric title="Frameworks activated" value={String(Object.keys(data.framework_coverage).length)}
                    detail="with at least one requirement resolved" />
          </div>
        )}
      </PageContainer>
    </>
  );
}

function Metric({ title, value, detail, to }: { title: string; value: string; detail: string; to?: string }) {
  const card = (
    <Card className={to ? "transition-shadow hover:shadow-md" : undefined}>
      <CardHeader>
        <CardTitle className="text-sm font-medium text-muted-foreground">{title}</CardTitle>
      </CardHeader>
      <CardContent>
        <p className="text-3xl font-semibold">{value}</p>
        <CardDescription>{detail}</CardDescription>
      </CardContent>
    </Card>
  );
  return to ? <Link to={to}>{card}</Link> : card;
}

function pct(v: number | null): string {
  return v == null ? "—" : `${v.toFixed(0)}%`;
}
