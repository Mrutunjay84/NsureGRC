import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { api } from "@/lib/api";
import type { DashboardResponse } from "@/lib/api";

export function DashboardPage({ onLoggedOut }: { onLoggedOut: () => void }) {
  const [data, setData] = useState<DashboardResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .get<DashboardResponse>("/tenant/reporting/dashboard/")
      .then(setData)
      .catch(() => setError("Could not load the dashboard"));
  }, []);

  async function logout() {
    await api.post("/auth/logout/");
    onLoggedOut();
  }

  return (
    <div className="min-h-svh bg-background p-6">
      <div className="mx-auto flex max-w-5xl flex-col gap-6">
        <div className="flex items-center justify-between">
          <h1 className="text-xl font-semibold">Dashboard</h1>
          <Button variant="outline" onClick={() => void logout()}>Log out</Button>
        </div>

        {error && <p className="text-sm text-destructive">{error}</p>}

        {data && (
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
            <Metric title="Posture" value={pct(data.posture.posture_pct)}
                    detail={`${data.posture.scored_count} assertion(s) scored, ${data.posture.excluded_count} excluded`} />
            <Metric title="High-finding ageing" value={String(data.high_finding_ageing.count)}
                    detail={data.high_finding_ageing.oldest_age_days != null
                      ? `oldest ${data.high_finding_ageing.oldest_age_days}d open` : "none open"} />
            <Metric title="Overdue tasks" value={String(data.overdue_tasks.count)}
                    detail={data.overdue_tasks.most_overdue_days != null
                      ? `up to ${data.overdue_tasks.most_overdue_days}d overdue` : "none overdue"} />
            <Metric title="Audit bottlenecks" value={String(data.audit_bottlenecks.count)}
                    detail={data.audit_bottlenecks.oldest_age_days != null
                      ? `oldest ${data.audit_bottlenecks.oldest_age_days}d waiting` : "none waiting"} />
            <Metric title="Controls tracked" value={String(Object.keys(data.control_health).length)}
                    detail="implementation controls with a health rollup" />
            <Metric title="Frameworks activated" value={String(Object.keys(data.framework_coverage).length)}
                    detail="with at least one requirement resolved" />
          </div>
        )}
      </div>
    </div>
  );
}

function Metric({ title, value, detail }: { title: string; value: string; detail: string }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm font-medium text-muted-foreground">{title}</CardTitle>
      </CardHeader>
      <CardContent>
        <p className="text-3xl font-semibold">{value}</p>
        <CardDescription>{detail}</CardDescription>
      </CardContent>
    </Card>
  );
}

function pct(v: number | null): string {
  return v == null ? "—" : `${v.toFixed(0)}%`;
}
