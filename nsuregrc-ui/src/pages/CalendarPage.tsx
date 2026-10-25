import { useEffect, useState } from "react";
import { CalendarClock } from "lucide-react";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageContainer, PageHeader } from "@/components/layout/PageHeader";
import { EmptyState } from "@/components/shared/EmptyState";
import { api } from "@/lib/api";
import type { CalendarResponse, Deadline } from "@/lib/api";

const DOMAIN_LABEL: Record<Deadline["domain"], string> = {
  controls: "Controls", risk: "Risk", governance: "Governance", privacy: "Privacy",
};

const WINDOW_OPTIONS = [30, 90, 180, 365];

function labelizeObjectType(value: string): string {
  return value.replaceAll("_", " ");
}

export function CalendarPage() {
  const [windowDays, setWindowDays] = useState(90);
  const [deadlines, setDeadlines] = useState<Deadline[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api
      .get<CalendarResponse>(`/tenant/reporting/calendar/?window_days=${windowDays}`)
      .then((r) => {
        setDeadlines(r.deadlines);
        setLoading(false);
      });
  }, [windowDays]);

  if (loading) return null;

  return (
    <>
      <PageHeader
        title="Calendar"
        description="Upcoming and overdue deadlines across tasks, control plans, exceptions, risk acceptances, policies, objectives, issues and rights requests"
        actions={
          <Select value={String(windowDays)} onValueChange={(v) => setWindowDays(Number(v))}>
            <SelectTrigger className="w-40"><SelectValue /></SelectTrigger>
            <SelectContent>
              {WINDOW_OPTIONS.map((d) => <SelectItem key={d} value={String(d)}>Next {d} days</SelectItem>)}
            </SelectContent>
          </Select>
        }
      />
      <PageContainer>
        {deadlines.length === 0 ? (
          <EmptyState icon={CalendarClock} title="No deadlines"
                      description="Nothing overdue, and nothing due in the selected window." />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Date</TableHead>
                <TableHead>Domain</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Title</TableHead>
                <TableHead />
              </TableRow>
            </TableHeader>
            <TableBody>
              {deadlines.map((d) => (
                <TableRow key={`${d.object_type}-${d.object_id}`}>
                  <TableCell className={d.overdue ? "font-medium text-destructive" : "font-medium"}>
                    {new Date(d.date).toLocaleDateString()}
                  </TableCell>
                  <TableCell className="text-muted-foreground">{DOMAIN_LABEL[d.domain]}</TableCell>
                  <TableCell className="text-muted-foreground">{labelizeObjectType(d.object_type)}</TableCell>
                  <TableCell>{d.title}</TableCell>
                  <TableCell className="text-right">
                    {d.overdue && <Badge variant="outline" className="border-destructive/30 text-destructive">Overdue</Badge>}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </PageContainer>
    </>
  );
}
