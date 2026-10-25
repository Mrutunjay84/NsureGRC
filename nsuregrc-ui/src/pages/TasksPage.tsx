import { useEffect, useState } from "react";
import { CheckSquare } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { StatusBadge } from "@/components/shared/StatusBadge";
import { PageContainer, PageHeader } from "@/components/layout/PageHeader";
import { EmptyState } from "@/components/shared/EmptyState";
import { api } from "@/lib/api";
import type { Task } from "@/lib/api";

export function TasksPage() {
  const [tasks, setTasks] = useState<Task[]>([]);
  const [loading, setLoading] = useState(true);

  function reload() {
    api.get<{ results: Task[] }>("/tenant/tasks/").then((r) => {
      setTasks(r.results);
      setLoading(false);
    });
  }

  useEffect(reload, []);

  async function transition(t: Task, status: string) {
    await api.post(`/tenant/tasks/${t.id}/transition/`, { status });
    reload();
  }

  if (loading) return null;

  return (
    <>
      <PageHeader title="Tasks" description="Assignable units of work against implementation controls" />
      <PageContainer>
        {tasks.length === 0 ? (
          <EmptyState icon={CheckSquare} title="No tasks" description="Tasks created on a control will show up here." />
        ) : (
          <Table>
            <TableHeader>
              <TableRow><TableHead>Title</TableHead><TableHead>Status</TableHead><TableHead>Due</TableHead><TableHead /></TableRow>
            </TableHeader>
            <TableBody>
              {tasks.map((t) => (
                <TableRow key={t.id}>
                  <TableCell className="font-medium">{t.title}</TableCell>
                  <TableCell><StatusBadge status={t.status} /></TableCell>
                  <TableCell className="text-muted-foreground">{t.due_date ?? "—"}</TableCell>
                  <TableCell className="text-right">
                    {t.status === "open" && (
                      <Button variant="outline" size="sm" onClick={() => void transition(t, "in_progress")}>Start</Button>
                    )}
                    {t.status === "in_progress" && (
                      <Button variant="outline" size="sm" onClick={() => void transition(t, "done")}>Mark done</Button>
                    )}
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
