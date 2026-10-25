import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { PageContainer, PageHeader } from "@/components/layout/PageHeader";
import { SeverityBadge, StatusBadge } from "@/components/shared/StatusBadge";
import { api, ApiError } from "@/lib/api";
import type { ImplementationControlDetail } from "@/lib/api";

export function ControlDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [control, setControl] = useState<ImplementationControlDetail | null>(null);
  const [assertOpen, setAssertOpen] = useState(false);
  const [findingOpen, setFindingOpen] = useState(false);
  const [taskOpen, setTaskOpen] = useState(false);

  function reload() {
    if (id) api.get<ImplementationControlDetail>(`/tenant/controls/implementation/${id}/`).then(setControl);
  }

  useEffect(reload, [id]);

  if (!control) return null;

  return (
    <>
      <PageHeader title={control.name} description={control.common_control_name}
                  actions={
                    <>
                      <Button variant="outline" onClick={() => setTaskOpen(true)}>New task</Button>
                      <Button variant="outline" onClick={() => setFindingOpen(true)}>Raise finding</Button>
                      <Button onClick={() => setAssertOpen(true)}>Assert against framework</Button>
                    </>
                  } />
      <PageContainer>
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
          <Section title="Assertions" count={control.assertions.length}>
            {control.assertions.length === 0 ? <Empty text="Not asserted against any framework yet" /> : (
              <ul className="space-y-2">
                {control.assertions.map((a) => (
                  <li key={a.id} className="rounded-md border p-3 text-sm">
                    <p className="font-medium">{a.framework_urn} / {a.requirement_urn}</p>
                    <div className="mt-1"><StatusBadge status={a.satisfaction_state} /></div>
                  </li>
                ))}
              </ul>
            )}
          </Section>

          <Section title="Findings" count={control.findings.length}>
            {control.findings.length === 0 ? <Empty text="No findings raised" /> : (
              <ul className="space-y-2">
                {control.findings.map((f) => (
                  <li key={f.id} className="rounded-md border p-3 text-sm">
                    <p className="font-medium">{f.title}</p>
                    <div className="mt-1 flex gap-1.5"><SeverityBadge severity={f.severity} /><StatusBadge status={f.status} /></div>
                  </li>
                ))}
              </ul>
            )}
          </Section>

          <Section title="Tasks" count={control.tasks.length}>
            {control.tasks.length === 0 ? <Empty text="No tasks" /> : (
              <ul className="space-y-2">
                {control.tasks.map((t) => (
                  <li key={t.id} className="rounded-md border p-3 text-sm">
                    <p className="font-medium">{t.title}</p>
                    <div className="mt-1"><StatusBadge status={t.status} /></div>
                  </li>
                ))}
              </ul>
            )}
          </Section>
        </div>
      </PageContainer>

      <AssertDialog open={assertOpen} onOpenChange={setAssertOpen} controlId={control.id} onDone={reload} />
      <FindingDialog open={findingOpen} onOpenChange={setFindingOpen} controlId={control.id} onDone={reload} />
      <TaskDialog open={taskOpen} onOpenChange={setTaskOpen} controlId={control.id} onDone={reload} />
    </>
  );
}

function Section({ title, count, children }: { title: string; count: number; children: React.ReactNode }) {
  return (
    <Card>
      <CardHeader><CardTitle className="text-sm font-medium">{title} ({count})</CardTitle></CardHeader>
      <CardContent>{children}</CardContent>
    </Card>
  );
}

function Empty({ text }: { text: string }) {
  return <p className="text-sm text-muted-foreground">{text}</p>;
}

function AssertDialog({ open, onOpenChange, controlId, onDone }: {
  open: boolean; onOpenChange: (v: boolean) => void; controlId: string; onDone: () => void;
}) {
  const [frameworkUrn, setFrameworkUrn] = useState("");
  const [requirementUrn, setRequirementUrn] = useState("");
  const [error, setError] = useState<string | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      await api.post(`/tenant/controls/implementation/${controlId}/assert/`,
        { framework_urn: frameworkUrn, requirement_urn: requirementUrn });
      setFrameworkUrn("");
      setRequirementUrn("");
      onOpenChange(false);
      onDone();
    } catch (err) {
      setError(describeError(err));
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <form onSubmit={submit}>
          <DialogHeader><DialogTitle>Assert against a framework requirement</DialogTitle></DialogHeader>
          <div className="space-y-3 py-4">
            <div className="space-y-1.5">
              <Label htmlFor="fw-urn">Framework URN</Label>
              <Input id="fw-urn" value={frameworkUrn} onChange={(e) => setFrameworkUrn(e.target.value)} required />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="req-urn">Requirement URN</Label>
              <Input id="req-urn" value={requirementUrn} onChange={(e) => setRequirementUrn(e.target.value)} required />
            </div>
            {error && <p className="text-sm text-destructive">{error}</p>}
            <p className="text-xs text-muted-foreground">
              Fails if this tenant hasn't activated the framework yet, or the requirement URN doesn't resolve.
            </p>
          </div>
          <DialogFooter><Button type="submit">Assert</Button></DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function FindingDialog({ open, onOpenChange, controlId, onDone }: {
  open: boolean; onOpenChange: (v: boolean) => void; controlId: string; onDone: () => void;
}) {
  const [title, setTitle] = useState("");
  const [severity, setSeverity] = useState("medium");
  const [source, setSource] = useState("manual");
  const [error, setError] = useState<string | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      await api.post("/tenant/findings/", { implementation_control: controlId, title, severity, source });
      setTitle("");
      onOpenChange(false);
      onDone();
    } catch (err) {
      setError(describeError(err));
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <form onSubmit={submit}>
          <DialogHeader><DialogTitle>Raise a finding</DialogTitle></DialogHeader>
          <div className="space-y-3 py-4">
            <div className="space-y-1.5">
              <Label htmlFor="f-title">Title</Label>
              <Input id="f-title" value={title} onChange={(e) => setTitle(e.target.value)} required />
            </div>
            <div className="space-y-1.5">
              <Label>Severity</Label>
              <Select value={severity} onValueChange={setSeverity}>
                <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
                <SelectContent>
                  {["low", "medium", "high", "critical"].map((s) => <SelectItem key={s} value={s}>{s}</SelectItem>)}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <Label>Source</Label>
              <Select value={source} onValueChange={setSource}>
                <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
                <SelectContent>
                  {["test", "audit", "risk", "manual", "integration", "ai_proposal"].map((s) => <SelectItem key={s} value={s}>{s}</SelectItem>)}
                </SelectContent>
              </Select>
            </div>
            {error && <p className="text-sm text-destructive">{error}</p>}
          </div>
          <DialogFooter><Button type="submit">Raise</Button></DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function TaskDialog({ open, onOpenChange, controlId, onDone }: {
  open: boolean; onOpenChange: (v: boolean) => void; controlId: string; onDone: () => void;
}) {
  const [title, setTitle] = useState("");
  const [error, setError] = useState<string | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      await api.post("/tenant/tasks/", { implementation_control: controlId, title });
      setTitle("");
      onOpenChange(false);
      onDone();
    } catch (err) {
      setError(describeError(err));
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <form onSubmit={submit}>
          <DialogHeader><DialogTitle>New task</DialogTitle></DialogHeader>
          <div className="space-y-3 py-4">
            <div className="space-y-1.5">
              <Label htmlFor="t-title">Title</Label>
              <Input id="t-title" value={title} onChange={(e) => setTitle(e.target.value)} required />
            </div>
            {error && <p className="text-sm text-destructive">{error}</p>}
          </div>
          <DialogFooter><Button type="submit">Create</Button></DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function describeError(err: unknown): string {
  if (err instanceof ApiError) {
    const body = err.body as { error?: string } | null;
    return body?.error ?? `Request failed (${err.status})`;
  }
  return "Something went wrong";
}
