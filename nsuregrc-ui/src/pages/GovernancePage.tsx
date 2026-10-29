import { useEffect, useState } from "react";
import { Scale } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageContainer, PageHeader } from "@/components/layout/PageHeader";
import { EmptyState } from "@/components/shared/EmptyState";
import { SeverityBadge, StatusBadge } from "@/components/shared/StatusBadge";
import { api, ApiError } from "@/lib/api";
import type { Issue, Objective, Policy } from "@/lib/api";

const NEXT_ISSUE_STATUS: Record<string, string> = { open: "in_progress", in_progress: "resolved", resolved: "closed" };

export function GovernancePage() {
  const [tab, setTab] = useState("policies");
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [objectives, setObjectives] = useState<Objective[]>([]);
  const [issues, setIssues] = useState<Issue[]>([]);
  const [loading, setLoading] = useState(true);
  const [dialog, setDialog] = useState<"policy" | "objective" | "issue" | null>(null);

  function reload() {
    Promise.all([
      api.get<{ results: Policy[] }>("/tenant/governance/policies/"),
      api.get<{ results: Objective[] }>("/tenant/governance/objectives/"),
      api.get<{ results: Issue[] }>("/tenant/governance/issues/"),
    ]).then(([p, o, i]) => {
      setPolicies(p.results);
      setObjectives(o.results);
      setIssues(i.results);
      setLoading(false);
    });
  }

  useEffect(reload, []);

  async function advanceIssue(issue: Issue) {
    const next = NEXT_ISSUE_STATUS[issue.status];
    if (!next) return;
    await api.post(`/tenant/governance/issues/${issue.id}/transition/`, { status: next });
    reload();
  }

  if (loading) return null;

  const actionFor: Record<string, { label: string; kind: "policy" | "objective" | "issue" }> = {
    policies: { label: "New policy", kind: "policy" },
    objectives: { label: "New objective", kind: "objective" },
    issues: { label: "New issue", kind: "issue" },
  };

  return (
    <>
      <PageHeader title="Policies & Objectives" description="Governance documents, goals and open issues"
                  actions={<Button onClick={() => setDialog(actionFor[tab].kind)}>{actionFor[tab].label}</Button>} />
      <PageContainer>
        <Tabs value={tab} onValueChange={setTab}>
          <TabsList>
            <TabsTrigger value="policies">Policies ({policies.length})</TabsTrigger>
            <TabsTrigger value="objectives">Objectives ({objectives.length})</TabsTrigger>
            <TabsTrigger value="issues">Issues ({issues.length})</TabsTrigger>
          </TabsList>

          <TabsContent value="policies">
            {policies.length === 0 ? <EmptyState icon={Scale} title="No policies" description="Create a governance policy document." /> : (
              <Table>
                <TableHeader><TableRow><TableHead>Title</TableHead><TableHead>Status</TableHead><TableHead>Next review</TableHead></TableRow></TableHeader>
                <TableBody>
                  {policies.map((p) => (
                    <TableRow key={p.id}>
                      <TableCell className="font-medium">{p.title}</TableCell>
                      <TableCell><StatusBadge status={p.status} /></TableCell>
                      <TableCell className="text-muted-foreground">{p.next_review_date ?? "—"}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </TabsContent>

          <TabsContent value="objectives">
            {objectives.length === 0 ? <EmptyState icon={Scale} title="No objectives" description="Track a governance goal." /> : (
              <Table>
                <TableHeader><TableRow><TableHead>Title</TableHead><TableHead>Status</TableHead><TableHead>Target date</TableHead></TableRow></TableHeader>
                <TableBody>
                  {objectives.map((o) => (
                    <TableRow key={o.id}>
                      <TableCell className="font-medium">{o.title}</TableCell>
                      <TableCell><StatusBadge status={o.status} /></TableCell>
                      <TableCell className="text-muted-foreground">{o.target_date ?? "—"}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </TabsContent>

          <TabsContent value="issues">
            {issues.length === 0 ? <EmptyState icon={Scale} title="No issues" description="Raise a governance concern not tied to one control." /> : (
              <Table>
                <TableHeader><TableRow><TableHead>Title</TableHead><TableHead>Severity</TableHead><TableHead>Status</TableHead><TableHead /></TableRow></TableHeader>
                <TableBody>
                  {issues.map((i) => (
                    <TableRow key={i.id}>
                      <TableCell className="font-medium">{i.title}</TableCell>
                      <TableCell><SeverityBadge severity={i.severity} /></TableCell>
                      <TableCell><StatusBadge status={i.status} /></TableCell>
                      <TableCell className="text-right">
                        {NEXT_ISSUE_STATUS[i.status] && (
                          <Button variant="outline" size="sm" onClick={() => void advanceIssue(i)}>
                            Move to {NEXT_ISSUE_STATUS[i.status].replaceAll("_", " ")}
                          </Button>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </TabsContent>
        </Tabs>
      </PageContainer>

      <NewPolicyDialog open={dialog === "policy"} onOpenChange={(v) => !v && setDialog(null)} onCreated={reload} />
      <NewObjectiveDialog open={dialog === "objective"} onOpenChange={(v) => !v && setDialog(null)} onCreated={reload} />
      <NewIssueDialog open={dialog === "issue"} onOpenChange={(v) => !v && setDialog(null)} onCreated={reload} />
    </>
  );
}

function NewPolicyDialog({ open, onOpenChange, onCreated }: { open: boolean; onOpenChange: (v: boolean) => void; onCreated: () => void }) {
  const [title, setTitle] = useState("");
  const [error, setError] = useState<string | null>(null);
  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      await api.post("/tenant/governance/policies/", { title });
      setTitle("");
      onOpenChange(false);
      onCreated();
    } catch (err) {
      setError(err instanceof ApiError ? `Request failed (${err.status})` : "Failed");
    }
  }
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <form onSubmit={submit}>
          <DialogHeader><DialogTitle>New policy</DialogTitle></DialogHeader>
          <div className="space-y-3 py-4">
            <div className="space-y-1.5"><Label htmlFor="p-title">Title</Label><Input id="p-title" value={title} onChange={(e) => setTitle(e.target.value)} required /></div>
            {error && <p className="text-sm text-destructive">{error}</p>}
          </div>
          <DialogFooter><Button type="submit">Create</Button></DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function NewObjectiveDialog({ open, onOpenChange, onCreated }: { open: boolean; onOpenChange: (v: boolean) => void; onCreated: () => void }) {
  const [title, setTitle] = useState("");
  const [error, setError] = useState<string | null>(null);
  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      await api.post("/tenant/governance/objectives/", { title });
      setTitle("");
      onOpenChange(false);
      onCreated();
    } catch (err) {
      setError(err instanceof ApiError ? `Request failed (${err.status})` : "Failed");
    }
  }
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <form onSubmit={submit}>
          <DialogHeader><DialogTitle>New objective</DialogTitle></DialogHeader>
          <div className="space-y-3 py-4">
            <div className="space-y-1.5"><Label htmlFor="o-title">Title</Label><Input id="o-title" value={title} onChange={(e) => setTitle(e.target.value)} required /></div>
            {error && <p className="text-sm text-destructive">{error}</p>}
          </div>
          <DialogFooter><Button type="submit">Create</Button></DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function NewIssueDialog({ open, onOpenChange, onCreated }: { open: boolean; onOpenChange: (v: boolean) => void; onCreated: () => void }) {
  const [title, setTitle] = useState("");
  const [severity, setSeverity] = useState("medium");
  const [error, setError] = useState<string | null>(null);
  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      await api.post("/tenant/governance/issues/", { title, severity });
      setTitle("");
      onOpenChange(false);
      onCreated();
    } catch (err) {
      setError(err instanceof ApiError ? `Request failed (${err.status})` : "Failed");
    }
  }
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <form onSubmit={submit}>
          <DialogHeader><DialogTitle>New issue</DialogTitle></DialogHeader>
          <div className="space-y-3 py-4">
            <div className="space-y-1.5"><Label htmlFor="i-title">Title</Label><Input id="i-title" value={title} onChange={(e) => setTitle(e.target.value)} required /></div>
            <div className="space-y-1.5">
              <Label>Severity</Label>
              <Select value={severity} onValueChange={setSeverity}>
                <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
                <SelectContent>{["low", "medium", "high", "critical"].map((s) => <SelectItem key={s} value={s}>{s}</SelectItem>)}</SelectContent>
              </Select>
            </div>
            {error && <p className="text-sm text-destructive">{error}</p>}
          </div>
          <DialogFooter><Button type="submit">Create</Button></DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
