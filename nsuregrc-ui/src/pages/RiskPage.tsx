import { useEffect, useState } from "react";
import { ShieldAlert } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageContainer, PageHeader } from "@/components/layout/PageHeader";
import { EmptyState } from "@/components/shared/EmptyState";
import { StatusBadge } from "@/components/shared/StatusBadge";
import { api, ApiError } from "@/lib/api";
import type { RiskAssessment, RiskScenario } from "@/lib/api";

const LEVEL_CLASSES: Record<string, string> = {
  low: "bg-blue-50 text-blue-700 border-blue-200 dark:bg-blue-950 dark:text-blue-300 dark:border-blue-900",
  medium: "bg-amber-50 text-amber-700 border-amber-200 dark:bg-amber-950 dark:text-amber-300 dark:border-amber-900",
  high: "bg-orange-50 text-orange-700 border-orange-200 dark:bg-orange-950 dark:text-orange-300 dark:border-orange-900",
  critical: "bg-red-50 text-red-700 border-red-200 dark:bg-red-950 dark:text-red-300 dark:border-red-900",
};

const NEXT_STATUS: Record<string, string> = { open: "treating", treating: "closed" };

export function RiskPage() {
  const [assessments, setAssessments] = useState<RiskAssessment[]>([]);
  const [scenarios, setScenarios] = useState<RiskScenario[]>([]);
  const [loading, setLoading] = useState(true);
  const [assessmentOpen, setAssessmentOpen] = useState(false);
  const [scenarioOpen, setScenarioOpen] = useState(false);

  function reload() {
    Promise.all([
      api.get<{ results: RiskAssessment[] }>("/tenant/risk/assessments/"),
      api.get<{ results: RiskScenario[] }>("/tenant/risk/scenarios/"),
    ]).then(([a, s]) => {
      setAssessments(a.results);
      setScenarios(s.results);
      setLoading(false);
    });
  }

  useEffect(reload, []);

  async function advance(s: RiskScenario) {
    const next = NEXT_STATUS[s.status];
    if (!next) return;
    await api.post(`/tenant/risk/scenarios/${s.id}/transition/`, { status: next });
    reload();
  }

  if (loading) return null;

  return (
    <>
      <PageHeader title="Risk Register" description="Risk scenarios scored by likelihood x impact (ISO 27005)"
                  actions={
                    <>
                      <Button variant="outline" onClick={() => setAssessmentOpen(true)}>New assessment</Button>
                      <Button onClick={() => setScenarioOpen(true)} disabled={assessments.length === 0}>New scenario</Button>
                    </>
                  } />
      <PageContainer>
        {scenarios.length === 0 ? (
          <EmptyState icon={ShieldAlert} title="No risk scenarios yet"
                      description={assessments.length === 0 ? "Create a risk assessment first." : "Add a scenario to start scoring risk."} />
        ) : (
          <Table>
            <TableHeader>
              <TableRow><TableHead>Scenario</TableHead><TableHead>Level</TableHead><TableHead>Treatment</TableHead><TableHead>Status</TableHead><TableHead /></TableRow>
            </TableHeader>
            <TableBody>
              {scenarios.map((s) => (
                <TableRow key={s.id}>
                  <TableCell className="font-medium">{s.name}</TableCell>
                  <TableCell>
                    <Badge variant="outline" className={LEVEL_CLASSES[s.risk_level] ?? ""}>
                      {s.risk_level} ({s.likelihood}x{s.impact})
                    </Badge>
                  </TableCell>
                  <TableCell className="text-muted-foreground">{s.treatment ?? "—"}</TableCell>
                  <TableCell><StatusBadge status={s.status} /></TableCell>
                  <TableCell className="text-right">
                    {NEXT_STATUS[s.status] && (
                      <Button variant="outline" size="sm" onClick={() => void advance(s)}>
                        Move to {NEXT_STATUS[s.status]}
                      </Button>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </PageContainer>

      <NewAssessmentDialog open={assessmentOpen} onOpenChange={setAssessmentOpen} onCreated={reload} />
      <NewScenarioDialog open={scenarioOpen} onOpenChange={setScenarioOpen} onCreated={reload} assessments={assessments} />
    </>
  );
}

function NewAssessmentDialog({ open, onOpenChange, onCreated }: { open: boolean; onOpenChange: (v: boolean) => void; onCreated: () => void }) {
  const [name, setName] = useState("");
  const [error, setError] = useState<string | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      await api.post("/tenant/risk/assessments/", { name });
      setName("");
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
          <DialogHeader><DialogTitle>New risk assessment</DialogTitle></DialogHeader>
          <div className="space-y-3 py-4">
            <div className="space-y-1.5">
              <Label htmlFor="ra-name">Name</Label>
              <Input id="ra-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="Q1 2027 risk assessment" required />
            </div>
            {error && <p className="text-sm text-destructive">{error}</p>}
          </div>
          <DialogFooter><Button type="submit">Create</Button></DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function NewScenarioDialog({ open, onOpenChange, onCreated, assessments }: {
  open: boolean; onOpenChange: (v: boolean) => void; onCreated: () => void; assessments: RiskAssessment[];
}) {
  const [assessmentId, setAssessmentId] = useState("");
  const [name, setName] = useState("");
  const [likelihood, setLikelihood] = useState("3");
  const [impact, setImpact] = useState("3");
  const [error, setError] = useState<string | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      await api.post("/tenant/risk/scenarios/", {
        risk_assessment: assessmentId, name, likelihood: Number(likelihood), impact: Number(impact),
      });
      setName("");
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
          <DialogHeader><DialogTitle>New risk scenario</DialogTitle></DialogHeader>
          <div className="space-y-3 py-4">
            <div className="space-y-1.5">
              <Label>Risk assessment</Label>
              <Select value={assessmentId} onValueChange={setAssessmentId}>
                <SelectTrigger className="w-full"><SelectValue placeholder="Select an assessment" /></SelectTrigger>
                <SelectContent>
                  {assessments.map((a) => <SelectItem key={a.id} value={a.id}>{a.name}</SelectItem>)}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="rs-name">Scenario</Label>
              <Input id="rs-name" value={name} onChange={(e) => setName(e.target.value)} required />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label>Likelihood (1-5)</Label>
                <Select value={likelihood} onValueChange={setLikelihood}>
                  <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
                  <SelectContent>{[1, 2, 3, 4, 5].map((n) => <SelectItem key={n} value={String(n)}>{n}</SelectItem>)}</SelectContent>
                </Select>
              </div>
              <div className="space-y-1.5">
                <Label>Impact (1-5)</Label>
                <Select value={impact} onValueChange={setImpact}>
                  <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
                  <SelectContent>{[1, 2, 3, 4, 5].map((n) => <SelectItem key={n} value={String(n)}>{n}</SelectItem>)}</SelectContent>
                </Select>
              </div>
            </div>
            {error && <p className="text-sm text-destructive">{error}</p>}
          </div>
          <DialogFooter><Button type="submit" disabled={!assessmentId}>Create</Button></DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
