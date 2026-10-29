import { useEffect, useState } from "react";
import { Lock } from "lucide-react";
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
import type { Breach, ProcessingActivity, RightsRequest } from "@/lib/api";

const NEXT_REQUEST_STATUS: Record<string, string> = { received: "in_progress", in_progress: "fulfilled" };
const NEXT_BREACH_STATUS: Record<string, string> = { open: "investigating", investigating: "contained", contained: "notified", notified: "closed" };

export function PrivacyPage() {
  const [tab, setTab] = useState("activities");
  const [activities, setActivities] = useState<ProcessingActivity[]>([]);
  const [requests, setRequests] = useState<RightsRequest[]>([]);
  const [breaches, setBreaches] = useState<Breach[]>([]);
  const [loading, setLoading] = useState(true);
  const [dialog, setDialog] = useState<"activity" | "request" | "breach" | null>(null);

  function reload() {
    Promise.all([
      api.get<{ results: ProcessingActivity[] }>("/tenant/privacy/processing-activities/"),
      api.get<{ results: RightsRequest[] }>("/tenant/privacy/rights-requests/"),
      api.get<{ results: Breach[] }>("/tenant/privacy/breaches/"),
    ]).then(([a, r, b]) => {
      setActivities(a.results);
      setRequests(r.results);
      setBreaches(b.results);
      setLoading(false);
    });
  }

  useEffect(reload, []);

  async function advanceRequest(r: RightsRequest) {
    const next = NEXT_REQUEST_STATUS[r.status];
    if (!next) return;
    await api.post(`/tenant/privacy/rights-requests/${r.id}/transition/`, { status: next });
    reload();
  }

  async function advanceBreach(b: Breach) {
    const next = NEXT_BREACH_STATUS[b.status];
    if (!next) return;
    await api.post(`/tenant/privacy/breaches/${b.id}/transition/`, { status: next });
    reload();
  }

  if (loading) return null;

  const actionFor: Record<string, { label: string; kind: "activity" | "request" | "breach" }> = {
    activities: { label: "New processing activity", kind: "activity" },
    requests: { label: "New rights request", kind: "request" },
    breaches: { label: "Report a breach", kind: "breach" },
  };

  return (
    <>
      <PageHeader title="Privacy" description="GDPR records of processing, data-subject requests and breach notifications"
                  actions={<Button onClick={() => setDialog(actionFor[tab].kind)}>{actionFor[tab].label}</Button>} />
      <PageContainer>
        <Tabs value={tab} onValueChange={setTab}>
          <TabsList>
            <TabsTrigger value="activities">Processing activities ({activities.length})</TabsTrigger>
            <TabsTrigger value="requests">Rights requests ({requests.length})</TabsTrigger>
            <TabsTrigger value="breaches">Breaches ({breaches.length})</TabsTrigger>
          </TabsList>

          <TabsContent value="activities">
            {activities.length === 0 ? <EmptyState icon={Lock} title="No processing activities" description="Start a Record of Processing Activities entry." /> : (
              <Table>
                <TableHeader><TableRow><TableHead>Name</TableHead><TableHead>Role</TableHead><TableHead>Status</TableHead></TableRow></TableHeader>
                <TableBody>
                  {activities.map((a) => (
                    <TableRow key={a.id}>
                      <TableCell className="font-medium">{a.name}</TableCell>
                      <TableCell className="text-muted-foreground">{a.role}</TableCell>
                      <TableCell><StatusBadge status={a.status} /></TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </TabsContent>

          <TabsContent value="requests">
            {requests.length === 0 ? <EmptyState icon={Lock} title="No rights requests" description="Log a data-subject rights request (access, erasure, etc.)." /> : (
              <Table>
                <TableHeader><TableRow><TableHead>Reference</TableHead><TableHead>Type</TableHead><TableHead>Status</TableHead><TableHead /></TableRow></TableHeader>
                <TableBody>
                  {requests.map((r) => (
                    <TableRow key={r.id}>
                      <TableCell className="font-medium">{r.requester_reference}</TableCell>
                      <TableCell className="text-muted-foreground">{r.request_type}</TableCell>
                      <TableCell><StatusBadge status={r.status} /></TableCell>
                      <TableCell className="text-right">
                        {NEXT_REQUEST_STATUS[r.status] && (
                          <Button variant="outline" size="sm" onClick={() => void advanceRequest(r)}>
                            Move to {NEXT_REQUEST_STATUS[r.status].replaceAll("_", " ")}
                          </Button>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </TabsContent>

          <TabsContent value="breaches">
            {breaches.length === 0 ? <EmptyState icon={Lock} title="No breaches recorded" description="This list should stay empty." /> : (
              <Table>
                <TableHeader><TableRow><TableHead>Title</TableHead><TableHead>Severity</TableHead><TableHead>Status</TableHead><TableHead /></TableRow></TableHeader>
                <TableBody>
                  {breaches.map((b) => (
                    <TableRow key={b.id}>
                      <TableCell className="font-medium">{b.title}</TableCell>
                      <TableCell><SeverityBadge severity={b.severity} /></TableCell>
                      <TableCell><StatusBadge status={b.status} /></TableCell>
                      <TableCell className="text-right">
                        {NEXT_BREACH_STATUS[b.status] && (
                          <Button variant="outline" size="sm" onClick={() => void advanceBreach(b)}>
                            Move to {NEXT_BREACH_STATUS[b.status]}
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

      <NewActivityDialog open={dialog === "activity"} onOpenChange={(v) => !v && setDialog(null)} onCreated={reload} />
      <NewRequestDialog open={dialog === "request"} onOpenChange={(v) => !v && setDialog(null)} onCreated={reload} />
      <NewBreachDialog open={dialog === "breach"} onOpenChange={(v) => !v && setDialog(null)} onCreated={reload} />
    </>
  );
}

function NewActivityDialog({ open, onOpenChange, onCreated }: { open: boolean; onOpenChange: (v: boolean) => void; onCreated: () => void }) {
  const [name, setName] = useState("");
  const [role, setRole] = useState("controller");
  const [error, setError] = useState<string | null>(null);
  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      await api.post("/tenant/privacy/processing-activities/", { name, role });
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
          <DialogHeader><DialogTitle>New processing activity</DialogTitle></DialogHeader>
          <div className="space-y-3 py-4">
            <div className="space-y-1.5"><Label htmlFor="pa-name">Name</Label><Input id="pa-name" value={name} onChange={(e) => setName(e.target.value)} required /></div>
            <div className="space-y-1.5">
              <Label>Role</Label>
              <Select value={role} onValueChange={setRole}>
                <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
                <SelectContent><SelectItem value="controller">Controller</SelectItem><SelectItem value="processor">Processor</SelectItem></SelectContent>
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

function NewRequestDialog({ open, onOpenChange, onCreated }: { open: boolean; onOpenChange: (v: boolean) => void; onCreated: () => void }) {
  const [reference, setReference] = useState("");
  const [requestType, setRequestType] = useState("access");
  const [error, setError] = useState<string | null>(null);
  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      await api.post("/tenant/privacy/rights-requests/", { requester_reference: reference, request_type: requestType });
      setReference("");
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
          <DialogHeader><DialogTitle>New rights request</DialogTitle></DialogHeader>
          <div className="space-y-3 py-4">
            <div className="space-y-1.5">
              <Label htmlFor="rr-ref">Case reference</Label>
              <Input id="rr-ref" value={reference} onChange={(e) => setReference(e.target.value)} placeholder="Never raw data-subject PII" required />
            </div>
            <div className="space-y-1.5">
              <Label>Request type</Label>
              <Select value={requestType} onValueChange={setRequestType}>
                <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
                <SelectContent>
                  {["access", "erasure", "rectification", "portability", "restriction", "objection"].map((t) => (
                    <SelectItem key={t} value={t}>{t}</SelectItem>
                  ))}
                </SelectContent>
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

function NewBreachDialog({ open, onOpenChange, onCreated }: { open: boolean; onOpenChange: (v: boolean) => void; onCreated: () => void }) {
  const [title, setTitle] = useState("");
  const [severity, setSeverity] = useState("high");
  const [error, setError] = useState<string | null>(null);
  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      await api.post("/tenant/privacy/breaches/", { title, severity });
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
          <DialogHeader><DialogTitle>Report a breach</DialogTitle></DialogHeader>
          <div className="space-y-3 py-4">
            <div className="space-y-1.5"><Label htmlFor="b-title">Title</Label><Input id="b-title" value={title} onChange={(e) => setTitle(e.target.value)} required /></div>
            <div className="space-y-1.5">
              <Label>Severity</Label>
              <Select value={severity} onValueChange={setSeverity}>
                <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
                <SelectContent>{["low", "medium", "high", "critical"].map((s) => <SelectItem key={s} value={s}>{s}</SelectItem>)}</SelectContent>
              </Select>
            </div>
            {error && <p className="text-sm text-destructive">{error}</p>}
          </div>
          <DialogFooter><Button type="submit">Report</Button></DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
