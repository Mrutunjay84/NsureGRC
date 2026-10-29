import { useEffect, useState } from "react";
import { Server } from "lucide-react";
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
import type { Asset, Incident } from "@/lib/api";

const ASSET_TYPE_LABEL: Record<string, string> = {
  hardware: "Hardware", software: "Software", data: "Data", facility: "Facility",
  personnel: "Personnel", service: "Service", other: "Other",
};

const NEXT_INCIDENT_STATUS: Record<string, string> = {
  detected: "investigating", investigating: "contained", contained: "resolved", resolved: "closed",
};

export function AssetsPage() {
  const [tab, setTab] = useState("assets");
  const [assets, setAssets] = useState<Asset[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(true);
  const [dialog, setDialog] = useState<"asset" | "incident" | null>(null);

  function reload() {
    Promise.all([
      api.get<{ results: Asset[] }>("/tenant/assets/"),
      api.get<{ results: Incident[] }>("/tenant/risk/incidents/"),
    ]).then(([a, i]) => {
      setAssets(a.results);
      setIncidents(i.results);
      setLoading(false);
    });
  }

  useEffect(reload, []);

  async function advanceIncident(incident: Incident) {
    const next = NEXT_INCIDENT_STATUS[incident.status];
    if (!next) return;
    await api.post(`/tenant/risk/incidents/${incident.id}/transition/`, { status: next });
    reload();
  }

  if (loading) return null;

  return (
    <>
      <PageHeader title="Assets & Incidents" description="Assets, their business impact, and security incidents"
                  actions={<Button onClick={() => setDialog(tab === "assets" ? "asset" : "incident")}>
                    {tab === "assets" ? "New asset" : "New incident"}
                  </Button>} />
      <PageContainer>
        <Tabs value={tab} onValueChange={setTab}>
          <TabsList>
            <TabsTrigger value="assets">Assets ({assets.length})</TabsTrigger>
            <TabsTrigger value="incidents">Incidents ({incidents.length})</TabsTrigger>
          </TabsList>

          <TabsContent value="assets">
            {assets.length === 0 ? (
              <EmptyState icon={Server} title="No assets" description="Add an asset to start tracking its business impact." />
            ) : (
              <Table>
                <TableHeader><TableRow><TableHead>Name</TableHead><TableHead>Type</TableHead><TableHead>Criticality</TableHead></TableRow></TableHeader>
                <TableBody>
                  {assets.map((a) => (
                    <TableRow key={a.id}>
                      <TableCell className="font-medium">{a.name}</TableCell>
                      <TableCell className="text-muted-foreground">{ASSET_TYPE_LABEL[a.asset_type]}</TableCell>
                      <TableCell><SeverityBadge severity={a.criticality} /></TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </TabsContent>

          <TabsContent value="incidents">
            {incidents.length === 0 ? (
              <EmptyState icon={Server} title="No incidents" description="Raise a security incident." />
            ) : (
              <Table>
                <TableHeader><TableRow><TableHead>Title</TableHead><TableHead>Severity</TableHead><TableHead>Status</TableHead><TableHead /></TableRow></TableHeader>
                <TableBody>
                  {incidents.map((i) => (
                    <TableRow key={i.id}>
                      <TableCell className="font-medium">{i.title}</TableCell>
                      <TableCell><SeverityBadge severity={i.severity} /></TableCell>
                      <TableCell><StatusBadge status={i.status} /></TableCell>
                      <TableCell className="text-right">
                        {NEXT_INCIDENT_STATUS[i.status] && (
                          <Button variant="outline" size="sm" onClick={() => void advanceIncident(i)}>
                            Move to {NEXT_INCIDENT_STATUS[i.status]}
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

      <NewAssetDialog open={dialog === "asset"} onOpenChange={(v) => !v && setDialog(null)} onCreated={reload} />
      <NewIncidentDialog open={dialog === "incident"} onOpenChange={(v) => !v && setDialog(null)} onCreated={reload} />
    </>
  );
}

function NewAssetDialog({ open, onOpenChange, onCreated }: { open: boolean; onOpenChange: (v: boolean) => void; onCreated: () => void }) {
  const [name, setName] = useState("");
  const [assetType, setAssetType] = useState("data");
  const [criticality, setCriticality] = useState("medium");
  const [error, setError] = useState<string | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      await api.post("/tenant/assets/", { name, asset_type: assetType, criticality });
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
          <DialogHeader><DialogTitle>New asset</DialogTitle></DialogHeader>
          <div className="space-y-3 py-4">
            <div className="space-y-1.5">
              <Label htmlFor="asset-name">Name</Label>
              <Input id="asset-name" value={name} onChange={(e) => setName(e.target.value)} required />
            </div>
            <div className="space-y-1.5">
              <Label>Type</Label>
              <Select value={assetType} onValueChange={setAssetType}>
                <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
                <SelectContent>
                  {Object.entries(ASSET_TYPE_LABEL).map(([v, label]) => <SelectItem key={v} value={v}>{label}</SelectItem>)}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <Label>Criticality</Label>
              <Select value={criticality} onValueChange={setCriticality}>
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

function NewIncidentDialog({ open, onOpenChange, onCreated }: { open: boolean; onOpenChange: (v: boolean) => void; onCreated: () => void }) {
  const [title, setTitle] = useState("");
  const [severity, setSeverity] = useState("medium");
  const [error, setError] = useState<string | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      await api.post("/tenant/risk/incidents/", { title, severity });
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
          <DialogHeader><DialogTitle>New incident</DialogTitle></DialogHeader>
          <div className="space-y-3 py-4">
            <div className="space-y-1.5">
              <Label htmlFor="incident-title">Title</Label>
              <Input id="incident-title" value={title} onChange={(e) => setTitle(e.target.value)} required />
            </div>
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
