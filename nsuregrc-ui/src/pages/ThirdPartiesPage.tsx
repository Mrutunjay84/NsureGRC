import { useEffect, useState } from "react";
import { Building2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageContainer, PageHeader } from "@/components/layout/PageHeader";
import { EmptyState } from "@/components/shared/EmptyState";
import { SeverityBadge, StatusBadge } from "@/components/shared/StatusBadge";
import { api, ApiError } from "@/lib/api";
import type { ThirdPartyEntity } from "@/lib/api";

const CATEGORY_LABEL: Record<string, string> = { vendor: "Vendor", processor: "Processor", partner: "Partner", other: "Other" };

export function ThirdPartiesPage() {
  const [entities, setEntities] = useState<ThirdPartyEntity[]>([]);
  const [loading, setLoading] = useState(true);
  const [dialogOpen, setDialogOpen] = useState(false);

  function reload() {
    api.get<{ results: ThirdPartyEntity[] }>("/tenant/third-parties/entities/").then((r) => {
      setEntities(r.results);
      setLoading(false);
    });
  }

  useEffect(reload, []);

  if (loading) return null;

  return (
    <>
      <PageHeader title="Third Parties" description="Vendors, processors and partners, and their assessments"
                  actions={<Button onClick={() => setDialogOpen(true)}>New entity</Button>} />
      <PageContainer>
        {entities.length === 0 ? (
          <EmptyState icon={Building2} title="No third parties" description="Add a vendor, processor or partner to start tracking it." />
        ) : (
          <Table>
            <TableHeader>
              <TableRow><TableHead>Name</TableHead><TableHead>Category</TableHead><TableHead>Criticality</TableHead><TableHead>Status</TableHead></TableRow>
            </TableHeader>
            <TableBody>
              {entities.map((e) => (
                <TableRow key={e.id}>
                  <TableCell className="font-medium">{e.name}</TableCell>
                  <TableCell className="text-muted-foreground">{CATEGORY_LABEL[e.category]}</TableCell>
                  <TableCell><SeverityBadge severity={e.criticality} /></TableCell>
                  <TableCell><StatusBadge status={e.status} /></TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </PageContainer>

      <NewEntityDialog open={dialogOpen} onOpenChange={setDialogOpen} onCreated={reload} />
    </>
  );
}

function NewEntityDialog({ open, onOpenChange, onCreated }: { open: boolean; onOpenChange: (v: boolean) => void; onCreated: () => void }) {
  const [name, setName] = useState("");
  const [category, setCategory] = useState("vendor");
  const [criticality, setCriticality] = useState("medium");
  const [error, setError] = useState<string | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      await api.post("/tenant/third-parties/entities/", { name, category, criticality });
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
          <DialogHeader><DialogTitle>New third-party entity</DialogTitle></DialogHeader>
          <div className="space-y-3 py-4">
            <div className="space-y-1.5">
              <Label htmlFor="tp-name">Name</Label>
              <Input id="tp-name" value={name} onChange={(e) => setName(e.target.value)} required />
            </div>
            <div className="space-y-1.5">
              <Label>Category</Label>
              <Select value={category} onValueChange={setCategory}>
                <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
                <SelectContent>
                  {Object.entries(CATEGORY_LABEL).map(([v, label]) => <SelectItem key={v} value={v}>{label}</SelectItem>)}
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
