import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { ClipboardCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageContainer, PageHeader } from "@/components/layout/PageHeader";
import { EmptyState } from "@/components/shared/EmptyState";
import { StatusBadge } from "@/components/shared/StatusBadge";
import { api, ApiError } from "@/lib/api";
import type { Audit } from "@/lib/api";

export function AuditsPage() {
  const [audits, setAudits] = useState<Audit[]>([]);
  const [loading, setLoading] = useState(true);
  const [createOpen, setCreateOpen] = useState(false);

  function reload() {
    api.get<{ results: Audit[] }>("/tenant/audits/").then((r) => {
      setAudits(r.results);
      setLoading(false);
    });
  }

  useEffect(reload, []);

  if (loading) return null;

  return (
    <>
      <PageHeader title="Compliance Audits" description="Formal assessment exercises against a framework"
                  actions={<Button onClick={() => setCreateOpen(true)}>New audit</Button>} />
      <PageContainer>
        {audits.length === 0 ? (
          <EmptyState icon={ClipboardCheck} title="No audits yet" description="Start one against a framework your tenant has activated." />
        ) : (
          <Table>
            <TableHeader><TableRow><TableHead>Name</TableHead><TableHead>Framework</TableHead><TableHead>Status</TableHead></TableRow></TableHeader>
            <TableBody>
              {audits.map((a) => (
                <TableRow key={a.id}>
                  <TableCell><Link to={`/audits/${a.id}`} className="font-medium hover:underline">{a.name}</Link></TableCell>
                  <TableCell className="text-muted-foreground">{a.framework_urn}</TableCell>
                  <TableCell><StatusBadge status={a.status} /></TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </PageContainer>

      <CreateAuditDialog open={createOpen} onOpenChange={setCreateOpen} onCreated={reload} />
    </>
  );
}

function CreateAuditDialog({ open, onOpenChange, onCreated }: { open: boolean; onOpenChange: (v: boolean) => void; onCreated: () => void }) {
  const [name, setName] = useState("");
  const [frameworkUrn, setFrameworkUrn] = useState("");
  const [error, setError] = useState<string | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      await api.post("/tenant/audits/", { name, framework_urn: frameworkUrn });
      setName("");
      setFrameworkUrn("");
      onOpenChange(false);
      onCreated();
    } catch (err) {
      const body = err instanceof ApiError ? (err.body as { error?: string } | null) : null;
      setError(body?.error ?? "Failed to create - check the framework URN is activated for this tenant");
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <form onSubmit={submit}>
          <DialogHeader><DialogTitle>New compliance audit</DialogTitle></DialogHeader>
          <div className="space-y-3 py-4">
            <div className="space-y-1.5">
              <Label htmlFor="a-name">Name</Label>
              <Input id="a-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="Q1 2027 SOC 2 audit" required />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="a-fw">Framework URN</Label>
              <Input id="a-fw" value={frameworkUrn} onChange={(e) => setFrameworkUrn(e.target.value)} required />
              <p className="text-xs text-muted-foreground">Must already be activated for this tenant.</p>
            </div>
            {error && <p className="text-sm text-destructive">{error}</p>}
          </div>
          <DialogFooter><Button type="submit">Create</Button></DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
