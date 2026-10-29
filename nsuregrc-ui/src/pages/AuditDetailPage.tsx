import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageContainer, PageHeader } from "@/components/layout/PageHeader";
import { StatusBadge } from "@/components/shared/StatusBadge";
import { api, ApiError } from "@/lib/api";
import type { AuditDetail } from "@/lib/api";

// Mirrors ngrc.compliance_audit.services._ALLOWED_AUDIT_TRANSITIONS exactly - the backend is the real
// enforcement (fails closed regardless of what this offers); this only decides which button(s) to show.
const NEXT_STATUSES: Record<string, string[]> = {
  draft: ["assigned"],
  assigned: ["in_progress"],
  in_progress: ["submitted"],
  submitted: ["review"],
  review: ["changes_requested", "accepted"],
  changes_requested: ["in_progress"],
  accepted: ["signoff"],
  signoff: ["locked"],
  locked: [],
};

export function AuditDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [audit, setAudit] = useState<AuditDetail | null>(null);
  const [itemOpen, setItemOpen] = useState(false);

  function reload() {
    if (id) api.get<AuditDetail>(`/tenant/audits/${id}/`).then(setAudit);
  }

  useEffect(reload, [id]);

  async function transition(status: string) {
    if (!audit) return;
    await api.post(`/tenant/audits/${audit.id}/transition/`, { status });
    reload();
  }

  if (!audit) return null;

  return (
    <>
      <PageHeader title={audit.name} description={audit.framework_urn}
                  actions={
                    <>
                      <Button variant="outline" onClick={() => setItemOpen(true)}>Add requirement</Button>
                      {NEXT_STATUSES[audit.status]?.map((s) => (
                        <Button key={s} onClick={() => void transition(s)}>Move to {s.replaceAll("_", " ")}</Button>
                      ))}
                    </>
                  } />
      <PageContainer>
        <div className="mb-4"><StatusBadge status={audit.status} /></div>
        {audit.items.length === 0 ? (
          <p className="text-sm text-muted-foreground">No requirements added to this audit yet.</p>
        ) : (
          <Table>
            <TableHeader><TableRow><TableHead>Requirement</TableHead><TableHead>Result</TableHead></TableRow></TableHeader>
            <TableBody>
              {audit.items.map((i) => (
                <TableRow key={i.id}>
                  <TableCell className="font-medium">{i.requirement_urn}</TableCell>
                  <TableCell><StatusBadge status={i.result} /></TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </PageContainer>

      <AddItemDialog open={itemOpen} onOpenChange={setItemOpen} auditId={audit.id} onDone={reload} />
    </>
  );
}

function AddItemDialog({ open, onOpenChange, auditId, onDone }: {
  open: boolean; onOpenChange: (v: boolean) => void; auditId: string; onDone: () => void;
}) {
  const [requirementUrn, setRequirementUrn] = useState("");
  const [error, setError] = useState<string | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      await api.post(`/tenant/audits/${auditId}/items/`, { requirement_urn: requirementUrn });
      setRequirementUrn("");
      onOpenChange(false);
      onDone();
    } catch (err) {
      const body = err instanceof ApiError ? (err.body as { error?: string } | null) : null;
      setError(body?.error ?? "Failed - check the requirement URN resolves in this audit's framework");
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <form onSubmit={submit}>
          <DialogHeader><DialogTitle>Add a requirement</DialogTitle></DialogHeader>
          <div className="space-y-3 py-4">
            <div className="space-y-1.5">
              <Label htmlFor="req-urn">Requirement URN</Label>
              <Input id="req-urn" value={requirementUrn} onChange={(e) => setRequirementUrn(e.target.value)} required />
            </div>
            {error && <p className="text-sm text-destructive">{error}</p>}
          </div>
          <DialogFooter><Button type="submit">Add</Button></DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
