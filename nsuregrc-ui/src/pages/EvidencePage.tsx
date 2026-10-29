import { useEffect, useRef, useState } from "react";
import { FileStack } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { StatusBadge } from "@/components/shared/StatusBadge";
import { PageContainer, PageHeader } from "@/components/layout/PageHeader";
import { EmptyState } from "@/components/shared/EmptyState";
import { api, ApiError, uploadEvidenceRevision } from "@/lib/api";
import type { EvidenceDetail, EvidenceItem } from "@/lib/api";

export function EvidencePage() {
  const [items, setItems] = useState<EvidenceItem[]>([]);
  const [selected, setSelected] = useState<EvidenceDetail | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [loading, setLoading] = useState(true);

  function reload() {
    api.get<{ evidence: EvidenceItem[] }>("/tenant/evidence/").then((r) => {
      setItems(r.evidence);
      setLoading(false);
    });
  }

  useEffect(reload, []);

  function openDetail(id: string) {
    api.get<EvidenceDetail>(`/tenant/evidence/${id}/`).then(setSelected);
  }

  if (loading) return null;

  return (
    <>
      <PageHeader title="Evidence" description="Uploaded documents and their revisions"
                  actions={<Button onClick={() => setCreateOpen(true)}>New evidence</Button>} />
      <PageContainer>
        {items.length === 0 ? (
          <EmptyState icon={FileStack} title="No evidence yet" description="Create an evidence record, then upload a file to it." />
        ) : (
          <Table>
            <TableHeader>
              <TableRow><TableHead>Title</TableHead><TableHead>Class</TableHead><TableHead>Created</TableHead></TableRow>
            </TableHeader>
            <TableBody>
              {items.map((e) => (
                <TableRow key={e.id} className="cursor-pointer" onClick={() => openDetail(e.id)}>
                  <TableCell className="font-medium">{e.title}</TableCell>
                  <TableCell className="text-muted-foreground">{e.data_class === "C" ? "Confidential" : "Restricted"}</TableCell>
                  <TableCell className="text-muted-foreground">{new Date(e.created_at).toLocaleDateString()}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </PageContainer>

      <CreateEvidenceDialog open={createOpen} onOpenChange={setCreateOpen} onCreated={reload} />
      {selected && (
        <EvidenceDetailDialog evidence={selected} onClose={() => setSelected(null)}
                              onUploaded={() => openDetail(selected.id)} />
      )}
    </>
  );
}

function CreateEvidenceDialog({ open, onOpenChange, onCreated }: { open: boolean; onOpenChange: (v: boolean) => void; onCreated: () => void }) {
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [error, setError] = useState<string | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      await api.post("/tenant/evidence/", { title, description });
      setTitle("");
      setDescription("");
      onOpenChange(false);
      onCreated();
    } catch (err) {
      setError(err instanceof ApiError ? `Request failed (${err.status})` : "Failed to create");
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <form onSubmit={submit}>
          <DialogHeader><DialogTitle>New evidence record</DialogTitle></DialogHeader>
          <div className="space-y-3 py-4">
            <div className="space-y-1.5">
              <Label htmlFor="e-title">Title</Label>
              <Input id="e-title" value={title} onChange={(ev) => setTitle(ev.target.value)} required />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="e-desc">Description</Label>
              <Input id="e-desc" value={description} onChange={(ev) => setDescription(ev.target.value)} />
            </div>
            {error && <p className="text-sm text-destructive">{error}</p>}
          </div>
          <DialogFooter><Button type="submit">Create</Button></DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function EvidenceDetailDialog({ evidence, onClose, onUploaded }: { evidence: EvidenceDetail; onClose: () => void; onUploaded: () => void }) {
  const fileInput = useRef<HTMLInputElement>(null);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleFile(file: File) {
    setUploading(true);
    setError(null);
    try {
      await uploadEvidenceRevision(evidence.id, file);
      onUploaded();
    } catch {
      setError("Upload failed");
    } finally {
      setUploading(false);
    }
  }

  return (
    <Dialog open onOpenChange={(v) => !v && onClose()}>
      <DialogContent>
        <DialogHeader><DialogTitle>{evidence.title}</DialogTitle></DialogHeader>
        <div className="space-y-3 py-2">
          <p className="text-sm text-muted-foreground">{evidence.description || "No description."}</p>
          <div>
            <p className="mb-1.5 text-sm font-medium">Revisions</p>
            {evidence.revisions.length === 0 ? (
              <p className="text-sm text-muted-foreground">No files uploaded yet.</p>
            ) : (
              <ul className="space-y-1.5">
                {evidence.revisions.map((r) => (
                  <li key={r.id} className="flex items-center justify-between rounded-md border px-3 py-1.5 text-sm">
                    <span>{r.filename} · rev {r.revision_no}</span>
                    <StatusBadge status={r.state} />
                  </li>
                ))}
              </ul>
            )}
          </div>
          <input ref={fileInput} type="file" className="hidden"
                 onChange={(e) => e.target.files?.[0] && void handleFile(e.target.files[0])} />
          {error && <p className="text-sm text-destructive">{error}</p>}
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => fileInput.current?.click()} disabled={uploading}>
            {uploading ? "Uploading…" : "Upload file"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
