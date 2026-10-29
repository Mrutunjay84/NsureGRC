import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageContainer, PageHeader } from "@/components/layout/PageHeader";
import { EmptyState } from "@/components/shared/EmptyState";
import { api, ApiError } from "@/lib/api";
import type { CommonControl, ImplementationControl } from "@/lib/api";

export function ControlsPage() {
  const [commonControls, setCommonControls] = useState<CommonControl[]>([]);
  const [implControls, setImplControls] = useState<ImplementationControl[]>([]);
  const [loading, setLoading] = useState(true);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [commonDialogOpen, setCommonDialogOpen] = useState(false);

  function reload() {
    Promise.all([
      api.get<{ results: CommonControl[] }>("/tenant/controls/common/"),
      api.get<{ results: ImplementationControl[] }>("/tenant/controls/implementation/"),
    ]).then(([cc, ic]) => {
      setCommonControls(cc.results);
      setImplControls(ic.results);
      setLoading(false);
    });
  }

  useEffect(reload, []);

  if (loading) return null;

  return (
    <>
      <PageHeader
        title="Controls"
        description="Common control catalogue and their per-environment implementations"
        actions={
          <>
            <Button variant="outline" onClick={() => setCommonDialogOpen(true)}>New common control</Button>
            <Button onClick={() => setDialogOpen(true)} disabled={commonControls.length === 0}>New control</Button>
          </>
        }
      />
      <PageContainer>
        {implControls.length === 0 ? (
          <EmptyState icon={ShieldCheck} title="No implementation controls yet"
                      description={commonControls.length === 0
                        ? "Create a common control first, then implement it."
                        : "Create your first implementation control to start tracking it."} />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Common control</TableHead>
                <TableHead>Owner</TableHead>
                <TableHead>Lifecycle</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {implControls.map((c) => (
                <TableRow key={c.id} className="cursor-pointer">
                  <TableCell>
                    <Link to={`/controls/${c.id}`} className="font-medium hover:underline">{c.name}</Link>
                  </TableCell>
                  <TableCell className="text-muted-foreground">{c.common_control_name}</TableCell>
                  <TableCell className="text-muted-foreground">{c.owner ?? "—"}</TableCell>
                  <TableCell className="text-muted-foreground">{c.lifecycle}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </PageContainer>

      <CreateCommonControlDialog open={commonDialogOpen} onOpenChange={setCommonDialogOpen} onCreated={reload} />
      <CreateImplementationControlDialog open={dialogOpen} onOpenChange={setDialogOpen} onCreated={reload}
                                         commonControls={commonControls} />
    </>
  );
}

function CreateCommonControlDialog({ open, onOpenChange, onCreated }: { open: boolean; onOpenChange: (v: boolean) => void; onCreated: () => void }) {
  const [key, setKey] = useState("");
  const [name, setName] = useState("");
  const [error, setError] = useState<string | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      await api.post("/tenant/controls/common/", { key, name });
      setKey("");
      setName("");
      onOpenChange(false);
      onCreated();
    } catch (err) {
      setError(err instanceof ApiError ? JSON.stringify(err.body) : "Failed to create");
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <form onSubmit={submit}>
          <DialogHeader>
            <DialogTitle>New common control</DialogTitle>
          </DialogHeader>
          <div className="space-y-3 py-4">
            <div className="space-y-1.5">
              <Label htmlFor="cc-key">Key (slug)</Label>
              <Input id="cc-key" value={key} onChange={(e) => setKey(e.target.value)} placeholder="access-control" required />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="cc-name">Name</Label>
              <Input id="cc-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="Access Control" required />
            </div>
            {error && <p className="text-sm text-destructive">{error}</p>}
          </div>
          <DialogFooter>
            <Button type="submit">Create</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function CreateImplementationControlDialog({ open, onOpenChange, onCreated, commonControls }: {
  open: boolean; onOpenChange: (v: boolean) => void; onCreated: () => void; commonControls: CommonControl[];
}) {
  const [commonControlId, setCommonControlId] = useState("");
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [error, setError] = useState<string | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      await api.post("/tenant/controls/implementation/", { common_control: commonControlId, name, description });
      setName("");
      setDescription("");
      onOpenChange(false);
      onCreated();
    } catch (err) {
      setError(err instanceof ApiError ? JSON.stringify(err.body) : "Failed to create");
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <form onSubmit={submit}>
          <DialogHeader>
            <DialogTitle>New implementation control</DialogTitle>
          </DialogHeader>
          <div className="space-y-3 py-4">
            <div className="space-y-1.5">
              <Label>Common control</Label>
              <Select value={commonControlId} onValueChange={setCommonControlId}>
                <SelectTrigger className="w-full"><SelectValue placeholder="Select a common control" /></SelectTrigger>
                <SelectContent>
                  {commonControls.map((c) => (
                    <SelectItem key={c.id} value={c.id}>{c.name}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="ic-name">Name</Label>
              <Input id="ic-name" value={name} onChange={(e) => setName(e.target.value)} required />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="ic-desc">Description</Label>
              <Input id="ic-desc" value={description} onChange={(e) => setDescription(e.target.value)} />
            </div>
            {error && <p className="text-sm text-destructive">{error}</p>}
          </div>
          <DialogFooter>
            <Button type="submit" disabled={!commonControlId}>Create</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
