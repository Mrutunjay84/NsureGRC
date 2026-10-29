import { useEffect, useState } from "react";
import { FileWarning } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { SeverityBadge, StatusBadge } from "@/components/shared/StatusBadge";
import { PageContainer, PageHeader } from "@/components/layout/PageHeader";
import { EmptyState } from "@/components/shared/EmptyState";
import { api } from "@/lib/api";
import type { Finding } from "@/lib/api";

const NEXT_STATUS: Record<string, string> = {
  open: "in_remediation",
  in_remediation: "pending_verification",
  pending_verification: "closed",
};

export function FindingsPage() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);

  function reload() {
    api.get<{ results: Finding[] }>("/tenant/findings/").then((r) => {
      setFindings(r.results);
      setLoading(false);
    });
  }

  useEffect(reload, []);

  async function advance(f: Finding) {
    const next = NEXT_STATUS[f.status];
    if (!next) return;
    await api.post(`/tenant/findings/${f.id}/transition/`, { status: next });
    reload();
  }

  if (loading) return null;

  return (
    <>
      <PageHeader title="Findings" description="Control gaps across every implementation control, open through closed" />
      <PageContainer>
        {findings.length === 0 ? (
          <EmptyState icon={FileWarning} title="No findings" description="Findings raised against a control will show up here." />
        ) : (
          <Table>
            <TableHeader>
              <TableRow><TableHead>Title</TableHead><TableHead>Severity</TableHead><TableHead>Status</TableHead><TableHead>Source</TableHead><TableHead /></TableRow>
            </TableHeader>
            <TableBody>
              {findings.map((f) => (
                <TableRow key={f.id}>
                  <TableCell className="font-medium">{f.title}</TableCell>
                  <TableCell><SeverityBadge severity={f.severity} /></TableCell>
                  <TableCell><StatusBadge status={f.status} /></TableCell>
                  <TableCell className="text-muted-foreground">{f.source}</TableCell>
                  <TableCell className="text-right">
                    {NEXT_STATUS[f.status] && (
                      <Button variant="outline" size="sm" onClick={() => void advance(f)}>
                        Move to {NEXT_STATUS[f.status].replaceAll("_", " ")}
                      </Button>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </PageContainer>
    </>
  );
}
