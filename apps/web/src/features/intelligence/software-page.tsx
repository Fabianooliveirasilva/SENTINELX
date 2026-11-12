import { useQuery } from "@tanstack/react-query";
import { Package } from "lucide-react";
import { Link, useParams } from "react-router";

import { EmptyState } from "@/components/shared/empty-state";
import { ErrorAlert } from "@/components/shared/inline-alert";
import { PageHeader } from "@/components/shared/page-header";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { ProjectTabs } from "@/features/projects/project-tabs";
import { formatDateTime } from "@/lib/format";

import { intelKeys, projectSoftware } from "./api";

export function SoftwarePage() {
  const { projectId = "" } = useParams();
  const software = useQuery({ queryKey: intelKeys.software(projectId), queryFn: () => projectSoftware(projectId) });

  return (
    <div className="space-y-6">
      <PageHeader
        title="Software inventory"
        description="Products and versions observed by the latest scans. Only versioned, mapped products are correlated with CVEs."
      />
      <ProjectTabs projectId={projectId} />
      <Card>
        <CardContent className="pt-5">
          {software.isPending ? (
            <Skeleton className="h-20 w-full" />
          ) : software.isError ? (
            <ErrorAlert error={software.error} />
          ) : software.data.length === 0 ? (
            <EmptyState icon={Package} title="No software observed yet">
              Run HTTP, Nmap or Nuclei scans to build the inventory.
            </EmptyState>
          ) : (
            <Table aria-label="Software">
              <THead>
                <tr>
                  <TH>Product</TH>
                  <TH>Version</TH>
                  <TH>Where</TH>
                  <TH>CVE correlation</TH>
                  <TH>Last seen</TH>
                </tr>
              </THead>
              <TBody>
                {software.data.map((s) => (
                  <TR key={s.id}>
                    <TD className="text-sm">
                      {s.name}
                      <span className="block font-mono text-xs text-muted-foreground">{s.cpes.join(", ")}</span>
                    </TD>
                    <TD className="font-mono text-sm">{s.raw_version || "—"}</TD>
                    <TD className="font-mono text-xs break-all">
                      {s.location} <span className="text-muted-foreground">({s.source})</span>
                    </TD>
                    <TD>
                      {s.correlatable ? (
                        <Link
                          to={`/projects/${projectId}/findings`}
                          className="text-sm text-primary hover:underline"
                        >
                          correlated
                        </Link>
                      ) : (
                        <Badge>{s.version ? "unmapped product" : "no version"}</Badge>
                      )}
                    </TD>
                    <TD className="text-sm text-muted-foreground">{formatDateTime(s.last_seen_at)}</TD>
                  </TR>
                ))}
              </TBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
