import { useQuery } from "@tanstack/react-query";
import { Radar } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router";

import { EmptyState } from "@/components/shared/empty-state";
import { ErrorAlert } from "@/components/shared/inline-alert";
import { PageHeader } from "@/components/shared/page-header";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Select } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { listProjects } from "@/features/projects/api";
import { formatDateTime } from "@/lib/format";

import { getRecon } from "./api";

function Breakdown({ title, data }: { title: string; data: Record<string, number> }) {
  const rows = Object.entries(data).sort((a, b) => b[1] - a[1]);
  return (
    <Card>
      <CardHeader>
        <CardTitle>{title}</CardTitle>
      </CardHeader>
      <CardContent>
        {rows.length === 0 ? (
          <p className="text-sm text-muted-foreground">Nothing recorded.</p>
        ) : (
          <ul aria-label={title} className="space-y-1 text-sm">
            {rows.map(([key, n]) => (
              <li key={key} className="flex justify-between">
                <span>{key.replace(/_/g, " ")}</span>
                <span className="tabular-nums">{n}</span>
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  );
}

export function ReconPage() {
  const [projectId, setProjectId] = useState("");
  const projects = useQuery({ queryKey: ["projects", "picker"], queryFn: () => listProjects(1, "") });
  const recon = useQuery({ queryKey: ["portfolio", "recon", projectId], queryFn: () => getRecon(projectId) });

  return (
    <div className="space-y-6">
      <PageHeader
        title="Reconnaissance"
        description="Discovered assets and reconnaissance activity across your projects."
        actions={
          <Select
            aria-label="Project"
            className="sm:w-56"
            value={projectId}
            onChange={(e) => {
              setProjectId(e.target.value);
            }}
          >
            <option value="">All projects</option>
            {(projects.data?.items ?? []).map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
          </Select>
        }
      />
      {recon.isPending ? (
        <div role="status" aria-label="Loading reconnaissance" className="space-y-3">
          <Skeleton className="h-24 w-full" />
          <Skeleton className="h-48 w-full" />
        </div>
      ) : recon.isError ? (
        <ErrorAlert error={recon.error} />
      ) : recon.data.empty ? (
        <EmptyState icon={Radar} title="No projects to show yet">
          Create a project and register assets to see reconnaissance data.
        </EmptyState>
      ) : (
        <>
          <section aria-label="Reconnaissance figures" className="grid grid-cols-2 gap-3">
            <Card>
              <CardContent className="py-4">
                <p className="text-xs tracking-wide text-muted-foreground uppercase">Assets</p>
                <p className="text-3xl font-semibold tabular-nums">{recon.data.assets_total}</p>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="py-4">
                <p className="text-xs tracking-wide text-muted-foreground uppercase">New in 7 days</p>
                <p className="text-3xl font-semibold tabular-nums">{recon.data.assets_new_7d}</p>
              </CardContent>
            </Card>
          </section>
          <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-4">
            <Breakdown title="Assets by type" data={recon.data.assets_by_type} />
            <Breakdown title="Assets by exposure" data={recon.data.assets_by_exposure} />
            <Breakdown title="Scans (30 days) by scanner" data={recon.data.scans_30d_by_scanner} />
            <Breakdown title="Scans (30 days) by status" data={recon.data.scans_30d_by_status} />
          </div>
          <Card>
            <CardHeader>
              <CardTitle>Recently registered assets</CardTitle>
            </CardHeader>
            <CardContent>
              {recon.data.recent_assets.length === 0 ? (
                <p className="text-sm text-muted-foreground">No assets yet.</p>
              ) : (
                <Table aria-label="Recent assets">
                  <THead>
                    <tr>
                      <TH>Asset</TH>
                      <TH>Type</TH>
                      <TH>Exposure</TH>
                      <TH>Project</TH>
                      <TH>Registered</TH>
                    </tr>
                  </THead>
                  <TBody>
                    {recon.data.recent_assets.map((a) => (
                      <TR key={a.id}>
                        <TD>
                          <Link to={`/projects/${a.project_id}/assets/${a.id}`} className="font-mono text-sm text-primary hover:underline">
                            {a.value}
                          </Link>
                        </TD>
                        <TD className="text-sm">{a.type.replace(/_/g, " ")}</TD>
                        <TD className="text-sm">{a.exposure}</TD>
                        <TD className="text-sm">{a.project_name}</TD>
                        <TD className="text-sm text-muted-foreground">{formatDateTime(a.created_at)}</TD>
                      </TR>
                    ))}
                  </TBody>
                </Table>
              )}
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>Recent scans</CardTitle>
            </CardHeader>
            <CardContent>
              {recon.data.recent_scans.length === 0 ? (
                <p className="text-sm text-muted-foreground">No scans yet.</p>
              ) : (
                <Table aria-label="Recent scans">
                  <THead>
                    <tr>
                      <TH>Target</TH>
                      <TH>Scanner</TH>
                      <TH>Status</TH>
                      <TH>Project</TH>
                      <TH>Started</TH>
                    </tr>
                  </THead>
                  <TBody>
                    {recon.data.recent_scans.map((s) => (
                      <TR key={s.id}>
                        <TD>
                          <Link to={`/projects/${s.project_id}/scans/${s.id}`} className="font-mono text-sm text-primary hover:underline">
                            {s.target}
                          </Link>
                        </TD>
                        <TD className="text-sm">
                          {s.scanner} · {s.profile}
                        </TD>
                        <TD className="text-sm">{s.status}</TD>
                        <TD className="text-sm">{s.project_name}</TD>
                        <TD className="text-sm text-muted-foreground">{formatDateTime(s.created_at)}</TD>
                      </TR>
                    ))}
                  </TBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </>
      )}
    </div>
  );
}
