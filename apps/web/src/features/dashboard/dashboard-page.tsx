import { useQuery } from "@tanstack/react-query";
import { FolderPlus, ShieldCheck } from "lucide-react";
import { useState, type ReactNode } from "react";
import { Link } from "react-router";

import { EmptyState } from "@/components/shared/empty-state";
import { ErrorAlert } from "@/components/shared/inline-alert";
import { PageHeader } from "@/components/shared/page-header";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Select } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { useCan } from "@/features/auth/use-auth";
import { SeverityBadge } from "@/features/findings/severity";
import { listProjects } from "@/features/projects/api";
import { formatDateTime } from "@/lib/format";

import { dashboardKeys, getDashboard, type Dashboard } from "./api";
import { ExposureChart, PostureTrendChart, RemediationChart, RiskDistributionChart, ScanActivityChart } from "./charts";

const REFRESH_MS = 60_000;

function StatTile({ label, value, detail, children }: { label: string; value: ReactNode; detail?: ReactNode; children?: ReactNode }) {
  return (
    <Card>
      <CardContent className="space-y-1 py-4">
        <p className="text-xs tracking-wide text-muted-foreground uppercase">{label}</p>
        <div className="flex items-baseline gap-2">
          <span className="text-3xl font-semibold tabular-nums">{value}</span>
          {children}
        </div>
        {detail ? <p className="text-xs text-muted-foreground">{detail}</p> : null}
      </CardContent>
    </Card>
  );
}

function Tiles({ data }: { data: Dashboard }) {
  const t = data.totals;
  const closed = data.remediation.closed_ratio;
  return (
    <section aria-label="Key figures" className="grid grid-cols-2 gap-3 lg:grid-cols-5">
      <StatTile label="Assets" value={t.assets} detail={`${String(data.assets_by_exposure.external ?? 0)} externally exposed`} />
      <StatTile label="Active scans" value={t.active_scans} detail="Pending, queued or running" />
      <StatTile
        label="Critical findings"
        value={t.critical_findings}
        detail={`${String(t.high_findings)} high · ${String(t.known_exploited_findings)} known exploited`}
      />
      <StatTile
        label="Posture score"
        value={data.posture.score.toFixed(0)}
        detail={data.posture.worst_project ? `Worst: ${data.posture.worst_project.name}` : "No scored findings"}
      >
        <SeverityBadge severity={data.posture.band} />
      </StatTile>
      <StatTile
        label="Closed findings"
        value={closed === null ? "—" : `${(closed * 100).toFixed(0)}%`}
        detail={`${String(t.active_findings)} still active`}
      />
    </section>
  );
}

function RecentFindings({ data }: { data: Dashboard }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Recent findings</CardTitle>
      </CardHeader>
      <CardContent>
        {data.recent_findings.length === 0 ? (
          <p className="text-sm text-muted-foreground">No active findings.</p>
        ) : (
          <ul aria-label="Recent findings" className="divide-y divide-border">
            {data.recent_findings.map((f) => (
              <li key={f.id} className="flex items-start gap-3 py-2">
                <SeverityBadge severity={f.risk_band ?? f.severity} />
                <div className="min-w-0 flex-1">
                  <Link
                    to={`/projects/${f.project_id}/findings/${f.id}`}
                    className="block truncate text-sm text-primary hover:underline"
                  >
                    {f.title}
                  </Link>
                  <p className="truncate text-xs text-muted-foreground">
                    {f.project_name} · {f.asset} · {formatDateTime(f.first_seen_at)}
                  </p>
                </div>
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  );
}

function ProjectRanking({ data }: { data: Dashboard }) {
  if (data.projects.length < 2) return null;
  return (
    <Card>
      <CardHeader>
        <CardTitle>Projects by risk posture</CardTitle>
      </CardHeader>
      <CardContent>
        <ul aria-label="Projects by risk posture" className="divide-y divide-border">
          {data.projects.map((p) => (
            <li key={p.id} className="flex items-center gap-3 py-2 text-sm">
              <SeverityBadge severity={p.band} />
              <Link to={`/projects/${p.id}/risk`} className="min-w-0 flex-1 truncate text-primary hover:underline">
                {p.name}
              </Link>
              <span className="text-xs text-muted-foreground tabular-nums">
                {p.score.toFixed(0)}/100 · {p.active} active
              </span>
            </li>
          ))}
        </ul>
      </CardContent>
    </Card>
  );
}

export function DashboardPage() {
  const [projectId, setProjectId] = useState("");
  const canCreate = useCan("projects:manage");
  const projects = useQuery({ queryKey: ["projects", "picker"], queryFn: () => listProjects(1, "") });
  const dashboard = useQuery({
    queryKey: dashboardKeys.scope(projectId),
    queryFn: () => getDashboard(projectId),
    refetchInterval: REFRESH_MS,
  });

  return (
    <div className="space-y-6">
      <PageHeader
        title="Dashboard"
        description="Security posture across the projects you can access, computed from stored assessment data."
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
      {dashboard.isPending ? (
        <div role="status" aria-label="Loading dashboard" className="space-y-3">
          <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
            {Array.from({ length: 5 }, (_, i) => (
              <Skeleton key={i} className="h-24" />
            ))}
          </div>
          <Skeleton className="h-64 w-full" />
        </div>
      ) : dashboard.isError ? (
        <ErrorAlert error={dashboard.error} />
      ) : dashboard.data.empty ? (
        <Card>
          <CardContent>
            <EmptyState icon={canCreate ? FolderPlus : ShieldCheck} title="No projects to show yet">
              {canCreate ? (
                <Link to="/projects" className="text-primary hover:underline">
                  Create a project and register its authorized assets.
                </Link>
              ) : (
                "Ask an administrator to add you to a project."
              )}
            </EmptyState>
          </CardContent>
        </Card>
      ) : (
        <>
          <Tiles data={dashboard.data} />
          <div className="grid gap-4 xl:grid-cols-2">
            <RiskDistributionChart data={dashboard.data.risk_distribution} />
            <PostureTrendChart data={dashboard.data.posture_trend} />
            <ScanActivityChart data={dashboard.data.scan_activity} />
            <RemediationChart data={dashboard.data.remediation} />
          </div>
          <div className="grid gap-4 xl:grid-cols-3">
            <div className="xl:col-span-2">
              <RecentFindings data={dashboard.data} />
            </div>
            <div className="space-y-4">
              <ExposureChart data={dashboard.data.assets_by_exposure} />
              <ProjectRanking data={dashboard.data} />
            </div>
          </div>
          <p className="text-xs text-muted-foreground">Updated {formatDateTime(dashboard.data.generated_at)}</p>
        </>
      )}
    </div>
  );
}
