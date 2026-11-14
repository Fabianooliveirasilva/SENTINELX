import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "react-router";

import { ErrorAlert } from "@/components/shared/inline-alert";
import { PageHeader } from "@/components/shared/page-header";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { SEVERITIES } from "@/features/findings/api";
import { RiskScore, SeverityBadge } from "@/features/findings/severity";
import { ProjectTabs } from "@/features/projects/project-tabs";

import { getProjectRisk, riskKeys, type ProjectRisk } from "./api";

function Trend({ points }: { points: ProjectRisk["trend"] }) {
  if (points.length < 2) {
    return <p className="text-sm text-muted-foreground">The trend appears after a second daily snapshot.</p>;
  }
  const width = 320;
  const height = 80;
  const step = width / (points.length - 1);
  const path = points
    .map((p, i) => `${i === 0 ? "M" : "L"}${(i * step).toFixed(1)},${(height - (p.score / 100) * height).toFixed(1)}`)
    .join(" ");
  const last = points[points.length - 1];
  return (
    <figure>
      <svg
        role="img"
        aria-label={`Risk trend over ${String(points.length)} days, latest ${String(last?.score ?? 0)}`}
        viewBox={`0 0 ${String(width)} ${String(height)}`}
        className="h-20 w-full max-w-md text-primary"
      >
        <path d={path} fill="none" stroke="currentColor" strokeWidth="2" />
      </svg>
      <figcaption className="text-xs text-muted-foreground">
        {points[0]?.day} → {last?.day}
      </figcaption>
    </figure>
  );
}

export function ProjectRiskPage() {
  const { projectId = "" } = useParams();
  const risk = useQuery({ queryKey: riskKeys.project(projectId), queryFn: () => getProjectRisk(projectId) });

  return (
    <div className="space-y-6">
      <PageHeader
        title="Risk posture"
        description="Explainable risk scores of open and acknowledged findings, with a daily trend."
      />
      <ProjectTabs projectId={projectId} />
      {risk.isPending ? (
        <Skeleton className="h-32 w-full" />
      ) : risk.isError ? (
        <ErrorAlert error={risk.error} />
      ) : (
        <>
          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle>Project posture</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <p className="text-4xl font-semibold tabular-nums" data-testid="posture-score">
                  {risk.data.posture.score.toFixed(1)}
                </p>
                <SeverityBadge severity={risk.data.posture.band} />
                <ul aria-label="Active findings by risk band" className="flex flex-wrap gap-3 text-sm">
                  {SEVERITIES.map((band) => (
                    <li key={band}>
                      {band}: <span className="font-semibold tabular-nums">{risk.data.posture.counts[band]}</span>
                    </li>
                  ))}
                </ul>
                <p className="text-xs text-muted-foreground">
                  Worst finding, raised when several serious findings coexist · model {risk.data.model_version} ·{" "}
                  <Link to="/risk-model" className="text-primary hover:underline">
                    how scores work
                  </Link>
                </p>
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle>Trend (30 days)</CardTitle>
              </CardHeader>
              <CardContent>
                <Trend points={risk.data.trend} />
              </CardContent>
            </Card>
          </div>
          <Card>
            <CardHeader>
              <CardTitle>Top risks</CardTitle>
            </CardHeader>
            <CardContent>
              {risk.data.top_risks.length === 0 ? (
                <p className="text-sm text-muted-foreground">No active findings.</p>
              ) : (
                <ol aria-label="Top risks" className="space-y-2">
                  {risk.data.top_risks.map((f) => (
                    <li key={f.id} className="flex items-center gap-3">
                      <RiskScore score={f.risk_score} band={f.risk_band} />
                      <Link to={`/projects/${projectId}/findings/${f.id}`} className="text-sm text-primary hover:underline">
                        {f.title}
                      </Link>
                    </li>
                  ))}
                </ol>
              )}
            </CardContent>
          </Card>
        </>
      )}
    </div>
  );
}
