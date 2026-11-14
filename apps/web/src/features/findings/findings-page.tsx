import { useQuery } from "@tanstack/react-query";
import { Search, ShieldCheck } from "lucide-react";
import { useState } from "react";
import { Link, useParams } from "react-router";

import { EmptyState } from "@/components/shared/empty-state";
import { ErrorAlert } from "@/components/shared/inline-alert";
import { PageHeader } from "@/components/shared/page-header";
import { Pagination } from "@/components/shared/pagination";
import { Card, CardContent } from "@/components/ui/card";
import { Input, Select } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { ProjectTabs } from "@/features/projects/project-tabs";
import { formatDateTime } from "@/lib/format";

import {
  FINDING_STATUSES,
  findingsKeys,
  findingsSummary,
  listFindings,
  SEVERITIES,
  STATUS_LABELS,
  type FindingFilters,
} from "./api";
import { RiskScore, SeverityBadge } from "./severity";

function SeveritySummary({ projectId }: { projectId: string }) {
  const summary = useQuery({ queryKey: findingsKeys.summary(projectId), queryFn: () => findingsSummary(projectId) });
  if (!summary.data) return null;
  return (
    <ul aria-label="Open findings by severity" className="grid grid-cols-2 gap-2 sm:grid-cols-5">
      {SEVERITIES.map((severity) => (
        <li key={severity} className="rounded-md border border-border bg-surface-raised px-3 py-2">
          <SeverityBadge severity={severity} />
          <p className="mt-1 text-xl font-semibold tabular-nums">{summary.data.active_by_severity[severity]}</p>
        </li>
      ))}
    </ul>
  );
}

export function FindingsPage() {
  const { projectId = "" } = useParams();
  const [filters, setFilters] = useState<FindingFilters>({
    page: 1,
    status: "active",
    severity: "",
    riskBand: "",
    sort: "risk",
    search: "",
  });
  const findings = useQuery({
    queryKey: findingsKeys.list(projectId, filters),
    queryFn: () => listFindings(projectId, filters),
  });
  const update = (patch: Partial<FindingFilters>) => {
    setFilters({ ...filters, page: 1, ...patch });
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Findings"
        description="Deduplicated issues derived from scan observations, most severe first."
      />
      <ProjectTabs projectId={projectId} />
      <SeveritySummary projectId={projectId} />
      <Card>
        <CardContent className="pt-5">
          <div className="mb-4 flex flex-col gap-2 sm:flex-row">
            <div className="relative flex-1">
              <Search className="pointer-events-none absolute top-2.5 left-3 size-4 text-muted-foreground" aria-hidden="true" />
              <Input
                aria-label="Search findings"
                placeholder="Search title or location"
                className="pl-9"
                value={filters.search}
                onChange={(e) => {
                  update({ search: e.target.value });
                }}
              />
            </div>
            <Select
              aria-label="Filter by status"
              className="sm:w-44"
              value={filters.status}
              onChange={(e) => {
                update({ status: e.target.value as FindingFilters["status"] });
              }}
            >
              <option value="active">Open + acknowledged</option>
              <option value="">All statuses</option>
              {FINDING_STATUSES.map((s) => (
                <option key={s} value={s}>
                  {STATUS_LABELS[s]}
                </option>
              ))}
            </Select>
            <Select
              aria-label="Filter by risk"
              className="sm:w-36"
              value={filters.riskBand}
              onChange={(e) => {
                update({ riskBand: e.target.value as FindingFilters["riskBand"] });
              }}
            >
              <option value="">Any risk</option>
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>
                  {s} risk
                </option>
              ))}
            </Select>
            <Select
              aria-label="Sort by"
              className="sm:w-36"
              value={filters.sort}
              onChange={(e) => {
                update({ sort: e.target.value as FindingFilters["sort"] });
              }}
            >
              <option value="risk">Risk</option>
              <option value="severity">Severity</option>
              <option value="last_seen">Last seen</option>
            </Select>
            <Select
              aria-label="Filter by severity"
              className="sm:w-40"
              value={filters.severity}
              onChange={(e) => {
                update({ severity: e.target.value as FindingFilters["severity"] });
              }}
            >
              <option value="">All severities</option>
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </Select>
          </div>
          {findings.isPending ? (
            <div role="status" aria-label="Loading findings" className="space-y-2">
              <Skeleton className="h-10 w-full" />
              <Skeleton className="h-10 w-full" />
            </div>
          ) : findings.isError ? (
            <ErrorAlert error={findings.error} />
          ) : findings.data.items.length === 0 ? (
            <EmptyState icon={ShieldCheck} title="No findings match these filters">
              Findings appear here after scans complete.
            </EmptyState>
          ) : (
            <>
              <Table aria-label="Findings">
                <THead>
                  <tr>
                    <TH>Risk</TH>
                    <TH>Severity</TH>
                    <TH>Finding</TH>
                    <TH>Status</TH>
                    <TH>Last seen</TH>
                  </tr>
                </THead>
                <TBody>
                  {findings.data.items.map((f) => (
                    <TR key={f.id}>
                      <TD>
                        <RiskScore score={f.risk_score} band={f.risk_band} />
                      </TD>
                      <TD>
                        <SeverityBadge severity={f.severity} />
                      </TD>
                      <TD>
                        <Link to={`/projects/${projectId}/findings/${f.id}`} className="text-sm text-primary hover:underline">
                          {f.title}
                        </Link>
                        <p className="mt-0.5 font-mono text-xs break-all text-muted-foreground">{f.location}</p>
                      </TD>
                      <TD className="text-sm">{STATUS_LABELS[f.status]}</TD>
                      <TD className="text-sm text-muted-foreground">{formatDateTime(f.last_seen_at)}</TD>
                    </TR>
                  ))}
                </TBody>
              </Table>
              <Pagination
                page={filters.page}
                pageSize={findings.data.page_size}
                total={findings.data.total}
                onPageChange={(page) => {
                  setFilters({ ...filters, page });
                }}
              />
            </>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
