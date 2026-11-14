import { useQuery } from "@tanstack/react-query";
import { Search, ShieldCheck } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router";

import { EmptyState } from "@/components/shared/empty-state";
import { ErrorAlert } from "@/components/shared/inline-alert";
import { PageHeader } from "@/components/shared/page-header";
import { Pagination } from "@/components/shared/pagination";
import { Card, CardContent } from "@/components/ui/card";
import { Input, Select } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { FINDING_STATUSES, SEVERITIES, STATUS_LABELS } from "@/features/findings/api";
import { RiskScore, SeverityBadge } from "@/features/findings/severity";
import { listProjects } from "@/features/projects/api";
import { formatDateTime } from "@/lib/format";

import { listPortfolioFindings, type PortfolioFilters } from "./api";

export function VulnerabilitiesPage() {
  const [filters, setFilters] = useState<PortfolioFilters>({
    page: 1,
    projectId: "",
    severity: "",
    status: "active",
    search: "",
  });
  const projects = useQuery({ queryKey: ["projects", "picker"], queryFn: () => listProjects(1, "") });
  const findings = useQuery({
    queryKey: ["portfolio", "vulnerabilities", filters],
    queryFn: () => listPortfolioFindings(filters),
  });
  const update = (patch: Partial<PortfolioFilters>) => {
    setFilters({ ...filters, page: 1, ...patch });
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Vulnerabilities"
        description="Findings across every project you can access, highest risk first."
      />
      {findings.data ? (
        <ul aria-label="Findings by severity" className="grid grid-cols-2 gap-2 sm:grid-cols-5">
          {SEVERITIES.map((s) => (
            <li key={s} className="rounded-md border border-border bg-surface-raised px-3 py-2">
              <SeverityBadge severity={s} />
              <p className="mt-1 text-xl font-semibold tabular-nums">{findings.data.by_severity[s] ?? 0}</p>
            </li>
          ))}
        </ul>
      ) : null}
      <Card>
        <CardContent className="pt-5">
          <div className="mb-4 flex flex-col gap-2 sm:flex-row">
            <div className="relative flex-1">
              <Search className="pointer-events-none absolute top-2.5 left-3 size-4 text-muted-foreground" aria-hidden="true" />
              <Input
                aria-label="Search findings"
                placeholder="Search title"
                className="pl-9"
                value={filters.search}
                onChange={(e) => {
                  update({ search: e.target.value });
                }}
              />
            </div>
            <Select
              aria-label="Filter by project"
              className="sm:w-44"
              value={filters.projectId}
              onChange={(e) => {
                update({ projectId: e.target.value });
              }}
            >
              <option value="">All projects</option>
              {(projects.data?.items ?? []).map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}
                </option>
              ))}
            </Select>
            <Select
              aria-label="Filter by status"
              className="sm:w-44"
              value={filters.status}
              onChange={(e) => {
                update({ status: e.target.value as PortfolioFilters["status"] });
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
              aria-label="Filter by severity"
              className="sm:w-40"
              value={filters.severity}
              onChange={(e) => {
                update({ severity: e.target.value as PortfolioFilters["severity"] });
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
            <div role="status" aria-label="Loading vulnerabilities" className="space-y-2">
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
              <Table aria-label="Vulnerabilities">
                <THead>
                  <tr>
                    <TH>Risk</TH>
                    <TH>Severity</TH>
                    <TH>Finding</TH>
                    <TH>Project</TH>
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
                        <Link to={`/projects/${f.project_id}/findings/${f.id}`} className="text-sm text-primary hover:underline">
                          {f.title}
                        </Link>
                        <p className="mt-0.5 font-mono text-xs break-all text-muted-foreground">{f.asset}</p>
                      </TD>
                      <TD className="text-sm">
                        <Link to={`/projects/${f.project_id}`} className="hover:underline">
                          {f.project_name}
                        </Link>
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
