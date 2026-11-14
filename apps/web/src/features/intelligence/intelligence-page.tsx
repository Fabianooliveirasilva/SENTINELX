import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { DatabaseZap, Search } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router";

import { EmptyState } from "@/components/shared/empty-state";
import { ErrorAlert } from "@/components/shared/inline-alert";
import { PageHeader } from "@/components/shared/page-header";
import { Pagination } from "@/components/shared/pagination";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input, Select } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { useCan } from "@/features/auth/use-auth";
import { SeverityBadge } from "@/features/findings/severity";
import { formatDateTime } from "@/lib/format";

import { getIntelStatus, intelKeys, requestProductSync, searchCves, type CveFilters } from "./api";
import { asSeverity } from "./severity";

function StatusCard() {
  const canManage = useCan("settings:manage");
  const queryClient = useQueryClient();
  const status = useQuery({ queryKey: intelKeys.status, queryFn: getIntelStatus });
  const sync = useMutation({
    mutationFn: (p: { vendor: string; product: string }) => requestProductSync(p.vendor, p.product),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: intelKeys.status }),
  });
  if (status.isPending) return <Skeleton className="h-24 w-full" />;
  if (status.isError) return <ErrorAlert error={status.error} />;
  const s = status.data;
  return (
    <Card>
      <CardHeader>
        <CardTitle>Sources</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <dl className="grid gap-4 text-sm sm:grid-cols-4">
          <div>
            <dt className="text-xs text-muted-foreground uppercase">CVEs stored</dt>
            <dd className="text-xl font-semibold tabular-nums">{s.cves}</dd>
          </div>
          <div>
            <dt className="text-xs text-muted-foreground uppercase">In CISA KEV</dt>
            <dd className="text-xl font-semibold tabular-nums">{s.kev_cves}</dd>
          </div>
          <div>
            <dt className="text-xs text-muted-foreground uppercase">NVD API key</dt>
            <dd>{s.nvd_api_key_configured ? "configured" : "not configured (slower sync)"}</dd>
          </div>
          <div>
            <dt className="text-xs text-muted-foreground uppercase">Sync</dt>
            <dd>{s.enabled ? "enabled" : "disabled"}</dd>
          </div>
        </dl>
        {sync.isError ? <ErrorAlert error={sync.error} /> : null}
        {s.products.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            No products tracked yet. Products are added automatically when scans detect versioned software.
          </p>
        ) : (
          <Table aria-label="Tracked products">
            <THead>
              <tr>
                <TH>Product (CPE)</TH>
                <TH>Status</TH>
                <TH>CVEs</TH>
                <TH>Synced</TH>
                {canManage ? <TH className="sr-only">Actions</TH> : null}
              </tr>
            </THead>
            <TBody>
              {s.products.map((p) => (
                <TR key={`${p.vendor}:${p.product}`}>
                  <TD className="font-mono text-sm">
                    {p.vendor}:{p.product}
                  </TD>
                  <TD>
                    <Badge tone={p.status === "ok" ? "ok" : p.status === "error" ? "down" : "neutral"}>{p.status}</Badge>
                    {p.error ? <span className="block text-xs text-muted-foreground">{p.error}</span> : null}
                  </TD>
                  <TD className="text-sm tabular-nums">{p.cve_count}</TD>
                  <TD className="text-sm text-muted-foreground">{formatDateTime(p.synced_at)}</TD>
                  {canManage ? (
                    <TD>
                      <Button
                        size="sm"
                        variant="outline"
                        disabled={sync.isPending}
                        onClick={() => {
                          sync.mutate({ vendor: p.vendor, product: p.product });
                        }}
                      >
                        Refresh
                      </Button>
                    </TD>
                  ) : null}
                </TR>
              ))}
            </TBody>
          </Table>
        )}
      </CardContent>
    </Card>
  );
}

export function IntelligencePage() {
  const [filters, setFilters] = useState<CveFilters>({ page: 1, search: "", severity: "", kev: false });
  const cves = useQuery({ queryKey: intelKeys.cves(filters), queryFn: () => searchCves(filters) });
  const update = (patch: Partial<CveFilters>) => {
    setFilters({ ...filters, page: 1, ...patch });
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Threat intelligence"
        description="CVEs from the NVD for software SentinelX has observed, with CISA KEV status."
      />
      <StatusCard />
      <Card>
        <CardContent className="pt-5">
          <div className="mb-4 flex flex-col gap-2 sm:flex-row">
            <div className="relative flex-1">
              <Search className="pointer-events-none absolute top-2.5 left-3 size-4 text-muted-foreground" aria-hidden="true" />
              <Input
                aria-label="Search CVEs"
                placeholder="CVE ID or description"
                className="pl-9"
                value={filters.search}
                onChange={(e) => {
                  update({ search: e.target.value });
                }}
              />
            </div>
            <Select
              aria-label="Filter by severity"
              className="sm:w-40"
              value={filters.severity}
              onChange={(e) => {
                update({ severity: e.target.value });
              }}
            >
              <option value="">All severities</option>
              {["critical", "high", "medium", "low"].map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </Select>
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={filters.kev}
                onChange={(e) => {
                  update({ kev: e.target.checked });
                }}
              />
              Known exploited only
            </label>
          </div>
          {cves.isPending ? (
            <Skeleton className="h-20 w-full" />
          ) : cves.isError ? (
            <ErrorAlert error={cves.error} />
          ) : cves.data.items.length === 0 ? (
            <EmptyState icon={DatabaseZap} title="No CVEs match">
              CVEs are fetched for products detected by scans.
            </EmptyState>
          ) : (
            <>
              <Table aria-label="CVEs">
                <THead>
                  <tr>
                    <TH>CVE</TH>
                    <TH>Severity</TH>
                    <TH>Description</TH>
                  </tr>
                </THead>
                <TBody>
                  {cves.data.items.map((c) => (
                    <TR key={c.id}>
                      <TD className="whitespace-nowrap">
                        <Link to={`/intelligence/cves/${c.id}`} className="font-mono text-sm text-primary hover:underline">
                          {c.id}
                        </Link>
                        {c.kev_added_on ? (
                          <Badge tone="down" className="ml-2">
                            KEV
                          </Badge>
                        ) : null}
                      </TD>
                      <TD className="whitespace-nowrap">
                        <SeverityBadge severity={asSeverity(c.cvss_severity)} />{" "}
                        <span className="text-xs tabular-nums">{c.cvss_score ?? "—"}</span>
                      </TD>
                      <TD className="max-w-xl text-sm text-muted-foreground">
                        <span className="line-clamp-2">{c.description}</span>
                      </TD>
                    </TR>
                  ))}
                </TBody>
              </Table>
              <Pagination
                page={filters.page}
                pageSize={cves.data.page_size}
                total={cves.data.total}
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
