import { useQuery } from "@tanstack/react-query";
import { Boxes, Search } from "lucide-react";
import { useState } from "react";
import { Link, useParams } from "react-router";

import { EmptyState } from "@/components/shared/empty-state";
import { ErrorAlert } from "@/components/shared/inline-alert";
import { PageHeader } from "@/components/shared/page-header";
import { Pagination } from "@/components/shared/pagination";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { Input, Select } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { useCan } from "@/features/auth/use-auth";
import { ProjectTabs } from "@/features/projects/project-tabs";

import { ASSET_TYPE_LABELS, ASSET_TYPES, assetsKeys, listAssets, type AssetFilters } from "./api";
import { EligibilityBadges } from "./eligibility-badges";
import { RegisterAssetDialog } from "./register-asset-dialog";

export function AssetsPage() {
  const { projectId = "" } = useParams();
  const canWrite = useCan("assets:write");
  const [filters, setFilters] = useState<AssetFilters>({ page: 1, type: "", status: "active", search: "" });
  const assets = useQuery({
    queryKey: assetsKeys.list(projectId, filters),
    queryFn: () => listAssets(projectId, filters),
  });
  const update = (patch: Partial<AssetFilters>) => {
    setFilters({ ...filters, page: 1, ...patch });
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Asset inventory"
        description="Registered assets and whether they may be tested right now."
        actions={canWrite ? <RegisterAssetDialog projectId={projectId} /> : null}
      />
      <ProjectTabs projectId={projectId} />
      <Card>
        <CardContent className="pt-5">
          <div className="mb-4 flex flex-col gap-2 sm:flex-row">
            <div className="relative flex-1">
              <Search className="pointer-events-none absolute top-2.5 left-3 size-4 text-muted-foreground" aria-hidden="true" />
              <Input
                aria-label="Search assets"
                placeholder="Search by value"
                className="pl-9"
                value={filters.search}
                onChange={(e) => {
                  update({ search: e.target.value });
                }}
              />
            </div>
            <Select
              aria-label="Filter by type"
              className="sm:w-48"
              value={filters.type}
              onChange={(e) => {
                update({ type: e.target.value as AssetFilters["type"] });
              }}
            >
              <option value="">All types</option>
              {ASSET_TYPES.map((t) => (
                <option key={t} value={t}>
                  {ASSET_TYPE_LABELS[t]}
                </option>
              ))}
            </Select>
            <Select
              aria-label="Filter by status"
              className="sm:w-40"
              value={filters.status}
              onChange={(e) => {
                update({ status: e.target.value as AssetFilters["status"] });
              }}
            >
              <option value="active">Active</option>
              <option value="archived">Archived</option>
              <option value="">All</option>
            </Select>
          </div>
          {assets.isPending ? (
            <div role="status" aria-label="Loading assets" className="space-y-2">
              <Skeleton className="h-10 w-full" />
              <Skeleton className="h-10 w-full" />
            </div>
          ) : assets.isError ? (
            <ErrorAlert error={assets.error} />
          ) : assets.data.items.length === 0 ? (
            <EmptyState icon={Boxes} title="No assets match these filters">
              {canWrite ? "Register the domains, IPs and applications you are authorized to assess." : null}
            </EmptyState>
          ) : (
            <>
              <Table aria-label="Assets">
                <THead>
                  <tr>
                    <TH>Asset</TH>
                    <TH>Type</TH>
                    <TH>Criticality</TH>
                    <TH>Eligibility</TH>
                  </tr>
                </THead>
                <TBody>
                  {assets.data.items.map((asset) => (
                    <TR key={asset.id}>
                      <TD>
                        <Link to={`/projects/${projectId}/assets/${asset.id}`} className="font-mono text-sm text-primary hover:underline">
                          {asset.value}
                        </Link>
                        {asset.tags.length > 0 ? (
                          <div className="mt-1 flex flex-wrap gap-1">
                            {asset.tags.map((tag) => (
                              <Badge key={tag}>{tag}</Badge>
                            ))}
                          </div>
                        ) : null}
                      </TD>
                      <TD className="text-sm">{ASSET_TYPE_LABELS[asset.type]}</TD>
                      <TD className="text-sm capitalize">{asset.criticality}</TD>
                      <TD>
                        {asset.status === "archived" ? <Badge>Archived</Badge> : <EligibilityBadges eligibility={asset.eligibility} />}
                      </TD>
                    </TR>
                  ))}
                </TBody>
              </Table>
              <Pagination
                page={filters.page}
                pageSize={assets.data.page_size}
                total={assets.data.total}
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
