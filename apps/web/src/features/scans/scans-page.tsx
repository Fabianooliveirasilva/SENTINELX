import { useQuery } from "@tanstack/react-query";
import { Radar } from "lucide-react";
import { useState } from "react";
import { Link, useParams } from "react-router";

import { EmptyState } from "@/components/shared/empty-state";
import { ErrorAlert } from "@/components/shared/inline-alert";
import { PageHeader } from "@/components/shared/page-header";
import { Pagination } from "@/components/shared/pagination";
import { Card, CardContent } from "@/components/ui/card";
import { Select } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { useCan } from "@/features/auth/use-auth";
import { ProjectTabs } from "@/features/projects/project-tabs";
import { formatDateTime } from "@/lib/format";

import { getControls, isActive, listScans, POLL_INTERVAL_MS, SCAN_STATUSES, scansKeys, type ScanFilters } from "./api";
import { EmergencyControls, HaltedBanner } from "./emergency-stop";
import { NewScanDialog } from "./new-scan-dialog";
import { ScanStatusBadge } from "./scan-status";

export function ScansPage() {
  const { projectId = "" } = useParams();
  const canExecute = useCan("scans:execute");
  const canManage = useCan("settings:manage");
  const [filters, setFilters] = useState<ScanFilters>({ page: 1, status: "" });
  const controls = useQuery({ queryKey: scansKeys.controls, queryFn: getControls });
  const scans = useQuery({
    queryKey: scansKeys.list(projectId, filters),
    queryFn: () => listScans(projectId, filters),
    refetchInterval: (query) =>
      query.state.data?.items.some((job) => isActive(job.status)) ? POLL_INTERVAL_MS : false,
  });
  const halted = controls.data?.halted ?? false;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Scans"
        description="Asynchronous scans of authorized assets with safe, server-defined profiles."
        actions={
          <>
            {canManage && controls.data ? <EmergencyControls controls={controls.data} /> : null}
            {canExecute ? <NewScanDialog projectId={projectId} disabled={halted} /> : null}
          </>
        }
      />
      <ProjectTabs projectId={projectId} />
      {controls.data?.halted ? <HaltedBanner controls={controls.data} /> : null}
      <Card>
        <CardContent className="pt-5">
          <div className="mb-4 flex justify-end">
            <Select
              aria-label="Filter by status"
              className="sm:w-44"
              value={filters.status}
              onChange={(e) => {
                setFilters({ page: 1, status: e.target.value as ScanFilters["status"] });
              }}
            >
              <option value="">All statuses</option>
              {SCAN_STATUSES.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </Select>
          </div>
          {scans.isPending ? (
            <div role="status" aria-label="Loading scans" className="space-y-2">
              <Skeleton className="h-10 w-full" />
              <Skeleton className="h-10 w-full" />
            </div>
          ) : scans.isError ? (
            <ErrorAlert error={scans.error} />
          ) : scans.data.items.length === 0 ? (
            <EmptyState icon={Radar} title="No scans yet">
              {canExecute ? "Start a scan on an asset with a current authorization." : null}
            </EmptyState>
          ) : (
            <>
              <Table aria-label="Scans">
                <THead>
                  <tr>
                    <TH>Target</TH>
                    <TH>Scanner</TH>
                    <TH>Status</TH>
                    <TH>Requested</TH>
                  </tr>
                </THead>
                <TBody>
                  {scans.data.items.map((job) => (
                    <TR key={job.id}>
                      <TD>
                        <Link to={`/projects/${projectId}/scans/${job.id}`} className="font-mono text-sm text-primary hover:underline">
                          {job.target}
                        </Link>
                      </TD>
                      <TD className="text-sm">
                        {job.scanner} <span className="text-muted-foreground">· {job.profile}</span>
                      </TD>
                      <TD>
                        <ScanStatusBadge status={job.status} />
                      </TD>
                      <TD className="text-sm text-muted-foreground">{formatDateTime(job.created_at)}</TD>
                    </TR>
                  ))}
                </TBody>
              </Table>
              <Pagination
                page={filters.page}
                pageSize={scans.data.page_size}
                total={scans.data.total}
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
