import { useQuery } from "@tanstack/react-query";
import { ScrollText } from "lucide-react";
import { useState } from "react";

import { EmptyState } from "@/components/shared/empty-state";
import { ErrorAlert } from "@/components/shared/inline-alert";
import { PageHeader } from "@/components/shared/page-header";
import { Pagination } from "@/components/shared/pagination";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { Select } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { formatDateTime } from "@/lib/format";

import { auditKeys, listAuditActions, listAuditLogs, type AuditEntry, type AuditFilters } from "./api";

function describeDetails(details: AuditEntry["details"]): string {
  const entries = Object.entries(details);
  return entries.length === 0 ? "" : entries.map(([k, v]) => `${k}: ${JSON.stringify(v)}`).join(" · ");
}

export function AuditLogsPage() {
  const [filters, setFilters] = useState<AuditFilters>({ page: 1, action: "", outcome: "" });
  const logs = useQuery({ queryKey: auditKeys.list(filters), queryFn: () => listAuditLogs(filters) });
  const actions = useQuery({ queryKey: auditKeys.actions, queryFn: listAuditActions });

  return (
    <div className="space-y-6">
      <PageHeader
        title="Audit Logs"
        description="Append-only record of security-relevant activity. Entries cannot be modified or deleted."
      />
      <Card>
        <CardContent className="pt-5">
          <div className="mb-4 flex flex-col gap-2 sm:flex-row">
            <Select
              aria-label="Filter by action"
              className="sm:w-72"
              value={filters.action}
              onChange={(event) => {
                setFilters({ ...filters, page: 1, action: event.target.value });
              }}
            >
              <option value="">All actions</option>
              {(actions.data ?? []).map((action) => (
                <option key={action} value={action}>
                  {action}
                </option>
              ))}
            </Select>
            <Select
              aria-label="Filter by outcome"
              className="sm:w-44"
              value={filters.outcome}
              onChange={(event) => {
                setFilters({ ...filters, page: 1, outcome: event.target.value as AuditFilters["outcome"] });
              }}
            >
              <option value="">All outcomes</option>
              <option value="success">Success</option>
              <option value="failure">Failure</option>
            </Select>
          </div>
          {logs.isPending ? (
            <div role="status" aria-label="Loading audit log" className="space-y-2">
              <Skeleton className="h-10 w-full" />
              <Skeleton className="h-10 w-full" />
            </div>
          ) : logs.isError ? (
            <ErrorAlert error={logs.error} />
          ) : logs.data.items.length === 0 ? (
            <EmptyState icon={ScrollText} title="No audit entries match these filters" />
          ) : (
            <>
              <Table aria-label="Audit log entries">
                <THead>
                  <tr>
                    <TH>Time</TH>
                    <TH>Action</TH>
                    <TH>Actor</TH>
                    <TH>Target</TH>
                    <TH>Source</TH>
                  </tr>
                </THead>
                <TBody>
                  {logs.data.items.map((entry) => (
                    <TR key={entry.id}>
                      <TD className="text-xs whitespace-nowrap text-muted-foreground">{formatDateTime(entry.created_at)}</TD>
                      <TD>
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-xs">{entry.action}</span>
                          <Badge tone={entry.outcome === "success" ? "ok" : "down"}>{entry.outcome}</Badge>
                        </div>
                        {Object.keys(entry.details).length > 0 ? (
                          <div className="mt-1 max-w-md truncate text-xs text-muted-foreground">{describeDetails(entry.details)}</div>
                        ) : null}
                      </TD>
                      <TD className="text-xs">{entry.actor_email ?? <span className="text-muted-foreground">anonymous</span>}</TD>
                      <TD className="font-mono text-xs text-muted-foreground">
                        {entry.target_type ? `${entry.target_type}:${(entry.target_id ?? "").slice(0, 8)}` : "—"}
                      </TD>
                      <TD className="font-mono text-xs text-muted-foreground">
                        {entry.ip_address ?? "—"}
                        {entry.request_id ? <div title="Request ID">{entry.request_id.slice(0, 8)}</div> : null}
                      </TD>
                    </TR>
                  ))}
                </TBody>
              </Table>
              <Pagination
                page={filters.page}
                pageSize={logs.data.page_size}
                total={logs.data.total}
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
