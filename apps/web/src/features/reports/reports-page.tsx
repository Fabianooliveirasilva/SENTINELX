import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Download, FileText, Trash2 } from "lucide-react";
import { useState } from "react";
import { useParams } from "react-router";

import { EmptyState } from "@/components/shared/empty-state";
import { FormField } from "@/components/shared/form-field";
import { ErrorAlert } from "@/components/shared/inline-alert";
import { PageHeader } from "@/components/shared/page-header";
import { Pagination } from "@/components/shared/pagination";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input, Select } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { useCan } from "@/features/auth/use-auth";
import { ProjectTabs } from "@/features/projects/project-tabs";
import { listScans, scansKeys } from "@/features/scans/api";
import { formatDateTime } from "@/lib/format";

import {
  deleteReport,
  downloadReport,
  formatBytes,
  isPending,
  listReports,
  reportKeys,
  requestReport,
  type Report,
  type ReportInput,
} from "./api";

const POLL_MS = 3_000;

function Builder({ projectId }: { projectId: string }) {
  const queryClient = useQueryClient();
  const [input, setInput] = useState<ReportInput>({
    scope: "project",
    format: "pdf",
    include_resolved: false,
    include_ai: true,
    include_evidence: true,
  });
  const [title, setTitle] = useState("");
  const scans = useQuery({
    queryKey: scansKeys.list(projectId, { page: 1, status: "completed" }),
    queryFn: () => listScans(projectId, { page: 1, status: "completed" }),
    enabled: input.scope === "scan",
  });
  const mutation = useMutation({
    mutationFn: () => requestReport(projectId, { ...input, ...(title.trim() ? { title: title.trim() } : {}) }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: reportKeys.all(projectId) }),
  });
  const toggle = (key: "include_resolved" | "include_ai" | "include_evidence", label: string, hint: string) => (
    <label className="flex items-start gap-2 text-sm" title={hint}>
      <input
        type="checkbox"
        className="mt-0.5"
        checked={input[key]}
        onChange={(e) => {
          setInput({ ...input, [key]: e.target.checked });
        }}
      />
      <span>
        {label}
        <span className="block text-xs text-muted-foreground">{hint}</span>
      </span>
    </label>
  );

  return (
    <Card>
      <CardHeader>
        <CardTitle>New report</CardTitle>
        <CardDescription>
          Generated from stored assessment data. AI commentary is included only from analyses a person has reviewed,
          and is labelled as such.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form
          noValidate
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault();
            mutation.mutate();
          }}
        >
          {mutation.isError ? <ErrorAlert error={mutation.error} /> : null}
          <div className="grid gap-4 sm:grid-cols-3">
            <FormField label="Scope">
              <Select
                value={input.scope}
                onChange={(e) => {
                  const scope = e.target.value as ReportInput["scope"];
                  setInput({ ...input, scope, ...(scope === "project" ? { scan_job_id: undefined } : {}) });
                }}
              >
                <option value="project">Whole project</option>
                <option value="scan">One scan</option>
              </Select>
            </FormField>
            <FormField label="Format">
              <Select
                value={input.format}
                onChange={(e) => {
                  setInput({ ...input, format: e.target.value as ReportInput["format"] });
                }}
              >
                <option value="pdf">PDF</option>
                <option value="json">JSON (machine-readable)</option>
              </Select>
            </FormField>
            <FormField label="Title (optional)">
              <Input
                value={title}
                maxLength={200}
                onChange={(e) => {
                  setTitle(e.target.value);
                }}
              />
            </FormField>
          </div>
          {input.scope === "scan" ? (
            <FormField label="Scan">
              <Select
                value={input.scan_job_id ?? ""}
                onChange={(e) => {
                  setInput({ ...input, scan_job_id: e.target.value || undefined });
                }}
              >
                <option value="">Select a completed scan…</option>
                {(scans.data?.items ?? []).map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.target} · {s.scanner}/{s.profile} · {formatDateTime(s.created_at)}
                  </option>
                ))}
              </Select>
            </FormField>
          ) : null}
          <div className="grid gap-3 sm:grid-cols-3">
            {toggle("include_evidence", "Technical evidence", "Bounded excerpts of tool output per finding.")}
            {toggle("include_ai", "Reviewed AI commentary", "Only analyses marked as reviewed.")}
            {toggle("include_resolved", "Closed findings", "Resolved, false positive and accepted risk.")}
          </div>
          <div className="flex justify-end">
            <Button type="submit" disabled={mutation.isPending || (input.scope === "scan" && !input.scan_job_id)}>
              <FileText aria-hidden="true" />
              {mutation.isPending ? "Requesting…" : "Generate report"}
            </Button>
          </div>
        </form>
      </CardContent>
    </Card>
  );
}

function ReportRow({ projectId, report, canGenerate }: { projectId: string; report: Report; canGenerate: boolean }) {
  const queryClient = useQueryClient();
  const download = useMutation({ mutationFn: () => downloadReport(projectId, report.id) });
  const remove = useMutation({
    mutationFn: () => deleteReport(projectId, report.id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: reportKeys.all(projectId) }),
  });
  const tone = report.status === "completed" ? "ok" : report.status === "failed" ? "down" : "degraded";
  return (
    <TR>
      <TD>
        <span className="text-sm font-medium">{report.title}</span>
        <span className="block text-xs text-muted-foreground">
          {report.scope === "scan" ? "Scan" : "Project"} · {report.generated_by_email ?? "—"} ·{" "}
          {formatDateTime(report.created_at)}
        </span>
        {report.error ? <span className="block text-xs text-status-down">{report.error}</span> : null}
        {download.isError ? <ErrorAlert error={download.error} /> : null}
        {remove.isError ? <ErrorAlert error={remove.error} /> : null}
      </TD>
      <TD className="font-mono text-xs uppercase">{report.format}</TD>
      <TD>
        <Badge tone={tone}>{report.status}</Badge>
      </TD>
      <TD className="text-xs tabular-nums">{formatBytes(report.size_bytes)}</TD>
      <TD className="font-mono text-[11px] text-muted-foreground" title={report.sha256 ?? ""}>
        {report.sha256 ? `${report.sha256.slice(0, 12)}…` : "—"}
      </TD>
      <TD>
        <div className="flex justify-end gap-1">
          <Button
            size="sm"
            variant="ghost"
            disabled={report.status !== "completed" || download.isPending}
            onClick={() => {
              download.mutate();
            }}
          >
            <Download aria-hidden="true" />
            Download
          </Button>
          {canGenerate ? (
            <Button
              size="sm"
              variant="ghost"
              aria-label={`Delete ${report.title}`}
              disabled={remove.isPending}
              onClick={() => {
                if (window.confirm(`Delete report "${report.title}"?`)) remove.mutate();
              }}
            >
              <Trash2 aria-hidden="true" />
            </Button>
          ) : null}
        </div>
      </TD>
    </TR>
  );
}

export function ReportsPage() {
  const { projectId = "" } = useParams();
  const canGenerate = useCan("reports:generate");
  const [page, setPage] = useState(1);
  const reports = useQuery({
    queryKey: reportKeys.list(projectId, page),
    queryFn: () => listReports(projectId, page),
    refetchInterval: (query) => (query.state.data?.items.some(isPending) ? POLL_MS : false),
  });
  return (
    <div className="space-y-6">
      <PageHeader
        title="Reports"
        description="PDF and JSON reports with scope, authorization references, methodology, findings, evidence, risk prioritization and remediation."
      />
      <ProjectTabs projectId={projectId} />
      {canGenerate ? <Builder projectId={projectId} /> : null}
      <Card>
        <CardContent className="pt-5">
          {reports.isPending ? (
            <Skeleton className="h-10 w-full" />
          ) : reports.isError ? (
            <ErrorAlert error={reports.error} />
          ) : reports.data.items.length === 0 ? (
            <EmptyState icon={FileText} title="No reports yet" />
          ) : (
            <>
              <Table aria-label="Reports">
                <THead>
                  <tr>
                    <TH>Report</TH>
                    <TH>Format</TH>
                    <TH>Status</TH>
                    <TH>Size</TH>
                    <TH>SHA-256</TH>
                    <TH className="text-right">Actions</TH>
                  </tr>
                </THead>
                <TBody>
                  {reports.data.items.map((r) => (
                    <ReportRow key={r.id} projectId={projectId} report={r} canGenerate={canGenerate} />
                  ))}
                </TBody>
              </Table>
              <Pagination
                page={page}
                pageSize={reports.data.page_size}
                total={reports.data.total}
                onPageChange={setPage}
              />
            </>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
