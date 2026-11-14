import { z } from "zod";

import { apiDownload, apiRequest, noContent, pageSchema } from "@/lib/api-client";

export const reportSchema = z.object({
  id: z.uuid(),
  project_id: z.uuid(),
  scope: z.enum(["project", "scan"]),
  scan_job_id: z.uuid().nullable(),
  format: z.enum(["pdf", "json"]),
  title: z.string(),
  parameters: z.record(z.string(), z.unknown()),
  status: z.enum(["pending", "running", "completed", "failed"]),
  schema_version: z.string(),
  size_bytes: z.number().int().nullable(),
  sha256: z.string().nullable(),
  summary: z.record(z.string(), z.unknown()),
  error: z.string().nullable(),
  generated_by_email: z.string().nullable(),
  created_at: z.string(),
  completed_at: z.string().nullable(),
});
export type Report = z.infer<typeof reportSchema>;

export interface ReportInput {
  scope: "project" | "scan";
  scan_job_id?: string | undefined;
  format: "pdf" | "json";
  title?: string;
  include_resolved: boolean;
  include_ai: boolean;
  include_evidence: boolean;
}

export const reportKeys = {
  list: (projectId: string, page: number) => ["reports", projectId, page] as const,
  all: (projectId: string) => ["reports", projectId] as const,
};

const base = (projectId: string) => `/projects/${projectId}/reports`;

export function listReports(projectId: string, page: number) {
  return apiRequest(base(projectId), pageSchema(reportSchema), { query: { page, page_size: 20 } });
}

export function requestReport(projectId: string, body: ReportInput) {
  return apiRequest(base(projectId), reportSchema, { method: "POST", body });
}

export function deleteReport(projectId: string, reportId: string) {
  return apiRequest(`${base(projectId)}/${reportId}`, noContent, { method: "DELETE" });
}

/** Download through the API (authorized and audited), then hand the file to the browser. */
export async function downloadReport(projectId: string, reportId: string): Promise<void> {
  const file = await apiDownload(`${base(projectId)}/${reportId}/download`);
  const url = URL.createObjectURL(file.blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = file.filename;
  link.rel = "noopener";
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => {
    URL.revokeObjectURL(url);
  }, 1000);
}

export const isPending = (r: Report) => r.status === "pending" || r.status === "running";

export function formatBytes(size: number | null): string {
  if (size === null) return "—";
  if (size < 1024) return `${String(size)} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
  return `${(size / 1024 / 1024).toFixed(1)} MB`;
}
