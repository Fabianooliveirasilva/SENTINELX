import { z } from "zod";

import { scopeDecisionSchema, TECHNIQUES, ASSET_TYPES } from "@/features/assets/api";
import { apiRequest, pageSchema } from "@/lib/api-client";

export const SCAN_STATUSES = ["pending", "queued", "running", "completed", "failed", "cancelled"] as const;
export type ScanStatus = (typeof SCAN_STATUSES)[number];
export const ACTIVE_STATUSES: readonly ScanStatus[] = ["pending", "queued", "running"];

export const isActive = (status: ScanStatus) => ACTIVE_STATUSES.includes(status);

export const scannerSchema = z.object({
  name: z.string(),
  technique: z.enum(TECHNIQUES),
  description: z.string(),
  default_profile: z.string(),
  profiles: z.array(z.object({ name: z.string(), description: z.string() })),
  supported_asset_types: z.array(z.enum(ASSET_TYPES)),
});
export type ScannerInfo = z.infer<typeof scannerSchema>;

export const scanJobSchema = z.object({
  id: z.uuid(),
  project_id: z.uuid(),
  asset_id: z.uuid(),
  scanner: z.string(),
  profile: z.string(),
  technique: z.enum(TECHNIQUES),
  target: z.string(),
  status: z.enum(SCAN_STATUSES),
  requested_by_id: z.string().nullable(),
  created_at: z.string(),
  queued_at: z.string().nullable(),
  started_at: z.string().nullable(),
  finished_at: z.string().nullable(),
  error_code: z.string().nullable(),
  error_message: z.string().nullable(),
  pinned_addresses: z.array(z.string()),
  summary: z.record(z.string(), z.unknown()),
});
export type ScanJob = z.infer<typeof scanJobSchema>;

export const scanResultSchema = z.object({
  id: z.uuid(),
  kind: z.string(),
  key: z.string(),
  data: z.record(z.string(), z.unknown()),
  attention: z.array(z.string()),
});
export type ScanResult = z.infer<typeof scanResultSchema>;

export const scanDetailSchema = scanJobSchema.extend({
  scope_decision: scopeDecisionSchema.nullable(),
  tool_versions: z.record(z.string(), z.string()),
  correlation_id: z.string().nullable(),
  results: z.array(scanResultSchema),
  evidence: z.array(z.object({ id: z.uuid(), label: z.string(), media_type: z.string(), content: z.string() })),
});
export type ScanDetail = z.infer<typeof scanDetailSchema>;

export const controlsSchema = z.object({
  halted: z.boolean(),
  reason: z.string().nullable(),
  updated_at: z.string().nullable(),
  updated_by: z.string().nullable(),
});
export type ScanControls = z.infer<typeof controlsSchema>;

export interface ScanFilters {
  page: number;
  status: ScanStatus | "";
}

export const scansKeys = {
  all: (projectId: string) => ["scans", projectId] as const,
  list: (projectId: string, filters: ScanFilters) => ["scans", projectId, "list", filters] as const,
  detail: (projectId: string, scanId: string) => ["scans", projectId, "detail", scanId] as const,
  scanners: ["scanners"] as const,
  controls: ["scan-controls"] as const,
};

const base = (projectId: string) => `/projects/${projectId}/scans`;

export function listScanners() {
  return apiRequest("/scanners", z.array(scannerSchema));
}

export function listScans(projectId: string, filters: ScanFilters) {
  return apiRequest(base(projectId), pageSchema(scanJobSchema), {
    query: { page: filters.page, page_size: 25, status: filters.status },
  });
}

export function requestScan(projectId: string, body: { asset_id: string; scanner: string; profile: string }) {
  return apiRequest(base(projectId), scanJobSchema, { method: "POST", body });
}

export function getScan(projectId: string, scanId: string) {
  return apiRequest(`${base(projectId)}/${scanId}`, scanDetailSchema);
}

export function cancelScan(projectId: string, scanId: string) {
  return apiRequest(`${base(projectId)}/${scanId}/cancel`, scanJobSchema, { method: "POST" });
}

export function getControls() {
  return apiRequest("/scans/controls", controlsSchema);
}

export function emergencyStop(reason: string) {
  return apiRequest("/scans/emergency-stop", controlsSchema.extend({ cancelled_jobs: z.number() }), {
    method: "POST",
    body: { reason },
  });
}

export function resumeScanning() {
  return apiRequest("/scans/resume", controlsSchema, { method: "POST" });
}

/** Poll every few seconds while a job can still change state. */
export const POLL_INTERVAL_MS = 3000;
