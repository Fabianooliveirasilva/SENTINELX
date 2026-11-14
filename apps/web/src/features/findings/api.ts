import { z } from "zod";

import { apiRequest, pageSchema } from "@/lib/api-client";

export const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
export type Severity = (typeof SEVERITIES)[number];
export const FINDING_STATUSES = ["open", "acknowledged", "false_positive", "accepted_risk", "resolved"] as const;
export type FindingStatus = (typeof FINDING_STATUSES)[number];
export const STATUS_LABELS: Record<FindingStatus, string> = {
  open: "Open",
  acknowledged: "Acknowledged",
  false_positive: "False positive",
  accepted_risk: "Accepted risk",
  resolved: "Resolved",
};
export const REASON_REQUIRED: readonly FindingStatus[] = ["false_positive", "accepted_risk", "resolved"];

export const findingSchema = z.object({
  id: z.uuid(),
  project_id: z.uuid(),
  asset_id: z.uuid(),
  rule_id: z.string(),
  source: z.string(),
  category: z.string(),
  title: z.string(),
  location: z.string(),
  severity: z.enum(SEVERITIES),
  confidence: z.enum(["tentative", "firm", "confirmed"]),
  cwe: z.number().int().nullable(),
  status: z.enum(FINDING_STATUSES),
  status_reason: z.string().nullable(),
  first_seen_at: z.string(),
  last_seen_at: z.string(),
  resolved_at: z.string().nullable(),
  occurrence_count: z.number().int(),
  last_scan_job_id: z.string().nullable(),
  cve_id: z.string().nullable(),
  risk_score: z.number().nullable(),
  risk_band: z.enum(SEVERITIES).nullable(),
});
export type Finding = z.infer<typeof findingSchema>;

export const findingDetailSchema = findingSchema.extend({
  description: z.string(),
  remediation: z.string(),
  references: z.array(z.string()),
  ruleset_version: z.string(),
  risk_factors: z.array(
    z.object({ name: z.string(), value: z.string(), effect: z.string(), points: z.number(), reason: z.string() }),
  ),
  risk_explanation: z.string().nullable(),
  risk_model_version: z.string().nullable(),
  risk_calculated_at: z.string().nullable(),
  risk_history: z.array(
    z.object({
      score: z.number(),
      band: z.enum(SEVERITIES),
      model_version: z.string(),
      trigger: z.string(),
      calculated_at: z.string(),
    }),
  ),
  occurrences: z.array(
    z.object({
      id: z.uuid(),
      scan_job_id: z.string().nullable(),
      observed_at: z.string(),
      observation: z.record(z.string(), z.unknown()),
    }),
  ),
  history: z.array(
    z.object({
      id: z.uuid(),
      from_status: z.enum(FINDING_STATUSES).nullable(),
      to_status: z.enum(FINDING_STATUSES),
      reason: z.string(),
      changed_by_email: z.string().nullable(),
      created_at: z.string(),
    }),
  ),
});
export type FindingDetail = z.infer<typeof findingDetailSchema>;

export const summarySchema = z.object({
  by_status: z.record(z.enum(FINDING_STATUSES), z.number()),
  active_by_severity: z.record(z.enum(SEVERITIES), z.number()),
});

export interface FindingFilters {
  page: number;
  status: FindingStatus | "" | "active";
  severity: Severity | "";
  riskBand: Severity | "";
  sort: "risk" | "severity" | "last_seen";
  search: string;
}

export const findingsKeys = {
  all: (projectId: string) => ["findings", projectId] as const,
  list: (projectId: string, filters: FindingFilters) => ["findings", projectId, "list", filters] as const,
  summary: (projectId: string) => ["findings", projectId, "summary"] as const,
  detail: (projectId: string, id: string) => ["findings", projectId, "detail", id] as const,
};

const base = (projectId: string) => `/projects/${projectId}/findings`;

export function listFindings(projectId: string, filters: FindingFilters) {
  return apiRequest(base(projectId), pageSchema(findingSchema), {
    query: {
      page: filters.page,
      page_size: 25,
      status: filters.status === "active" ? "" : filters.status,
      active: filters.status === "active" ? "true" : "",
      severity: filters.severity,
      risk_band: filters.riskBand,
      sort: filters.sort,
      search: filters.search,
    },
  });
}

export function findingsSummary(projectId: string) {
  return apiRequest(`${base(projectId)}/summary`, summarySchema);
}

export function getFinding(projectId: string, id: string) {
  return apiRequest(`${base(projectId)}/${id}`, findingDetailSchema);
}

export function changeFindingStatus(projectId: string, id: string, status: FindingStatus, reason: string) {
  return apiRequest(`${base(projectId)}/${id}/status`, findingSchema, { method: "POST", body: { status, reason } });
}
