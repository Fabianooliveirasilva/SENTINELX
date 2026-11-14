import { z } from "zod";

import { FINDING_STATUSES, SEVERITIES } from "@/features/findings/api";
import { apiRequest } from "@/lib/api-client";

const severity = z.enum(SEVERITIES);

export const portfolioFindingSchema = z.object({
  id: z.string(),
  project_id: z.string(),
  project_name: z.string(),
  asset: z.string(),
  title: z.string(),
  severity,
  status: z.enum(FINDING_STATUSES),
  source: z.string(),
  risk_band: severity.nullable(),
  risk_score: z.number().nullable(),
  cve_id: z.string().nullable(),
  first_seen_at: z.string(),
  last_seen_at: z.string(),
});

export const portfolioPageSchema = z.object({
  items: z.array(portfolioFindingSchema),
  total: z.number().int(),
  page: z.number().int(),
  page_size: z.number().int(),
  by_severity: z.record(z.string(), z.number().int()),
});

export interface PortfolioFilters {
  page: number;
  projectId: string;
  severity: "" | (typeof SEVERITIES)[number];
  status: "active" | "" | (typeof FINDING_STATUSES)[number];
  search: string;
}

export function listPortfolioFindings(f: PortfolioFilters) {
  return apiRequest("/vulnerabilities", portfolioPageSchema, {
    query: {
      page: f.page,
      page_size: 25,
      project_id: f.projectId,
      severity: f.severity,
      status: f.status === "active" ? "" : f.status,
      active: f.status === "active" ? "true" : f.status === "" ? "false" : "",
      search: f.search,
    },
  });
}

export const reconSchema = z.object({
  generated_at: z.string(),
  projects: z.number().int(),
  assets_total: z.number().int(),
  assets_new_7d: z.number().int(),
  assets_by_type: z.record(z.string(), z.number().int()),
  assets_by_exposure: z.record(z.string(), z.number().int()),
  scans_30d_by_scanner: z.record(z.string(), z.number().int()),
  scans_30d_by_status: z.record(z.string(), z.number().int()),
  recent_assets: z.array(
    z.object({
      id: z.string(),
      project_id: z.string(),
      project_name: z.string(),
      type: z.string(),
      value: z.string(),
      exposure: z.string(),
      created_at: z.string(),
    }),
  ),
  recent_scans: z.array(
    z.object({
      id: z.string(),
      project_id: z.string(),
      project_name: z.string(),
      scanner: z.string(),
      profile: z.string(),
      target: z.string(),
      status: z.string(),
      created_at: z.string(),
      finished_at: z.string().nullable(),
    }),
  ),
  empty: z.boolean(),
});
export type ReconOverview = z.infer<typeof reconSchema>;

export function getRecon(projectId: string) {
  return apiRequest("/reconnaissance", reconSchema, { query: { project_id: projectId || undefined } });
}
