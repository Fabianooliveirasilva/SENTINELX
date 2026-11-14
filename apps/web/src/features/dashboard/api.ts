import { z } from "zod";

import { SEVERITIES } from "@/features/findings/api";
import { apiRequest } from "@/lib/api-client";

const severity = z.enum(SEVERITIES);

export const dashboardSchema = z.object({
  generated_at: z.string(),
  scope: z.object({ project_id: z.string().nullable(), projects: z.number().int() }),
  totals: z.object({
    assets: z.number().int(),
    active_scans: z.number().int(),
    active_findings: z.number().int(),
    critical_findings: z.number().int(),
    high_findings: z.number().int(),
    known_exploited_findings: z.number().int(),
  }),
  posture: z.object({
    score: z.number(),
    band: severity,
    worst_project: z.object({ id: z.string(), name: z.string() }).nullable(),
  }),
  posture_trend: z.array(z.object({ day: z.string(), score: z.number() })),
  risk_distribution: z.record(severity, z.number().int()),
  assets_by_exposure: z.record(z.string(), z.number().int()),
  scan_activity: z.array(
    z.object({
      day: z.string(),
      completed: z.number().int(),
      failed: z.number().int(),
      cancelled: z.number().int(),
      active: z.number().int(),
    }),
  ),
  remediation: z.object({
    weekly: z.array(z.object({ week: z.string(), opened: z.number().int(), resolved: z.number().int() })),
    by_status: z.record(z.string(), z.number().int()),
    closed_ratio: z.number().nullable(),
  }),
  recent_findings: z.array(
    z.object({
      id: z.string(),
      project_id: z.string(),
      project_name: z.string(),
      title: z.string(),
      severity,
      risk_band: severity.nullable(),
      risk_score: z.number().nullable(),
      asset: z.string(),
      first_seen_at: z.string(),
    }),
  ),
  projects: z.array(
    z.object({ id: z.string(), name: z.string(), score: z.number(), band: severity, active: z.number().int() }),
  ),
  empty: z.boolean(),
});
export type Dashboard = z.infer<typeof dashboardSchema>;

export const dashboardKeys = { scope: (projectId: string) => ["dashboard", projectId] as const };

export function getDashboard(projectId: string) {
  return apiRequest("/dashboard", dashboardSchema, { query: { project_id: projectId || undefined } });
}

export const shortDay = (iso: string) =>
  new Date(`${iso}T00:00:00Z`).toLocaleDateString("en-US", { month: "short", day: "numeric", timeZone: "UTC" });
