import { z } from "zod";

import { findingSchema, SEVERITIES } from "@/features/findings/api";
import { apiRequest } from "@/lib/api-client";

export const modelSchema = z.object({
  model_version: z.string(),
  weights: z.record(z.string(), z.number()),
  defaults: z.record(z.string(), z.number()),
  bounds: z.record(z.string(), z.object({ min: z.number(), max: z.number() })),
  bands: z.record(z.string(), z.number()),
  formula: z.string(),
});
export type RiskModel = z.infer<typeof modelSchema>;

export const projectRiskSchema = z.object({
  model_version: z.string(),
  posture: z.object({
    score: z.number(),
    band: z.enum(SEVERITIES),
    active: z.number(),
    counts: z.record(z.enum(SEVERITIES), z.number()),
  }),
  top_risks: z.array(findingSchema),
  trend: z.array(z.object({ day: z.string(), score: z.number(), band: z.enum(SEVERITIES), active: z.number() })),
});
export type ProjectRisk = z.infer<typeof projectRiskSchema>;

export const riskKeys = {
  model: ["risk", "model"] as const,
  project: (projectId: string) => ["risk", "project", projectId] as const,
};

export function getRiskModel() {
  return apiRequest("/risk/model", modelSchema);
}

export function updateWeights(weights: Record<string, number>) {
  return apiRequest("/risk/weights", modelSchema.extend({ rescored: z.number() }), {
    method: "PUT",
    body: { weights },
  });
}

export function resetWeights() {
  return apiRequest("/risk/weights/reset", modelSchema.extend({ rescored: z.number() }), { method: "POST" });
}

export function getProjectRisk(projectId: string) {
  return apiRequest(`/projects/${projectId}/risk`, projectRiskSchema);
}
