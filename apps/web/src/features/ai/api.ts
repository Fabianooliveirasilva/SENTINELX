import { z } from "zod";

import { apiRequest, pageSchema } from "@/lib/api-client";

export const ANALYSIS_KINDS = [
  "finding_analysis",
  "scan_summary",
  "scan_comparison",
  "executive_summary",
  "technical_summary",
] as const;
export type AnalysisKind = (typeof ANALYSIS_KINDS)[number];

export const KIND_LABELS: Record<AnalysisKind, string> = {
  finding_analysis: "Finding analysis",
  scan_summary: "Scan summary",
  scan_comparison: "Scan comparison",
  executive_summary: "Executive summary",
  technical_summary: "Technical summary",
};

export const BASES = ["confirmed_evidence", "scanner_hypothesis", "external_intelligence", "ai_recommendation"] as const;
export type Basis = (typeof BASES)[number];

export const BASIS_LABELS: Record<Basis, string> = {
  confirmed_evidence: "Confirmed evidence",
  scanner_hypothesis: "Scanner hypothesis",
  external_intelligence: "External intelligence",
  ai_recommendation: "AI recommendation",
};

const claimSchema = z.object({ text: z.string(), basis: z.enum(BASES), references: z.array(z.string()) });
export const outputSchema = z.object({
  title: z.string(),
  summary: z.string(),
  sections: z.array(z.object({ heading: z.string(), claims: z.array(claimSchema) })),
  recommended_actions: z.array(
    z.object({
      action: z.string(),
      priority: z.enum(["immediate", "short_term", "long_term"]),
      rationale: z.string(),
      references: z.array(z.string()),
    }),
  ),
  investigation_steps: z.array(z.string()),
  limitations: z.array(z.string()),
  confidence: z.enum(["low", "medium", "high"]),
});
export type AnalysisOutput = z.infer<typeof outputSchema>;

export const analysisSchema = z.object({
  id: z.uuid(),
  project_id: z.uuid(),
  kind: z.enum(ANALYSIS_KINDS),
  subject_type: z.string(),
  subject_id: z.uuid(),
  parameters: z.record(z.string(), z.unknown()),
  status: z.enum(["pending", "running", "completed", "failed"]),
  provider: z.enum(["anthropic", "deterministic"]).nullable(),
  model: z.string().nullable(),
  prompt_version: z.string(),
  context_summary: z.record(z.string(), z.unknown()),
  output: outputSchema.nullable(),
  warnings: z.array(z.string()),
  fallback_reason: z.string().nullable(),
  error: z.string().nullable(),
  input_tokens: z.number().int(),
  output_tokens: z.number().int(),
  cost_usd: z.number(),
  duration_ms: z.number().int().nullable(),
  requested_by_id: z.uuid().nullable(),
  reviewed_by_email: z.string().nullable(),
  reviewed_at: z.string().nullable(),
  created_at: z.string(),
  completed_at: z.string().nullable(),
});
export type Analysis = z.infer<typeof analysisSchema>;

export const usageSchema = z.object({
  enabled: z.boolean(),
  model: z.string().nullable(),
  tokens_today: z.number().int(),
  cost_today_usd: z.number(),
  daily_token_budget: z.number().int(),
});

export const aiKeys = {
  all: (projectId: string) => ["ai", projectId] as const,
  usage: (projectId: string) => ["ai", projectId, "usage"] as const,
  list: (projectId: string, subjectId: string, kind: string, page: number) =>
    ["ai", projectId, "list", subjectId, kind, page] as const,
};

const base = (projectId: string) => `/projects/${projectId}/ai`;

export function aiUsage(projectId: string) {
  return apiRequest(`${base(projectId)}/usage`, usageSchema);
}

export function listAnalyses(projectId: string, params: { subjectId?: string; kind?: string; page?: number }) {
  return apiRequest(`${base(projectId)}/analyses`, pageSchema(analysisSchema), {
    query: { subject_id: params.subjectId, kind: params.kind, page: params.page ?? 1, page_size: 20 },
  });
}

export function requestAnalysis(
  projectId: string,
  body: { kind: AnalysisKind; subject_id?: string; compare_with?: string; refresh?: boolean },
) {
  return apiRequest(`${base(projectId)}/analyses`, analysisSchema, { method: "POST", body });
}

export function reviewAnalysis(projectId: string, analysisId: string) {
  return apiRequest(`${base(projectId)}/analyses/${analysisId}/review`, analysisSchema, { method: "POST" });
}

export const isRunning = (a: Analysis) => a.status === "pending" || a.status === "running";
