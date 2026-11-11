import { z } from "zod";

export const componentStatusSchema = z.enum(["ok", "unavailable"]);

export const componentHealthSchema = z.object({
  status: componentStatusSchema,
  latency_ms: z.number().nonnegative().nullable(),
  error: z.enum(["timeout", "unreachable"]).nullable(),
});

export const readinessReportSchema = z.object({
  status: componentStatusSchema,
  version: z.string(),
  components: z.record(z.string(), componentHealthSchema),
});

export type ComponentHealth = z.infer<typeof componentHealthSchema>;
export type ReadinessReport = z.infer<typeof readinessReportSchema>;
