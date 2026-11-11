import { z } from "zod";

import { apiRequest, pageSchema } from "@/lib/api-client";

export const auditEntrySchema = z.object({
  id: z.uuid(),
  created_at: z.string(),
  action: z.string(),
  outcome: z.enum(["success", "failure"]),
  actor_id: z.string().nullable(),
  actor_email: z.string().nullable(),
  target_type: z.string().nullable(),
  target_id: z.string().nullable(),
  project_id: z.string().nullable(),
  ip_address: z.string().nullable(),
  user_agent: z.string().nullable(),
  request_id: z.string().nullable(),
  details: z.record(z.string(), z.unknown()),
});
export type AuditEntry = z.infer<typeof auditEntrySchema>;

export interface AuditFilters {
  page: number;
  action: string;
  outcome: "" | "success" | "failure";
}

export const auditKeys = {
  list: (filters: AuditFilters) => ["audit", "list", filters] as const,
  actions: ["audit", "actions"] as const,
};

export function listAuditLogs(filters: AuditFilters) {
  return apiRequest("/audit-logs", pageSchema(auditEntrySchema), {
    query: { page: filters.page, page_size: 50, action: filters.action, outcome: filters.outcome },
  });
}

export function listAuditActions() {
  return apiRequest("/audit-logs/actions", z.array(z.string()));
}
