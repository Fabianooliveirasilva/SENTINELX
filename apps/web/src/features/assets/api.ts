import { z } from "zod";

import { apiRequest, pageSchema } from "@/lib/api-client";

export const ASSET_TYPES = ["domain", "subdomain", "ip_address", "web_application", "api_endpoint", "service"] as const;
export type AssetType = (typeof ASSET_TYPES)[number];

export const ASSET_TYPE_LABELS: Record<AssetType, string> = {
  domain: "Domain",
  subdomain: "Subdomain",
  ip_address: "IP address",
  web_application: "Web application",
  api_endpoint: "API endpoint",
  service: "Service",
};

export const ASSET_TYPE_PLACEHOLDERS: Record<AssetType, string> = {
  domain: "example.com",
  subdomain: "api.example.com",
  ip_address: "93.184.215.14",
  web_application: "https://app.example.com/",
  api_endpoint: "https://api.example.com/v1/",
  service: "mail.example.com:587",
};

export const CRITICALITIES = ["low", "medium", "high", "critical"] as const;
export const EXPOSURES = ["external", "internal", "unknown"] as const;
export const TECHNIQUES = ["passive", "active", "intrusive"] as const;
export type Technique = (typeof TECHNIQUES)[number];

const eligibilitySchema = z.object({
  passive: z.boolean(),
  active: z.boolean(),
  intrusive: z.boolean(),
  reasons: z.array(z.string()),
});

export const assetSchema = z.object({
  id: z.uuid(),
  project_id: z.uuid(),
  type: z.enum(ASSET_TYPES),
  value: z.string(),
  description: z.string(),
  tags: z.array(z.string()),
  criticality: z.enum(CRITICALITIES),
  exposure: z.enum(EXPOSURES),
  status: z.enum(["active", "archived"]),
  created_at: z.string(),
  updated_at: z.string(),
  eligibility: eligibilitySchema,
  active_authorizations: z.number().int().nonnegative(),
});
export type Asset = z.infer<typeof assetSchema>;

export const authorizationSchema = z.object({
  id: z.uuid(),
  authorized_by: z.string(),
  organization: z.string(),
  reference: z.string(),
  notes: z.string(),
  valid_from: z.string(),
  valid_until: z.string(),
  allow_active: z.boolean(),
  allow_intrusive: z.boolean(),
  include_subdomains: z.boolean(),
  ip_ranges: z.array(z.string()),
  status: z.enum(["active", "scheduled", "expired", "revoked"]),
  recorded_by_id: z.string().nullable(),
  created_at: z.string(),
  revoked_at: z.string().nullable(),
  revocation_reason: z.string().nullable(),
});
export type Authorization = z.infer<typeof authorizationSchema>;

export const assetDetailSchema = assetSchema.extend({ authorizations: z.array(authorizationSchema) });
export type AssetDetail = z.infer<typeof assetDetailSchema>;

const historySchema = z.array(
  z.object({
    id: z.uuid(),
    created_at: z.string(),
    action: z.string(),
    actor_email: z.string().nullable(),
    details: z.record(z.string(), z.unknown()),
  }),
);

export const scopeDecisionSchema = z.object({
  allowed: z.boolean(),
  target: z.string(),
  technique: z.enum(TECHNIQUES),
  asset_id: z.string().nullable(),
  authorization_id: z.string().nullable(),
  addresses: z.array(z.object({ address: z.string(), allowed: z.boolean(), reason: z.string().nullable() })),
  reasons: z.array(z.object({ code: z.string(), message: z.string() })),
});
export type ScopeDecision = z.infer<typeof scopeDecisionSchema>;

export interface AssetFilters {
  page: number;
  type: AssetType | "";
  status: "" | "active" | "archived";
  search: string;
}

export const assetsKeys = {
  all: (projectId: string) => ["assets", projectId] as const,
  list: (projectId: string, filters: AssetFilters) => ["assets", projectId, "list", filters] as const,
  detail: (projectId: string, assetId: string) => ["assets", projectId, "detail", assetId] as const,
  history: (projectId: string, assetId: string) => ["assets", projectId, "history", assetId] as const,
};

const base = (projectId: string) => `/projects/${projectId}`;

export function listAssets(projectId: string, filters: AssetFilters) {
  return apiRequest(`${base(projectId)}/assets`, pageSchema(assetSchema), {
    query: { page: filters.page, page_size: 25, type: filters.type, status: filters.status, search: filters.search },
  });
}

export interface NewAsset {
  type: AssetType;
  value: string;
  description: string;
  tags: string[];
  criticality: (typeof CRITICALITIES)[number];
  exposure: (typeof EXPOSURES)[number];
}

export function createAsset(projectId: string, asset: NewAsset) {
  return apiRequest(`${base(projectId)}/assets`, assetDetailSchema, { method: "POST", body: asset });
}

export function getAsset(projectId: string, assetId: string) {
  return apiRequest(`${base(projectId)}/assets/${assetId}`, assetDetailSchema);
}

export function updateAsset(projectId: string, assetId: string, changes: Partial<Omit<NewAsset, "type" | "value">> & { status?: "active" | "archived" }) {
  return apiRequest(`${base(projectId)}/assets/${assetId}`, assetDetailSchema, { method: "PATCH", body: changes });
}

export function assetHistory(projectId: string, assetId: string) {
  return apiRequest(`${base(projectId)}/assets/${assetId}/history`, historySchema);
}

export interface NewAuthorization {
  authorized_by: string;
  organization: string;
  reference: string;
  notes: string;
  valid_from: string;
  valid_until: string;
  allow_active: boolean;
  allow_intrusive: boolean;
  include_subdomains: boolean;
  ip_ranges: string[];
}

export function addAuthorization(projectId: string, assetId: string, body: NewAuthorization) {
  return apiRequest(`${base(projectId)}/assets/${assetId}/authorizations`, authorizationSchema, { method: "POST", body });
}

export function revokeAuthorization(projectId: string, assetId: string, authorizationId: string, reason: string) {
  return apiRequest(`${base(projectId)}/assets/${assetId}/authorizations/${authorizationId}/revoke`, authorizationSchema, {
    method: "POST",
    body: { reason },
  });
}

export function checkScope(projectId: string, target: string, technique: Technique) {
  return apiRequest(`${base(projectId)}/scope/check`, scopeDecisionSchema, { method: "POST", body: { target, technique } });
}
