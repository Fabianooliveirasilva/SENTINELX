import { z } from "zod";

import { apiRequest, pageSchema } from "@/lib/api-client";

export const cveSchema = z.object({
  id: z.string(),
  source: z.string(),
  description: z.string(),
  status: z.string(),
  published_at: z.string().nullable(),
  last_modified_at: z.string().nullable(),
  cvss_version: z.string().nullable(),
  cvss_vector: z.string().nullable(),
  cvss_score: z.number().nullable(),
  cvss_severity: z.string().nullable(),
  cwes: z.array(z.string()),
  kev_added_on: z.string().nullable(),
  fetched_at: z.string(),
});
export type Cve = z.infer<typeof cveSchema>;

export const cveDetailSchema = cveSchema.extend({
  cvss31_vector: z.string().nullable(),
  cvss31_score: z.number().nullable(),
  cvss40_vector: z.string().nullable(),
  cvss40_score: z.number().nullable(),
  references: z.array(z.string()),
  kev_due_on: z.string().nullable(),
  kev_ransomware: z.string().nullable(),
  matches: z.array(
    z.object({
      criteria: z.string(),
      vendor: z.string(),
      product: z.string(),
      version: z.string(),
      start_including: z.string().nullable(),
      start_excluding: z.string().nullable(),
      end_including: z.string().nullable(),
      end_excluding: z.string().nullable(),
    }),
  ),
});
export type CveDetail = z.infer<typeof cveDetailSchema>;

export const statusSchema = z.object({
  enabled: z.boolean(),
  nvd_api_key_configured: z.boolean(),
  cves: z.number(),
  kev_cves: z.number(),
  sources: z.array(
    z.object({
      name: z.string(),
      synced_at: z.string().nullable(),
      status: z.string(),
      version: z.string().nullable(),
      records: z.number(),
      error: z.string().nullable(),
    }),
  ),
  products: z.array(
    z.object({
      vendor: z.string(),
      product: z.string(),
      requested_at: z.string(),
      synced_at: z.string().nullable(),
      status: z.string(),
      cve_count: z.number(),
      error: z.string().nullable(),
    }),
  ),
});

export const softwareSchema = z.array(
  z.object({
    id: z.uuid(),
    asset_id: z.uuid(),
    source: z.string(),
    name: z.string(),
    version: z.string(),
    raw_version: z.string(),
    cpes: z.array(z.string()),
    location: z.string(),
    correlatable: z.boolean(),
    last_seen_at: z.string(),
    last_scan_job_id: z.string().nullable(),
  }),
);

export interface CveFilters {
  page: number;
  search: string;
  severity: string;
  kev: boolean;
}

export const intelKeys = {
  status: ["intel", "status"] as const,
  cves: (filters: CveFilters) => ["intel", "cves", filters] as const,
  cve: (id: string) => ["intel", "cve", id] as const,
  software: (projectId: string) => ["intel", "software", projectId] as const,
};

export function getIntelStatus() {
  return apiRequest("/intelligence/status", statusSchema);
}

export function searchCves(filters: CveFilters) {
  return apiRequest("/intelligence/cves", pageSchema(cveSchema), {
    query: {
      page: filters.page,
      page_size: 25,
      search: filters.search,
      severity: filters.severity,
      kev: filters.kev ? "true" : "",
    },
  });
}

export function getCve(id: string) {
  return apiRequest(`/intelligence/cves/${encodeURIComponent(id)}`, cveDetailSchema);
}

export function requestProductSync(vendor: string, product: string) {
  return apiRequest("/intelligence/products/sync", statusSchema.shape.products.element, {
    method: "POST",
    body: { vendor, product },
  });
}

export function projectSoftware(projectId: string) {
  return apiRequest(`/projects/${projectId}/software`, softwareSchema);
}

export function describeRange(m: CveDetail["matches"][number]): string {
  if (m.version !== "*" && m.version !== "-") return `version ${m.version}`;
  const parts = [
    m.start_including ? `>= ${m.start_including}` : null,
    m.start_excluding ? `> ${m.start_excluding}` : null,
    m.end_including ? `<= ${m.end_including}` : null,
    m.end_excluding ? `< ${m.end_excluding}` : null,
  ].filter(Boolean);
  return parts.length ? parts.join(" and ") : "all versions";
}
