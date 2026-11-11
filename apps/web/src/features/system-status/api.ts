import { useQuery } from "@tanstack/react-query";

import { apiRequest } from "@/lib/api-client";

import { readinessReportSchema, type ReadinessReport } from "./schemas";

export const READINESS_REFRESH_MS = 15_000;

export const systemStatusKeys = {
  readiness: ["system-status", "readiness"] as const,
};

export function fetchReadiness(signal?: AbortSignal): Promise<ReadinessReport> {
  // 503 carries a valid report describing which component is unavailable.
  return apiRequest("/health/ready", readinessReportSchema, {
    acceptStatuses: [503],
    ...(signal ? { signal } : {}),
  });
}

export function useReadiness() {
  return useQuery({
    queryKey: systemStatusKeys.readiness,
    queryFn: ({ signal }) => fetchReadiness(signal),
    refetchInterval: READINESS_REFRESH_MS,
  });
}
