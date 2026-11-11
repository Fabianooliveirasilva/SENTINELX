import { QueryClient } from "@tanstack/react-query";

import { ApiError } from "@/lib/api-client";

const MAX_RETRIES = 2;

export function createQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        staleTime: 10_000,
        refetchOnWindowFocus: false,
        // Do not retry client errors (4xx) or contract violations; they will not
        // succeed on retry and only add load.
        retry: (failureCount, error) => {
          if (error instanceof ApiError && error.status >= 400 && error.status < 500) return false;
          if (error instanceof ApiError && error.code === "invalid_response") return false;
          return failureCount < MAX_RETRIES;
        },
      },
    },
  });
}
