import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, type RenderResult } from "@testing-library/react";
import type { ReactElement } from "react";
import { createMemoryRouter, RouterProvider, type RouteObject } from "react-router";
import { vi } from "vitest";

import type { CurrentUser } from "@/features/auth/schemas";
import { sessionStore } from "@/features/auth/session-store";

/** Render routes with an isolated, non-retrying QueryClient. */
export function renderRoutes(routes: RouteObject[], initialPath = "/"): RenderResult {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false, refetchInterval: false } },
  });
  const router = createMemoryRouter(routes, { initialEntries: [initialPath] });
  return render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
}

export function renderWithRouter(element: ReactElement): RenderResult {
  return renderRoutes([{ path: "*", element }]);
}

export function jsonResponse(body: unknown, init: ResponseInit = {}): Response {
  const headers = new Headers(init.headers);
  headers.set("Content-Type", "application/json");
  return new Response(JSON.stringify(body), { status: 200, ...init, headers });
}

/** Stub global fetch with a sequence of responses (or errors) and return the mock. */
export function mockFetch(...results: (Response | Error)[]) {
  const fn = vi.fn<typeof fetch>();
  for (const result of results) {
    if (result instanceof Error) fn.mockRejectedValueOnce(result);
    else fn.mockResolvedValueOnce(result);
  }
  vi.stubGlobal("fetch", fn);
  return fn;
}

export const ALL_PERMISSIONS = [
  "users:read",
  "users:manage",
  "roles:read",
  "projects:read",
  "projects:manage",
  "audit:read",
  "settings:manage",
  "assets:read",
  "assets:write",
  "scans:read",
  "scans:execute",
];

/** Put the session store in an authenticated state for component tests. */
export function signInAs(
  role: CurrentUser["role"] = "admin",
  permissions: string[] = role === "admin" ? ALL_PERMISSIONS : ["projects:read"],
): CurrentUser {
  const user: CurrentUser = {
    id: "00000000-0000-4000-8000-000000000001",
    email: `${role}@example.com`,
    full_name: "Test User",
    role,
    permissions,
  };
  sessionStore.setSession("test-access-token", user);
  return user;
}

export const tokenResponse = (role: CurrentUser["role"] = "admin") => ({
  access_token: "fresh-token",
  token_type: "bearer",
  expires_in: 600,
  user: {
    id: "00000000-0000-4000-8000-000000000001",
    email: `${role}@example.com`,
    full_name: "Test User",
    role,
    permissions: role === "admin" ? ALL_PERMISSIONS : ["projects:read"],
  },
});

export function requestUrl(input: RequestInfo | URL | undefined): string {
  if (input === undefined) return "";
  if (typeof input === "string") return input;
  return input instanceof URL ? input.href : input.url;
}

export function requestBody(init: RequestInit | undefined): unknown {
  return typeof init?.body === "string" ? (JSON.parse(init.body) as unknown) : undefined;
}

type RouteResponse = Response | (() => Response);

/**
 * Stub fetch by "METHOD /api/v1/path" (query string ignored). Each route may
 * hold a queue of responses; the last one is reused once the queue drains.
 * Unmatched requests fail the test loudly.
 */
export function mockApi(routes: Record<string, RouteResponse | RouteResponse[]>) {
  const queues = new Map(
    Object.entries(routes).map(([key, value]) => [key, Array.isArray(value) ? [...value] : [value]]),
  );
  const fn = vi.fn<typeof fetch>((input, init) => {
    const url = new URL(requestUrl(input), "http://localhost");
    const key = `${init?.method ?? "GET"} ${url.pathname}`;
    const queue = queues.get(key);
    if (!queue || queue.length === 0) return Promise.reject(new Error(`Unexpected request: ${key}`));
    const next = queue.length > 1 ? queue.shift() : queue[0];
    if (!next) return Promise.reject(new Error(`Unexpected request: ${key}`));
    return Promise.resolve(typeof next === "function" ? next() : next.clone());
  });
  vi.stubGlobal("fetch", fn);
  return fn;
}
