import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, type RenderResult } from "@testing-library/react";
import type { ReactElement } from "react";
import { createMemoryRouter, RouterProvider, type RouteObject } from "react-router";
import { vi } from "vitest";

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
