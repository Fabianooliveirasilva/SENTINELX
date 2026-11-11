import { screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { jsonResponse, mockFetch, renderRoutes } from "@/test-utils";

import { routes } from "./routes";

describe("routes", () => {
  it("renders the application shell with primary navigation", async () => {
    mockFetch(jsonResponse({ status: "ok", version: "0.1.0", components: {} }));

    renderRoutes(routes, "/");

    expect(screen.getByRole("navigation", { name: "Primary" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "System Status" })).toBeInTheDocument();
    expect(await screen.findByText("No components reported.")).toBeInTheDocument();
  });

  it("renders a 404 page for unknown paths", () => {
    renderRoutes(routes, "/does-not-exist");

    expect(screen.getByRole("heading", { name: "Page not found" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /back to system status/i })).toHaveAttribute(
      "href",
      "/",
    );
  });
});
