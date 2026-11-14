import { screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { jsonResponse, mockFetch, renderRoutes, signInAs } from "@/test-utils";

import { routes } from "./routes";

const readiness = { status: "ok", version: "0.2.0", components: {} };

describe("routes", () => {
  it("redirects anonymous users to the login page, preserving the destination", async () => {
    // Session bootstrap: refresh fails -> anonymous.
    mockFetch(jsonResponse({ error: { code: "not_authenticated", message: "x", request_id: null } }, { status: 401 }));

    renderRoutes(routes, "/audit-logs");

    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeInTheDocument();
  });

  it("renders the application shell for authenticated users", async () => {
    signInAs("admin");
    mockFetch(jsonResponse(readiness));

    renderRoutes(routes, "/system-status");

    const nav = screen.getByRole("navigation", { name: "Primary" });
    expect(nav).toHaveTextContent("Dashboard");
    expect(nav).toHaveTextContent("System Status");
    expect(nav).toHaveTextContent("Users & Roles");
    expect(nav).toHaveTextContent("Audit Logs");
    expect(await screen.findByText("No components reported.")).toBeInTheDocument();
  });

  it("hides navigation entries the user has no permission for", () => {
    signInAs("viewer", ["projects:read"]);
    mockFetch(jsonResponse(readiness));

    renderRoutes(routes, "/system-status");

    const nav = screen.getByRole("navigation", { name: "Primary" });
    expect(nav).toHaveTextContent("Projects");
    expect(nav).not.toHaveTextContent("Users & Roles");
    expect(nav).not.toHaveTextContent("Audit Logs");
  });

  it("shows access denied when visiting a page without permission", () => {
    signInAs("viewer", ["projects:read"]);

    renderRoutes(routes, "/users");

    expect(screen.getByRole("heading", { name: "Access denied" })).toBeInTheDocument();
  });

  it("renders a 404 page for unknown paths", () => {
    signInAs("admin");

    renderRoutes(routes, "/does-not-exist");

    expect(screen.getByRole("heading", { name: "Page not found" })).toBeInTheDocument();
  });
});
