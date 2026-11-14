import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { routes } from "@/app/routes";
import { jsonResponse, mockApi, renderRoutes, requestUrl, signInAs } from "@/test-utils";
import { expectNoA11yViolations } from "@/test-axe";

const PROJECT = "00000000-0000-4000-8000-0000000000f1";
const projects = {
  items: [{ id: PROJECT, name: "Acme", slug: "acme", description: "", created_at: "2026-11-01T00:00:00Z", updated_at: "2026-11-01T00:00:00Z", member_count: 2 }],
  total: 1,
  page: 1,
  page_size: 25,
};
const wait = { timeout: 10_000 };

const vulns = {
  items: [
    {
      id: "00000000-0000-4000-8000-0000000000b1",
      project_id: PROJECT,
      project_name: "Acme",
      asset: "app.example.com",
      title: "<b>Cleartext</b> HTTP",
      severity: "high",
      status: "open",
      source: "http",
      risk_band: "high",
      risk_score: 71,
      cve_id: null,
      first_seen_at: "2026-11-12T10:00:00Z",
      last_seen_at: "2026-11-13T10:00:00Z",
    },
  ],
  total: 1,
  page: 1,
  page_size: 25,
  by_severity: { high: 1 },
};

const recon = {
  generated_at: "2026-11-14T10:00:00Z",
  projects: 1,
  assets_total: 3,
  assets_new_7d: 2,
  assets_by_type: { domain: 1, ip_address: 2 },
  assets_by_exposure: { external: 3, internal: 0, unknown: 0 },
  scans_30d_by_scanner: { dns: 4 },
  scans_30d_by_status: { completed: 4 },
  recent_assets: [
    { id: "00000000-0000-4000-8000-0000000000a1", project_id: PROJECT, project_name: "Acme", type: "domain", value: "example.com", exposure: "external", created_at: "2026-11-13T10:00:00Z" },
  ],
  recent_scans: [
    { id: "00000000-0000-4000-8000-0000000000c1", project_id: PROJECT, project_name: "Acme", scanner: "dns", profile: "safe", target: "example.com", status: "completed", created_at: "2026-11-13T10:00:00Z", finished_at: "2026-11-13T10:01:00Z" },
  ],
  empty: false,
};

describe("Vulnerabilities page", () => {
  it("lists findings across projects as text, links to the project finding, and filters", async () => {
    signInAs("security_analyst", ["projects:read", "findings:read", "assets:read"]);
    const fetchMock = mockApi({
      "GET /api/v1/vulnerabilities": jsonResponse(vulns),
      "GET /api/v1/projects": jsonResponse(projects),
    });
    const { container } = renderRoutes(routes, "/vulnerabilities");
    const table = await screen.findByRole("table", { name: "Vulnerabilities" }, wait);
    expect(within(table).getByRole("link", { name: "<b>Cleartext</b> HTTP" })).toHaveAttribute(
      "href",
      `/projects/${PROJECT}/findings/00000000-0000-4000-8000-0000000000b1`,
    );
    expect(within(table).getByRole("link", { name: "Acme" })).toBeInTheDocument();
    expect(screen.getByRole("list", { name: "Findings by severity" })).toHaveTextContent("1");
    await expectNoA11yViolations(container);

    await userEvent.selectOptions(screen.getByLabelText("Filter by severity"), "high");
    await vi.waitFor(() => {
      expect(fetchMock.mock.calls.some(([input]) => requestUrl(input).includes("severity=high"))).toBe(true);
    });
  });

  it("shows an empty state", async () => {
    signInAs("viewer", ["projects:read", "findings:read"]);
    mockApi({
      "GET /api/v1/vulnerabilities": jsonResponse({ ...vulns, items: [], total: 0, by_severity: {} }),
      "GET /api/v1/projects": jsonResponse(projects),
    });
    renderRoutes(routes, "/vulnerabilities");
    expect(await screen.findByText("No findings match these filters", {}, wait)).toBeInTheDocument();
  });
});

describe("Reconnaissance page", () => {
  it("shows discovery figures, breakdowns and recent activity", async () => {
    signInAs("security_analyst", ["projects:read", "assets:read"]);
    mockApi({
      "GET /api/v1/reconnaissance": jsonResponse(recon),
      "GET /api/v1/projects": jsonResponse(projects),
    });
    const { container } = renderRoutes(routes, "/reconnaissance");
    const figures = await screen.findByRole("region", { name: "Reconnaissance figures" }, wait);
    expect(figures).toHaveTextContent("Assets3");
    expect(figures).toHaveTextContent("New in 7 days2");
    expect(screen.getByRole("list", { name: "Assets by type" })).toHaveTextContent("ip address");
    expect(screen.getByRole("table", { name: "Recent assets" })).toHaveTextContent("example.com");
    expect(screen.getByRole("table", { name: "Recent scans" })).toHaveTextContent("dns · safe");
    await expectNoA11yViolations(container);
  });

  it("guides users without projects", async () => {
    signInAs("viewer", ["projects:read", "assets:read"]);
    mockApi({
      "GET /api/v1/reconnaissance": jsonResponse({ ...recon, empty: true, projects: 0 }),
      "GET /api/v1/projects": jsonResponse({ ...projects, items: [], total: 0 }),
    });
    renderRoutes(routes, "/reconnaissance");
    expect(await screen.findByText("No projects to show yet", {}, wait)).toBeInTheDocument();
  });

  it("is denied to users without asset access", async () => {
    signInAs("viewer", ["projects:read"]);
    mockApi({ "GET /api/v1/projects": jsonResponse(projects) });
    renderRoutes(routes, "/reconnaissance");
    expect(await screen.findByText("Access denied", {}, wait)).toBeInTheDocument();
    expect(screen.queryByRole("region", { name: "Reconnaissance figures" })).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Reconnaissance" })).not.toBeInTheDocument();
  });
});
