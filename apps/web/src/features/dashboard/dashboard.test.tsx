import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { routes } from "@/app/routes";
import { jsonResponse, mockApi, renderRoutes, requestUrl, signInAs } from "@/test-utils";

const PROJECT = "00000000-0000-4000-8000-0000000000f1";
const days = (n: number) =>
  Array.from({ length: n }, (_, i) => `2026-11-${String(i + 1).padStart(2, "0")}`);

const dashboard = (overrides: Record<string, unknown> = {}) => ({
  generated_at: "2026-11-13T10:00:00Z",
  scope: { project_id: null, projects: 2 },
  totals: {
    assets: 7,
    active_scans: 1,
    active_findings: 12,
    critical_findings: 2,
    high_findings: 3,
    known_exploited_findings: 1,
  },
  posture: { score: 81.4, band: "critical", worst_project: { id: PROJECT, name: "Acme" } },
  posture_trend: days(5).map((day, i) => ({ day, score: 60 + i * 5 })),
  risk_distribution: { critical: 2, high: 3, medium: 4, low: 2, info: 1 },
  assets_by_exposure: { external: 5, internal: 2, unknown: 0 },
  scan_activity: days(14).map((day, i) => ({ day, completed: i % 3, failed: i % 5 === 0 ? 1 : 0, cancelled: 0, active: 0 })),
  remediation: {
    weekly: days(8).map((week, i) => ({ week, opened: i, resolved: i > 2 ? i - 1 : 0 })),
    by_status: { open: 10, acknowledged: 2, resolved: 6, false_positive: 1, accepted_risk: 1 },
    closed_ratio: 0.4,
  },
  recent_findings: [
    {
      id: "00000000-0000-4000-8000-0000000000b1",
      project_id: PROJECT,
      project_name: "Acme",
      title: "<b>Exposed</b> admin panel",
      severity: "high",
      risk_band: "critical",
      risk_score: 88,
      asset: "app.example.com",
      first_seen_at: "2026-11-12T10:00:00Z",
    },
  ],
  projects: [
    { id: PROJECT, name: "Acme", score: 81.4, band: "critical", active: 9 },
    { id: "00000000-0000-4000-8000-0000000000f2", name: "Beta", score: 30, band: "low", active: 3 },
  ],
  empty: false,
  ...overrides,
});
const projects = {
  items: [{ id: PROJECT, name: "Acme", slug: "acme", description: "", created_at: "2026-11-01T00:00:00Z", updated_at: "2026-11-01T00:00:00Z", member_count: 2 }],
  total: 1,
  page: 1,
  page_size: 25,
};

describe("DashboardPage", () => {
  it("shows key figures, charts with data tables, recent findings and project ranking", async () => {
    signInAs("security_analyst", ["projects:read", "findings:read"]);
    mockApi({
      "GET /api/v1/dashboard": jsonResponse(dashboard()),
      "GET /api/v1/projects": jsonResponse(projects),
    });
    renderRoutes(routes, "/");
    const figures = await screen.findByRole("region", { name: "Key figures" }, { timeout: 10_000 });
    expect(figures).toHaveTextContent("Assets7");
    expect(figures).toHaveTextContent("5 externally exposed");
    expect(figures).toHaveTextContent("Critical findings2");
    expect(figures).toHaveTextContent("3 high · 1 known exploited");
    expect(figures).toHaveTextContent("Posture score81");
    expect(figures).toHaveTextContent("Worst: Acme");
    expect(figures).toHaveTextContent("Closed findings40%");

    // Every chart has a text alternative and a data table.
    expect(screen.getByRole("img", { name: /Risk distribution: Critical 2, High 3, Medium 4, Low 2, Info 1/ })).toBeInTheDocument();
    expect(screen.getByRole("img", { name: /Posture trend: 5 daily points, latest 80 of 100/ })).toBeInTheDocument();
    const riskTable = screen.getByRole("table", { name: "Risk distribution data" });
    expect(within(riskTable).getAllByRole("row")).toHaveLength(6);
    expect(screen.getByRole("table", { name: "Scan activity data" })).toBeInTheDocument();
    expect(screen.getByRole("table", { name: "Remediation progress data" })).toBeInTheDocument();

    const recent = screen.getByRole("list", { name: "Recent findings" });
    // Scanner-derived titles render as text.
    expect(within(recent).getByRole("link", { name: "<b>Exposed</b> admin panel" })).toHaveAttribute(
      "href",
      `/projects/${PROJECT}/findings/00000000-0000-4000-8000-0000000000b1`,
    );
    expect(screen.getByRole("list", { name: "Projects by risk posture" })).toHaveTextContent("Beta");
  });

  it("filters by project", async () => {
    signInAs("security_analyst", ["projects:read", "findings:read"]);
    const fetchMock = mockApi({
      "GET /api/v1/dashboard": jsonResponse(dashboard()),
      "GET /api/v1/projects": jsonResponse(projects),
    });
    renderRoutes(routes, "/");
    await screen.findByRole("region", { name: "Key figures" }, { timeout: 10_000 });
    await userEvent.selectOptions(screen.getByLabelText("Project"), PROJECT);
    await vi.waitFor(() => {
      expect(fetchMock.mock.calls.some(([input]) => requestUrl(input).includes(`project_id=${PROJECT}`))).toBe(true);
    });
  });

  it("guides users without projects", async () => {
    signInAs("viewer", ["projects:read"]);
    mockApi({
      "GET /api/v1/dashboard": jsonResponse(dashboard({ empty: true })),
      "GET /api/v1/projects": jsonResponse({ ...projects, items: [], total: 0 }),
    });
    renderRoutes(routes, "/");
    expect(await screen.findByText("No projects to show yet", {}, { timeout: 10_000 })).toBeInTheDocument();
    expect(screen.getByText("Ask an administrator to add you to a project.")).toBeInTheDocument();
  });

  it("explains a trend that cannot be drawn yet", async () => {
    signInAs("security_analyst", ["projects:read", "findings:read"]);
    mockApi({
      "GET /api/v1/dashboard": jsonResponse(dashboard({ posture_trend: [{ day: "2026-11-13", score: 70 }] })),
      "GET /api/v1/projects": jsonResponse(projects),
    });
    renderRoutes(routes, "/");
    expect(await screen.findByText("The trend appears after two daily snapshots.", {}, { timeout: 10_000 })).toBeInTheDocument();
  });
});
