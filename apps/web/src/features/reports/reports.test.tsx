import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { routes } from "@/app/routes";
import { installAuthHandler } from "@/features/auth/api";
import { jsonResponse, mockApi, renderRoutes, requestBody, requestUrl, signInAs } from "@/test-utils";

const PROJECT = "00000000-0000-4000-8000-0000000000f1";
const REPORT = "00000000-0000-4000-8000-0000000000e9";
const page = <T,>(items: T[]) => ({ items, total: items.length, page: 1, page_size: 20 });
const report = (overrides: Record<string, unknown> = {}) => ({
  id: REPORT,
  project_id: PROJECT,
  scope: "project",
  scan_job_id: null,
  format: "pdf",
  title: "Security assessment — Acme",
  parameters: {},
  status: "completed",
  schema_version: "sentinelx-report/1.0",
  size_bytes: 24576,
  sha256: "a".repeat(64),
  summary: {},
  error: null,
  generated_by_email: "analyst@example.com",
  created_at: "2026-11-13T10:00:00Z",
  completed_at: "2026-11-13T10:00:05Z",
  ...overrides,
});

describe("ReportsPage", () => {
  it("lists reports with integrity details and downloads through the API", async () => {
    signInAs("viewer", ["projects:read", "reports:read"]);
    installAuthHandler();
    const fetchMock = mockApi({
      [`GET /api/v1/projects/${PROJECT}/reports`]: jsonResponse(page([report()])),
      [`GET /api/v1/projects/${PROJECT}/reports/${REPORT}/download`]: () =>
        new Response("%PDF-1.4", {
          status: 200,
          headers: {
            "Content-Type": "application/pdf",
            "Content-Disposition": 'attachment; filename="sentinelx-report-project.pdf"',
            "X-Content-SHA256": "a".repeat(64),
          },
        }),
    });
    const createObjectURL = vi.fn(() => "blob:report");
    vi.stubGlobal("URL", Object.assign(URL, { createObjectURL, revokeObjectURL: vi.fn() }));
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => undefined);

    renderRoutes(routes, `/projects/${PROJECT}/reports`);
    const table = await screen.findByRole("table", { name: "Reports" });
    expect(within(table).getByText("Security assessment — Acme")).toBeInTheDocument();
    expect(within(table).getByText("24.0 KB")).toBeInTheDocument();
    expect(within(table).getByText("aaaaaaaaaaaa…")).toBeInTheDocument();
    // Viewers cannot generate or delete.
    expect(screen.queryByRole("button", { name: "Generate report" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Delete/ })).not.toBeInTheDocument();

    await userEvent.click(within(table).getByRole("button", { name: "Download" }));
    await vi.waitFor(() => {
      expect(click).toHaveBeenCalled();
    });
    const call = fetchMock.mock.calls.find(([input]) => requestUrl(input).includes("/download"));
    expect(call?.[1]?.headers).toMatchObject({ Authorization: "Bearer test-access-token" });
    expect(createObjectURL).toHaveBeenCalled();
    click.mockRestore();
  });

  it("requests a report with the chosen options", async () => {
    signInAs("security_analyst", ["projects:read", "reports:read", "reports:generate"]);
    const fetchMock = mockApi({
      [`GET /api/v1/projects/${PROJECT}/reports`]: jsonResponse(page([])),
      [`POST /api/v1/projects/${PROJECT}/reports`]: jsonResponse(report({ status: "pending", sha256: null }), {
        status: 202,
      }),
    });
    renderRoutes(routes, `/projects/${PROJECT}/reports`);
    await userEvent.selectOptions(await screen.findByLabelText("Format"), "json");
    await userEvent.type(screen.getByLabelText("Title (optional)"), "Q4 review");
    await userEvent.click(screen.getByRole("checkbox", { name: /Closed findings/ }));
    await userEvent.click(screen.getByRole("button", { name: "Generate report" }));
    await vi.waitFor(() => {
      expect(fetchMock.mock.calls.some(([, init]) => init?.method === "POST")).toBe(true);
    });
    const post = fetchMock.mock.calls.find(([, init]) => init?.method === "POST");
    expect(requestBody(post?.[1])).toEqual({
      scope: "project",
      format: "json",
      title: "Q4 review",
      include_resolved: true,
      include_ai: true,
      include_evidence: true,
    });
  });

  it("shows failed reports with their reason", async () => {
    signInAs("security_analyst", ["projects:read", "reports:read", "reports:generate"]);
    mockApi({
      [`GET /api/v1/projects/${PROJECT}/reports`]: jsonResponse(
        page([report({ status: "failed", error: "The report queue is unavailable.", sha256: null, size_bytes: null })]),
      ),
    });
    renderRoutes(routes, `/projects/${PROJECT}/reports`);
    const table = await screen.findByRole("table", { name: "Reports" });
    expect(within(table).getByText("The report queue is unavailable.")).toBeInTheDocument();
    expect(within(table).getByRole("button", { name: "Download" })).toBeDisabled();
  });
});
