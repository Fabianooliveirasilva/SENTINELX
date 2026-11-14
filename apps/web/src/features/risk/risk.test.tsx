import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { routes } from "@/app/routes";
import { jsonResponse, mockApi, renderRoutes, requestBody, signInAs } from "@/test-utils";

const PROJECT = "00000000-0000-4000-8000-0000000000f1";
const model = {
  model_version: "1.0.0",
  weights: { kev_points: 20, exposure_internal: 0.75 },
  defaults: { kev_points: 20, exposure_internal: 0.75 },
  bounds: { kev_points: { min: 0, max: 50 }, exposure_internal: { min: 0.1, max: 2 } },
  bands: { critical: 80, high: 60, medium: 40, low: 15 },
  formula: "base = CVSS x 10 ...",
};
const finding = {
  id: "00000000-0000-4000-8000-0000000000c9",
  project_id: PROJECT,
  asset_id: "00000000-0000-4000-8000-0000000000a1",
  rule_id: "http.cleartext_http",
  source: "http",
  category: "http",
  title: "Web content served over cleartext HTTP",
  location: "1.2.3.4 http://x/",
  severity: "medium",
  confidence: "confirmed",
  cwe: 319,
  status: "open",
  status_reason: null,
  first_seen_at: "2026-11-10T10:00:00Z",
  last_seen_at: "2026-11-11T10:00:00Z",
  resolved_at: null,
  occurrence_count: 1,
  last_scan_job_id: null,
  cve_id: null,
  risk_score: 60.5,
  risk_band: "high",
};

describe("ProjectRiskPage", () => {
  it("shows posture, band counts, top risks and the trend", async () => {
    signInAs("viewer", ["projects:read", "findings:read"]);
    mockApi({
      [`GET /api/v1/projects/${PROJECT}/risk`]: jsonResponse({
        model_version: "1.0.0",
        posture: { score: 62.1, band: "high", active: 2, counts: { critical: 0, high: 1, medium: 0, low: 1, info: 0 } },
        top_risks: [finding],
        trend: [
          { day: "2026-11-10", score: 40, band: "medium", active: 1 },
          { day: "2026-11-11", score: 62.1, band: "high", active: 2 },
        ],
      }),
    });
    renderRoutes(routes, `/projects/${PROJECT}/risk`);
    expect(await screen.findByTestId("posture-score")).toHaveTextContent("62.1");
    expect(screen.getByRole("list", { name: "Active findings by risk band" })).toHaveTextContent("high: 1");
    expect(within(screen.getByRole("list", { name: "Top risks" })).getByRole("link")).toHaveTextContent("cleartext HTTP");
    expect(screen.getByRole("img", { name: /Risk trend over 2 days, latest 62.1/ })).toBeInTheDocument();
  });
});

describe("RiskModelPage", () => {
  it("is read-only for analysts", async () => {
    signInAs("security_analyst", ["projects:read", "findings:read"]);
    mockApi({ "GET /api/v1/risk/model": jsonResponse(model) });
    renderRoutes(routes, "/risk-model");
    expect(await screen.findByTestId("risk-formula")).toHaveTextContent("CVSS x 10");
    expect(screen.getByLabelText("Current weights")).toHaveTextContent("kev points20");
    expect(screen.queryByRole("button", { name: "Save and rescore" })).not.toBeInTheDocument();
  });

  it("lets administrators change weights and reports rescoring", async () => {
    signInAs("admin");
    const fetchMock = mockApi({
      "GET /api/v1/risk/model": jsonResponse(model),
      "PUT /api/v1/risk/weights": jsonResponse({ ...model, weights: { ...model.weights, kev_points: 30 }, rescored: 4 }),
    });
    renderRoutes(routes, "/risk-model");
    const input = await screen.findByLabelText("kev points");
    await userEvent.clear(input);
    await userEvent.type(input, "30");
    await userEvent.click(screen.getByRole("button", { name: "Save and rescore" }));
    expect(await screen.findByText("Weights saved; 4 finding scores changed.")).toBeInTheDocument();
    const put = fetchMock.mock.calls.find(([, init]) => init?.method === "PUT");
    expect(requestBody(put?.[1])).toEqual({ weights: { kev_points: 30, exposure_internal: 0.75 } });
  });
});
