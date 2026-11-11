import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { routes } from "@/app/routes";
import { jsonResponse, mockApi, renderRoutes, requestBody, requestUrl, signInAs } from "@/test-utils";

const PROJECT = "00000000-0000-4000-8000-0000000000f1";
const FINDING = "00000000-0000-4000-8000-0000000000c9";
const api = `/api/v1/projects/${PROJECT}/findings`;
const page = <T,>(items: T[]) => ({ items, total: items.length, page: 1, page_size: 25 });

const finding = {
  id: FINDING,
  project_id: PROJECT,
  asset_id: "00000000-0000-4000-8000-0000000000a1",
  rule_id: "zap.40012",
  source: "zap",
  category: "web",
  title: "Cross Site Scripting (Reflected)",
  location: "40012 https://app.example.com",
  severity: "high",
  confidence: "firm",
  cwe: 79,
  status: "open",
  status_reason: null,
  first_seen_at: "2026-11-10T10:00:00Z",
  last_seen_at: "2026-11-11T10:00:00Z",
  resolved_at: null,
  occurrence_count: 2,
  last_scan_job_id: "00000000-0000-4000-8000-0000000000b1",
};
const detail = {
  ...finding,
  description: "<script>alert('desc')</script>",
  remediation: "Encode output.",
  references: ["https://owasp.org/xss"],
  ruleset_version: "2026.11.1",
  occurrences: [
    {
      id: "00000000-0000-4000-8000-0000000000d1",
      scan_job_id: "00000000-0000-4000-8000-0000000000b1",
      observed_at: "2026-11-11T10:00:00Z",
      observation: { kind: "web_alert", data: { attack: "<img src=x onerror=alert(1)>" } },
    },
  ],
  history: [
    {
      id: "00000000-0000-4000-8000-0000000000e1",
      from_status: null,
      to_status: "open",
      reason: "First observed.",
      changed_by_email: null,
      created_at: "2026-11-10T10:00:00Z",
    },
  ],
};
const summary = {
  by_status: { open: 1, acknowledged: 0, false_positive: 0, accepted_risk: 0, resolved: 3 },
  active_by_severity: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
};

describe("FindingsPage", () => {
  it("shows the severity summary and active findings by default", async () => {
    signInAs("viewer", ["projects:read", "findings:read"]);
    const fetchMock = mockApi({
      [`GET ${api}`]: jsonResponse(page([finding])),
      [`GET ${api}/summary`]: jsonResponse(summary),
    });
    renderRoutes(routes, `/projects/${PROJECT}/findings`);

    const table = await screen.findByRole("table", { name: "Findings" });
    expect(within(table).getByRole("link", { name: "Cross Site Scripting (Reflected)" })).toBeInTheDocument();
    const counts = await screen.findByRole("list", { name: "Open findings by severity" });
    expect(counts).toHaveTextContent("high1");
    const listCall = fetchMock.mock.calls.map(([input]) => requestUrl(input)).find((u) => u.includes("/findings?"));
    expect(listCall).toContain("active=true");

    await userEvent.selectOptions(screen.getByLabelText("Filter by severity"), "high");
    const urls = fetchMock.mock.calls.map(([input]) => requestUrl(input));
    expect(urls.some((u) => u.includes("severity=high"))).toBe(true);
  });
});

describe("FindingDetailPage", () => {
  it("renders scanner text inertly and hides triage from viewers", async () => {
    signInAs("viewer", ["projects:read", "findings:read"]);
    mockApi({ [`GET ${api}/${FINDING}`]: jsonResponse(detail) });
    const { container } = renderRoutes(routes, `/projects/${PROJECT}/findings/${FINDING}`);

    expect(await screen.findByRole("heading", { name: "Cross Site Scripting (Reflected)" })).toBeInTheDocument();
    expect(screen.getByText("<script>alert('desc')</script>")).toBeInTheDocument();
    expect(screen.getByText("CWE-79")).toBeInTheDocument();
    expect(screen.getByRole("list", { name: "Status history" })).toHaveTextContent("Open by SentinelX");
    expect(container.querySelector("script, img")).toBeNull();
    expect(screen.queryByRole("button", { name: "Change status" })).not.toBeInTheDocument();
  });

  it("requires a reason before marking a false positive", async () => {
    signInAs("admin");
    const fetchMock = mockApi({
      [`GET ${api}/${FINDING}`]: [
        jsonResponse(detail),
        jsonResponse({ ...detail, status: "false_positive", status_reason: "Input is encoded" }),
      ],
      [`POST ${api}/${FINDING}/status`]: jsonResponse({ ...finding, status: "false_positive" }),
    });
    renderRoutes(routes, `/projects/${PROJECT}/findings/${FINDING}`);

    await userEvent.click(await screen.findByRole("button", { name: "Change status" }));
    const dialog = await screen.findByRole("dialog", { name: "Change finding status" });
    await userEvent.selectOptions(within(dialog).getByLabelText("New status"), "false_positive");
    const save = within(dialog).getByRole("button", { name: "Save" });
    expect(save).toBeDisabled();
    await userEvent.type(within(dialog).getByLabelText("Reason"), "Input is encoded");
    await userEvent.click(save);

    expect(await screen.findByText("Input is encoded")).toBeInTheDocument();
    const post = fetchMock.mock.calls.find(([, init]) => init?.method === "POST");
    expect(requestBody(post?.[1])).toEqual({ status: "false_positive", reason: "Input is encoded" });
  });
});
