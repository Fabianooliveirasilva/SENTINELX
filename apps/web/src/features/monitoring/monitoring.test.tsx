import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { routes } from "@/app/routes";
import { jsonResponse, mockApi, renderRoutes, requestBody, requestUrl, signInAs } from "@/test-utils";

const PROJECT = "00000000-0000-4000-8000-0000000000f1";
const ASSET = "00000000-0000-4000-8000-0000000000a1";
const CHANNEL = "00000000-0000-4000-8000-0000000000c1";
const RULE = "00000000-0000-4000-8000-0000000000d1";
const VIEWER = ["projects:read", "events:read", "scans:read", "findings:read", "assets:read"];
const ANALYST = [...VIEWER, "alerts:manage", "scans:execute"];

const page = <T,>(items: T[]) => ({ items, total: items.length, page: 1, page_size: 50 });
const event = (overrides: Record<string, unknown> = {}) => ({
  id: "00000000-0000-4000-8000-0000000000e1",
  project_id: PROJECT,
  event_type: "finding.created",
  severity: "medium",
  title: "<b>Cleartext</b> HTTP",
  asset_id: ASSET,
  finding_id: "00000000-0000-4000-8000-0000000000b1",
  scan_job_id: null,
  details: { location: "93.184.215.14 http://x/", rule_id: "http.cleartext_http" },
  actor_email: null,
  occurred_at: "2026-11-12T10:00:00Z",
  ...overrides,
});
const summary = { since: "2026-11-05T00:00:00Z", total: 1, by_severity: { critical: 0, high: 0, medium: 1, low: 0, info: 0 } };
const types = [
  { type: "finding.created", description: "A new finding was observed" },
  { type: "scan.failed", description: "A scan failed" },
];
const channel = {
  id: CHANNEL,
  project_id: PROJECT,
  name: "SOC mail",
  kind: "email",
  enabled: true,
  recipients: ["soc@example.com"],
  url: null,
  has_secret: false,
  created_at: "2026-11-12T10:00:00Z",
  updated_at: "2026-11-12T10:00:00Z",
};
const rule = {
  id: RULE,
  project_id: PROJECT,
  name: "High findings",
  enabled: true,
  event_types: ["finding.created"],
  min_severity: "high",
  asset_id: null,
  quiet_period_minutes: 60,
  channels: [{ id: CHANNEL, name: "SOC mail", kind: "email", enabled: true }],
  created_at: "2026-11-12T10:00:00Z",
  updated_at: "2026-11-12T10:00:00Z",
};
const asset = {
  id: ASSET,
  project_id: PROJECT,
  type: "ip_address",
  value: "93.184.215.14",
  description: "",
  tags: [],
  criticality: "high",
  exposure: "external",
  status: "active",
  created_at: "2026-11-11T10:00:00Z",
  updated_at: "2026-11-11T10:00:00Z",
  eligibility: { passive: true, active: true, intrusive: false, reasons: [] },
  active_authorizations: 1,
};
const scanners = [
  {
    name: "nmap",
    technique: "active",
    description: "Port scan",
    default_profile: "quick",
    profiles: [{ name: "quick", description: "Top ports", technique: "active" }],
    supported_asset_types: ["ip_address"],
  },
];
const schedule = {
  id: "00000000-0000-4000-8000-0000000000a9",
  project_id: PROJECT,
  asset_id: ASSET,
  scanner: "nmap",
  profile: "quick",
  interval_hours: 24,
  enabled: true,
  next_run_at: "2026-11-13T10:00:00Z",
  last_run_at: "2026-11-12T10:00:00Z",
  last_status: "skipped",
  last_message: "Scanning is halted by an emergency stop.",
  last_scan_job_id: null,
  owner_id: "00000000-0000-4000-8000-000000000001",
  created_at: "2026-11-11T10:00:00Z",
  updated_at: "2026-11-11T10:00:00Z",
};

describe("EventsPage", () => {
  it("renders the timeline as text and filters by severity", async () => {
    signInAs("viewer", VIEWER);
    const fetchMock = mockApi({
      [`GET /api/v1/projects/${PROJECT}/events`]: jsonResponse(page([event()])),
      [`GET /api/v1/projects/${PROJECT}/events/summary`]: jsonResponse(summary),
      "GET /api/v1/events/types": jsonResponse(types),
    });
    renderRoutes(routes, `/projects/${PROJECT}/events`);
    const list = await screen.findByRole("list", { name: "Security events" });
    // Scanner-derived markup is shown literally, never rendered.
    expect(within(list).getByText("<b>Cleartext</b> HTTP")).toBeInTheDocument();
    expect(within(list).getByText("Finding created")).toBeInTheDocument();
    expect(within(list).getByRole("link", { name: "Finding" })).toHaveAttribute(
      "href",
      `/projects/${PROJECT}/findings/00000000-0000-4000-8000-0000000000b1`,
    );

    await userEvent.selectOptions(screen.getByLabelText("Minimum severity"), "high");
    const last = fetchMock.mock.calls
      .map(([input]) => requestUrl(input))
      .filter((url) => url.includes("/events?"))
      .at(-1);
    expect(last).toContain("min_severity=high");
  });
});

describe("AlertsPage", () => {
  it("shows viewers the rules but not channels or deliveries", async () => {
    signInAs("viewer", VIEWER);
    mockApi({ [`GET /api/v1/projects/${PROJECT}/alert-rules`]: jsonResponse([rule]) });
    renderRoutes(routes, `/projects/${PROJECT}/alerts`);
    const table = await screen.findByRole("table", { name: "Alert rules" });
    expect(within(table).getByText("High findings")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "New rule" })).not.toBeInTheDocument();
    expect(screen.queryByText("Notification channels")).not.toBeInTheDocument();
  });

  it("creates a webhook channel and reveals its secret once", async () => {
    signInAs("security_analyst", ANALYST);
    const fetchMock = mockApi({
      [`GET /api/v1/projects/${PROJECT}/alert-rules`]: jsonResponse([]),
      [`GET /api/v1/projects/${PROJECT}/notification-channels`]: jsonResponse([]),
      [`GET /api/v1/projects/${PROJECT}/notifications`]: jsonResponse(page([])),
      [`POST /api/v1/projects/${PROJECT}/notification-channels`]: jsonResponse(
        { ...channel, kind: "webhook", recipients: null, url: "https://hooks.example.com/x", has_secret: true, signing_secret: "whsec_abc123" },
        { status: 201 },
      ),
    });
    renderRoutes(routes, `/projects/${PROJECT}/alerts`);
    await userEvent.click(await screen.findByRole("button", { name: "New channel" }));
    await userEvent.type(screen.getByLabelText("Name"), "Chat");
    await userEvent.selectOptions(screen.getByLabelText("Type"), "webhook");
    await userEvent.type(screen.getByLabelText("URL"), "https://hooks.example.com/x");
    await userEvent.click(screen.getByRole("button", { name: "Create channel" }));

    expect(await screen.findByText("whsec_abc123")).toBeInTheDocument();
    const post = fetchMock.mock.calls.find(([, init]) => init?.method === "POST");
    expect(requestBody(post?.[1])).toEqual({ name: "Chat", kind: "webhook", url: "https://hooks.example.com/x" });
    await userEvent.click(screen.getByRole("button", { name: "I have stored it" }));
    expect(screen.queryByText("whsec_abc123")).not.toBeInTheDocument();
  });

  it("creates a rule routed to the selected channel", async () => {
    signInAs("security_analyst", ANALYST);
    const fetchMock = mockApi({
      [`GET /api/v1/projects/${PROJECT}/alert-rules`]: jsonResponse([]),
      [`GET /api/v1/projects/${PROJECT}/notification-channels`]: jsonResponse([channel]),
      [`GET /api/v1/projects/${PROJECT}/notifications`]: jsonResponse(page([])),
      "GET /api/v1/events/types": jsonResponse(types),
      [`POST /api/v1/projects/${PROJECT}/alert-rules`]: jsonResponse(rule, { status: 201 }),
    });
    renderRoutes(routes, `/projects/${PROJECT}/alerts`);
    await userEvent.click(await screen.findByRole("button", { name: "New rule" }));
    const dialog = await screen.findByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Name"), "Failures");
    await userEvent.click(await within(dialog).findByRole("checkbox", { name: "Scan failed" }));
    await userEvent.click(within(dialog).getByRole("checkbox", { name: /SOC mail/ }));
    await userEvent.click(within(dialog).getByRole("button", { name: "Create rule" }));

    await screen.findByRole("table", { name: "Notification channels" });
    const post = fetchMock.mock.calls.find(([input, init]) => init?.method === "POST" && requestUrl(input).includes("alert-rules"));
    expect(requestBody(post?.[1])).toEqual({
      name: "Failures",
      event_types: ["scan.failed"],
      min_severity: "high",
      asset_id: null,
      quiet_period_minutes: 60,
      channel_ids: [CHANNEL],
    });
  });
});

describe("SchedulesPage", () => {
  it("lists schedules with skip reasons and creates a new one", async () => {
    signInAs("security_analyst", ANALYST);
    const fetchMock = mockApi({
      [`GET /api/v1/projects/${PROJECT}/scan-schedules`]: jsonResponse(page([schedule])),
      [`GET /api/v1/projects/${PROJECT}/assets`]: jsonResponse({ ...page([asset]), page_size: 25 }),
      "GET /api/v1/scanners": jsonResponse(scanners),
      [`POST /api/v1/projects/${PROJECT}/scan-schedules`]: jsonResponse(schedule, { status: 201 }),
    });
    renderRoutes(routes, `/projects/${PROJECT}/schedules`);
    const table = await screen.findByRole("table", { name: "Scan schedules" });
    expect(within(table).getByText("Scanning is halted by an emergency stop.")).toBeInTheDocument();
    expect(await within(table).findByText("93.184.215.14")).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "New schedule" }));
    const dialog = await screen.findByRole("dialog");
    await userEvent.selectOptions(within(dialog).getByLabelText("Asset"), ASSET);
    await userEvent.selectOptions(await within(dialog).findByLabelText("Scanner"), "nmap");
    await userEvent.selectOptions(within(dialog).getByLabelText("Frequency"), "168");
    await userEvent.click(within(dialog).getByRole("button", { name: "Create schedule" }));

    await screen.findByRole("table", { name: "Scan schedules" });
    const post = fetchMock.mock.calls.find(([, init]) => init?.method === "POST");
    expect(requestBody(post?.[1])).toEqual({ asset_id: ASSET, scanner: "nmap", profile: "quick", interval_hours: 168 });
  });
});
