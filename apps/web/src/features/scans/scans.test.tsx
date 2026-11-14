import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { routes } from "@/app/routes";
import { jsonResponse, mockApi, renderRoutes, requestBody, requestUrl, signInAs } from "@/test-utils";

const PROJECT = "00000000-0000-4000-8000-0000000000f1";
const ASSET = "00000000-0000-4000-8000-0000000000a1";
const SCAN = "00000000-0000-4000-8000-0000000000b1";
const api = `/api/v1/projects/${PROJECT}`;
const page = <T,>(items: T[]) => ({ items, total: items.length, page: 1, page_size: 25 });

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
    name: "dns",
    technique: "passive",
    description: "DNS records",
    default_profile: "default",
    profiles: [{ name: "default", description: "Default profile" }],
    supported_asset_types: ["domain", "subdomain"],
  },
  {
    name: "nmap",
    technique: "active",
    description: "TCP port discovery",
    default_profile: "quick",
    profiles: [
      { name: "quick", description: "Top 100 TCP ports" },
      { name: "standard", description: "Top 1000 TCP ports" },
    ],
    supported_asset_types: ["ip_address", "domain"],
  },
];
const job = {
  id: SCAN,
  project_id: PROJECT,
  asset_id: ASSET,
  scanner: "nmap",
  profile: "standard",
  technique: "active",
  target: "93.184.215.14",
  status: "completed",
  requested_by_id: null,
  created_at: "2026-11-11T10:00:00Z",
  queued_at: "2026-11-11T10:00:01Z",
  started_at: "2026-11-11T10:00:02Z",
  finished_at: "2026-11-11T10:01:00Z",
  error_code: null,
  error_message: null,
  pinned_addresses: ["93.184.215.14"],
  summary: { observations: 1 },
};
const detail = {
  ...job,
  scope_decision: {
    allowed: true,
    target: "93.184.215.14",
    technique: "active",
    asset_id: ASSET,
    authorization_id: null,
    addresses: [{ address: "93.184.215.14", allowed: true, reason: null }],
    reasons: [],
  },
  tool_versions: { nmap: "7.95" },
  correlation_id: "req-1",
  results: [
    {
      id: "00000000-0000-4000-8000-0000000000d1",
      kind: "open_port",
      key: "93.184.215.14:80/tcp",
      data: { service: "<img src=x onerror=alert(1)>" },
      attention: ["cleartext_protocol"],
    },
  ],
  evidence: [
    {
      id: "00000000-0000-4000-8000-0000000000e1",
      label: "Nmap XML",
      media_type: "application/xml",
      content: "<script>alert(1)</script>",
    },
  ],
};
const running = { ...job, status: "running", finished_at: null };
const controls = { halted: false, reason: null, updated_at: null, updated_by: null };

describe("ScansPage", () => {
  it("lists scans and hides execution controls from viewers", async () => {
    signInAs("viewer", ["projects:read", "scans:read"]);
    mockApi({
      [`GET ${api}/scans`]: jsonResponse(page([job])),
      "GET /api/v1/scans/controls": jsonResponse(controls),
    });
    renderRoutes(routes, `/projects/${PROJECT}/scans`);

    const table = await screen.findByRole("table", { name: "Scans" });
    expect(within(table).getByRole("link", { name: "93.184.215.14" })).toBeInTheDocument();
    expect(within(table).getByText("completed")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /new scan/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /emergency stop/i })).not.toBeInTheDocument();
  });

  it("offers only scanners the asset is eligible for and queues a scan", async () => {
    signInAs("admin");
    const fetchMock = mockApi({
      [`GET ${api}/scans`]: jsonResponse(page([])),
      "GET /api/v1/scans/controls": jsonResponse(controls),
      "GET /api/v1/scanners": jsonResponse(scanners),
      [`GET ${api}/assets`]: jsonResponse(page([asset])),
      [`POST ${api}/scans`]: jsonResponse({ ...job, status: "queued" }, { status: 202 }),
      [`GET ${api}/scans/${SCAN}`]: jsonResponse(detail),
    });
    renderRoutes(routes, `/projects/${PROJECT}/scans`);
    await screen.findByText("No scans yet");

    await userEvent.click(screen.getByRole("button", { name: /new scan/i }));
    const dialog = await screen.findByRole("dialog", { name: "New scan" });
    await within(dialog).findByRole("option", { name: "93.184.215.14" });
    await userEvent.selectOptions(within(dialog).getByLabelText("Asset"), ASSET);
    const scannerSelect = within(dialog).getByLabelText("Scanner");
    // DNS does not support IP assets, so only Nmap is offered.
    expect(within(scannerSelect).queryByRole("option", { name: /dns/ })).not.toBeInTheDocument();
    await userEvent.selectOptions(scannerSelect, "nmap");
    expect(within(dialog).getByLabelText("Profile")).toHaveValue("quick");
    await userEvent.selectOptions(within(dialog).getByLabelText("Profile"), "standard");
    await userEvent.click(within(dialog).getByRole("button", { name: "Start scan" }));

    await screen.findByRole("heading", { name: "Scan details" });
    const post = fetchMock.mock.calls.find(([input, init]) => init?.method === "POST" && requestUrl(input).endsWith("/scans"));
    expect(requestBody(post?.[1])).toEqual({ asset_id: ASSET, scanner: "nmap", profile: "standard" });
  });

  it("shows the halted banner and lets administrators trigger an emergency stop", async () => {
    signInAs("admin");
    const fetchMock = mockApi({
      [`GET ${api}/scans`]: jsonResponse(page([])),
      "GET /api/v1/scans/controls": [
        jsonResponse(controls),
        jsonResponse({ halted: true, reason: "Impact reported", updated_at: "2026-11-11T10:00:00Z", updated_by: "admin@example.com" }),
      ],
      "POST /api/v1/scans/emergency-stop": jsonResponse({ ...controls, halted: true, cancelled_jobs: 2 }),
    });
    renderRoutes(routes, `/projects/${PROJECT}/scans`);

    await userEvent.click(await screen.findByRole("button", { name: /emergency stop/i }));
    const dialog = await screen.findByRole("dialog", { name: "Emergency stop" });
    const submit = within(dialog).getByRole("button", { name: "Stop all scans" });
    expect(submit).toBeDisabled();
    await userEvent.type(within(dialog).getByLabelText("Reason"), "Impact reported");
    await userEvent.click(submit);

    expect(await screen.findByText(/scanning is halted platform-wide/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /new scan/i })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Resume scanning" })).toBeInTheDocument();
    const post = fetchMock.mock.calls.find(([input]) => requestUrl(input).endsWith("/emergency-stop"));
    expect(requestBody(post?.[1])).toEqual({ reason: "Impact reported" });
  });
});

describe("ScanDetailPage", () => {
  it("renders the scope decision, observations and evidence as inert text", async () => {
    signInAs("viewer", ["projects:read", "scans:read"]);
    mockApi({ [`GET ${api}/scans/${SCAN}`]: jsonResponse(detail) });
    const { container } = renderRoutes(routes, `/projects/${PROJECT}/scans/${SCAN}`);

    expect(await screen.findByText("Execution-time scope decision")).toBeInTheDocument();
    expect(screen.getByRole("table", { name: "Resolved addresses" })).toHaveTextContent("authorized");
    const observations = screen.getByRole("table", { name: "Observations" });
    expect(within(observations).getByText("cleartext protocol")).toBeInTheDocument();
    expect(screen.getByText("<script>alert(1)</script>")).toBeInTheDocument();
    expect(container.querySelector("script, img")).toBeNull();
    expect(screen.queryByRole("button", { name: "Cancel scan" })).not.toBeInTheDocument();
  });

  it("cancels an active scan", async () => {
    signInAs("admin");
    const fetchMock = mockApi({
      [`GET ${api}/scans/${SCAN}`]: [
        jsonResponse({ ...detail, ...running, results: [], evidence: [] }),
        jsonResponse({ ...detail, status: "cancelled", error_code: "cancelled", error_message: "The scan was cancelled by a user.", results: [], evidence: [] }),
      ],
      [`POST ${api}/scans/${SCAN}/cancel`]: jsonResponse({ ...job, status: "cancelled" }),
    });
    renderRoutes(routes, `/projects/${PROJECT}/scans/${SCAN}`);

    await userEvent.click(await screen.findByRole("button", { name: "Cancel scan" }));
    expect(await screen.findByText(/cancelled by a user/)).toBeInTheDocument();
    expect(fetchMock.mock.calls.some(([input]) => requestUrl(input).endsWith("/cancel"))).toBe(true);
  });
});
