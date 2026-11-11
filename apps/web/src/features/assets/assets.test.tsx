import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { routes } from "@/app/routes";
import { jsonResponse, mockApi, renderRoutes, requestBody, requestUrl, signInAs } from "@/test-utils";

const PROJECT = "00000000-0000-4000-8000-0000000000f1";
const ASSET = "00000000-0000-4000-8000-0000000000a1";

const eligibility = { passive: true, active: true, intrusive: false, reasons: [] };
const asset = {
  id: ASSET,
  project_id: PROJECT,
  type: "domain",
  value: "example.com",
  description: "",
  tags: ["prod"],
  criticality: "high",
  exposure: "external",
  status: "active",
  created_at: "2026-11-11T10:00:00Z",
  updated_at: "2026-11-11T10:00:00Z",
  eligibility,
  active_authorizations: 1,
};
const authorization = {
  id: "00000000-0000-4000-8000-0000000000c1",
  authorized_by: "Jane Owner",
  organization: "Acme",
  reference: "SOW-114",
  notes: "",
  valid_from: "2026-11-10T00:00:00Z",
  valid_until: "2026-12-10T00:00:00Z",
  allow_active: true,
  allow_intrusive: false,
  include_subdomains: false,
  ip_ranges: ["93.184.215.0/24"],
  status: "active",
  recorded_by_id: null,
  created_at: "2026-11-10T00:00:00Z",
  revoked_at: null,
  revocation_reason: null,
};
const detail = { ...asset, authorizations: [authorization] };
const page = <T,>(items: T[]) => ({ items, total: items.length, page: 1, page_size: 25 });
const api = `/api/v1/projects/${PROJECT}`;

describe("AssetsPage", () => {
  it("lists assets with eligibility and hides write actions from viewers", async () => {
    signInAs("viewer", ["projects:read", "assets:read"]);
    mockApi({ [`GET ${api}/assets`]: jsonResponse(page([asset])) });

    renderRoutes(routes, `/projects/${PROJECT}/assets`);

    const table = await screen.findByRole("table", { name: "Assets" });
    expect(within(table).getByRole("link", { name: "example.com" })).toBeInTheDocument();
    expect(within(table).getByRole("list", { name: "Testing eligibility" })).toHaveTextContent("✓ active");
    expect(screen.queryByRole("button", { name: /register asset/i })).not.toBeInTheDocument();
    expect(screen.getByRole("navigation", { name: "Project sections" })).toHaveTextContent("Scope check");
  });

  it("registers an asset and parses tags", async () => {
    signInAs("admin");
    const fetchMock = mockApi({
      [`GET ${api}/assets`]: jsonResponse(page([])),
      [`POST ${api}/assets`]: jsonResponse(detail, { status: 201 }),
      [`GET ${api}/assets/${ASSET}`]: jsonResponse(detail),
      [`GET ${api}/assets/${ASSET}/history`]: jsonResponse([]),
    });
    renderRoutes(routes, `/projects/${PROJECT}/assets`);
    await screen.findByText("No assets match these filters");

    await userEvent.click(screen.getByRole("button", { name: /register asset/i }));
    const dialog = await screen.findByRole("dialog", { name: "Register asset" });
    await userEvent.selectOptions(within(dialog).getByLabelText("Type"), "ip_address");
    expect(within(dialog).getByLabelText("Value")).toHaveAttribute("placeholder", "93.184.215.14");
    await userEvent.selectOptions(within(dialog).getByLabelText("Type"), "domain");
    await userEvent.type(within(dialog).getByLabelText("Value"), "example.com");
    await userEvent.type(within(dialog).getByLabelText("Tags"), "prod, , pci ");
    await userEvent.click(within(dialog).getByRole("button", { name: "Register asset" }));

    expect(await screen.findByRole("heading", { name: "example.com" })).toBeInTheDocument();
    const call = fetchMock.mock.calls.find(([, init]) => init?.method === "POST");
    expect(requestBody(call?.[1])).toMatchObject({ type: "domain", value: "example.com", tags: ["prod", "pci"] });
  });
});

describe("AssetDetailPage", () => {
  it("shows authorizations and records a new one with ISO timestamps and parsed ranges", async () => {
    signInAs("security_analyst", ["projects:read", "assets:read", "assets:write"]);
    const fetchMock = mockApi({
      [`GET ${api}/assets/${ASSET}`]: jsonResponse(detail),
      [`GET ${api}/assets/${ASSET}/history`]: jsonResponse([
        { id: "00000000-0000-4000-8000-0000000000e1", created_at: "2026-11-11T10:00:00Z", action: "asset.created", actor_email: "a@example.com", details: {} },
      ]),
      [`POST ${api}/assets/${ASSET}/authorizations`]: jsonResponse(authorization, { status: 201 }),
    });
    renderRoutes(routes, `/projects/${PROJECT}/assets/${ASSET}`);

    const table = await screen.findByRole("table", { name: "Authorizations" });
    expect(within(table).getByText("SOW-114")).toBeInTheDocument();
    expect(within(table).getByText("93.184.215.0/24")).toBeInTheDocument();
    expect(await screen.findByRole("list", { name: "Asset history" })).toHaveTextContent("asset.created");

    await userEvent.click(screen.getByRole("button", { name: /add authorization/i }));
    const dialog = await screen.findByRole("dialog", { name: "Record authorization" });
    // Non-admins cannot grant intrusive testing.
    expect(within(dialog).queryByLabelText(/intrusive testing/i)).not.toBeInTheDocument();
    await userEvent.type(within(dialog).getByLabelText("Authorized by"), "Jane Owner");
    await userEvent.type(within(dialog).getByLabelText("Organization"), "Acme");
    await userEvent.type(within(dialog).getByLabelText("Reference"), "SOW-115");
    await userEvent.click(within(dialog).getByLabelText(/active testing/i));
    await userEvent.type(within(dialog).getByLabelText("Authorized IP ranges"), "93.184.215.0/24\n2606:2800:21f::/48");
    await userEvent.click(within(dialog).getByRole("button", { name: "Record authorization" }));

    await screen.findByRole("table", { name: "Authorizations" });
    const call = fetchMock.mock.calls.find(([url, init]) => init?.method === "POST" && requestUrl(url).endsWith("/authorizations"));
    const body = requestBody(call?.[1]) as Record<string, unknown>;
    expect(body).toMatchObject({ reference: "SOW-115", allow_active: true, allow_intrusive: false, ip_ranges: ["93.184.215.0/24", "2606:2800:21f::/48"] });
    expect(String(body.valid_from)).toMatch(/Z$/);
  });

  it("requires a reason before revoking", async () => {
    signInAs("admin");
    const fetchMock = mockApi({
      [`GET ${api}/assets/${ASSET}`]: jsonResponse(detail),
      [`GET ${api}/assets/${ASSET}/history`]: jsonResponse([]),
      [`POST ${api}/assets/${ASSET}/authorizations/${authorization.id}/revoke`]: jsonResponse({ ...authorization, status: "revoked" }),
    });
    renderRoutes(routes, `/projects/${PROJECT}/assets/${ASSET}`);

    await userEvent.click(await screen.findByRole("button", { name: "Revoke authorization SOW-114" }));
    const dialog = await screen.findByRole("dialog");
    const submit = within(dialog).getByRole("button", { name: "Revoke" });
    expect(submit).toBeDisabled();
    await userEvent.type(within(dialog).getByLabelText("Reason"), "Engagement ended");
    await userEvent.click(submit);

    const call = fetchMock.mock.calls.find(([url]) => requestUrl(url).endsWith("/revoke"));
    expect(requestBody(call?.[1])).toEqual({ reason: "Engagement ended" });
  });
});

describe("ScopeCheckPage", () => {
  it("shows the verdict with reasons and per-address results", async () => {
    signInAs("viewer", ["projects:read", "assets:read"]);
    mockApi({
      [`POST ${api}/scope/check`]: jsonResponse({
        allowed: false,
        target: "rebind.example.com",
        technique: "active",
        asset_id: ASSET,
        authorization_id: authorization.id,
        addresses: [
          { address: "93.184.215.14", allowed: true, reason: null },
          { address: "127.0.0.1", allowed: false, reason: "loopback_address" },
        ],
        reasons: [{ code: "loopback_address", message: "127.0.0.1 is not permitted (loopback_address)." }],
      }),
    });
    renderRoutes(routes, `/projects/${PROJECT}/scope`);

    await userEvent.type(await screen.findByLabelText("Target"), "rebind.example.com");
    await userEvent.click(screen.getByRole("button", { name: /check/i }));

    expect(await screen.findByTestId("scope-verdict")).toHaveTextContent("Out of scope");
    const addresses = screen.getByRole("table", { name: "Resolved addresses" });
    expect(within(addresses).getByText("loopback_address")).toBeInTheDocument();
    expect(within(addresses).getByText("permitted")).toBeInTheDocument();
  });
});
