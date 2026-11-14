import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { routes } from "@/app/routes";
import { jsonResponse, mockApi, renderRoutes, requestBody, requestUrl, signInAs } from "@/test-utils";

const PROJECT = "00000000-0000-4000-8000-0000000000f1";
const page = <T,>(items: T[]) => ({ items, total: items.length, page: 1, page_size: 25 });

const cve = {
  id: "CVE-2021-41773",
  source: "nvd",
  description: "Path traversal in Apache HTTP Server 2.4.49. <script>alert(1)</script>",
  status: "Analyzed",
  published_at: "2021-10-05T09:15:07Z",
  last_modified_at: "2025-10-24T00:00:00Z",
  cvss_version: "3.1",
  cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  cvss_score: 9.8,
  cvss_severity: "critical",
  cwes: ["CWE-22"],
  kev_added_on: "2021-11-03",
  fetched_at: "2026-11-11T10:00:00Z",
};
const detail = {
  ...cve,
  cvss31_vector: cve.cvss_vector,
  cvss31_score: 9.8,
  cvss40_vector: null,
  cvss40_score: null,
  references: ["https://httpd.apache.org/security/vulnerabilities_24.html"],
  kev_due_on: "2021-11-17",
  kev_ransomware: "Known",
  matches: [
    {
      criteria: "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
      vendor: "apache",
      product: "http_server",
      version: "2.4.49",
      start_including: null,
      start_excluding: null,
      end_including: null,
      end_excluding: null,
    },
    {
      criteria: "cpe:2.3:a:jquery:jquery:*:*:*:*:*:*:*:*",
      vendor: "jquery",
      product: "jquery",
      version: "*",
      start_including: "1.2",
      start_excluding: null,
      end_including: null,
      end_excluding: "3.5.0",
    },
  ],
};
const status = {
  enabled: true,
  nvd_api_key_configured: false,
  cves: 2,
  kev_cves: 1,
  sources: [],
  products: [
    {
      vendor: "apache",
      product: "http_server",
      requested_at: "2026-11-11T10:00:00Z",
      synced_at: "2026-11-11T10:05:00Z",
      status: "ok",
      cve_count: 1,
      error: null,
    },
  ],
};

describe("IntelligencePage", () => {
  it("shows sync status, KEV flags and lets admins refresh a product", async () => {
    signInAs("admin");
    const fetchMock = mockApi({
      "GET /api/v1/intelligence/status": jsonResponse(status),
      "GET /api/v1/intelligence/cves": jsonResponse(page([cve])),
      "POST /api/v1/intelligence/products/sync": jsonResponse(
        { ...status.products[0], status: "pending" },
        { status: 202 },
      ),
    });
    renderRoutes(routes, "/intelligence");

    const table = await screen.findByRole("table", { name: "CVEs" });
    expect(within(table).getByRole("link", { name: "CVE-2021-41773" })).toBeInTheDocument();
    expect(within(table).getByText("KEV")).toBeInTheDocument();
    expect(screen.getByText("not configured (slower sync)")).toBeInTheDocument();

    await userEvent.click(screen.getByLabelText("Known exploited only"));
    expect(fetchMock.mock.calls.some(([input]) => requestUrl(input).includes("kev=true"))).toBe(true);

    await userEvent.click(within(screen.getByRole("table", { name: "Tracked products" })).getByRole("button", { name: "Refresh" }));
    const post = fetchMock.mock.calls.find(([, init]) => init?.method === "POST");
    expect(requestBody(post?.[1])).toEqual({ vendor: "apache", product: "http_server" });
  });

  it("hides product refresh from analysts", async () => {
    signInAs("security_analyst", ["projects:read", "intelligence:read"]);
    mockApi({
      "GET /api/v1/intelligence/status": jsonResponse(status),
      "GET /api/v1/intelligence/cves": jsonResponse(page([])),
    });
    renderRoutes(routes, "/intelligence");
    await screen.findByRole("table", { name: "Tracked products" });
    expect(screen.queryByRole("button", { name: "Refresh" })).not.toBeInTheDocument();
    expect(screen.getByText("No CVEs match")).toBeInTheDocument();
  });
});

describe("CveDetailPage", () => {
  it("renders ranges, KEV details and safe external links", async () => {
    signInAs("viewer", ["projects:read", "intelligence:read"]);
    mockApi({ "GET /api/v1/intelligence/cves/CVE-2021-41773": jsonResponse(detail) });
    const { container } = renderRoutes(routes, "/intelligence/cves/CVE-2021-41773");

    const configs = await screen.findByRole("table", { name: "Affected configurations" });
    expect(configs).toHaveTextContent("version 2.4.49");
    expect(configs).toHaveTextContent(">= 1.2 and < 3.5.0");
    expect(screen.getByText("CISA KEV since 2021-11-03")).toBeInTheDocument();
    const link = within(screen.getByRole("list", { name: "References" })).getByRole("link");
    expect(link).toHaveAttribute("rel", "noopener noreferrer");
    expect(container.querySelector("script")).toBeNull();
  });
});

describe("SoftwarePage", () => {
  it("explains why components are or are not correlated", async () => {
    signInAs("viewer", ["projects:read", "assets:read"]);
    mockApi({
      [`GET /api/v1/projects/${PROJECT}/software`]: jsonResponse([
        {
          id: "00000000-0000-4000-8000-000000000101",
          asset_id: "00000000-0000-4000-8000-0000000000a1",
          source: "http",
          name: "Apache",
          version: "2.4.49",
          raw_version: "2.4.49",
          cpes: ["apache:http_server"],
          location: "https://app.example.com/",
          correlatable: true,
          last_seen_at: "2026-11-11T10:00:00Z",
          last_scan_job_id: null,
        },
        {
          id: "00000000-0000-4000-8000-000000000102",
          asset_id: "00000000-0000-4000-8000-0000000000a1",
          source: "http",
          name: "jQuery",
          version: "",
          raw_version: "",
          cpes: ["jquery:jquery"],
          location: "https://app.example.com/",
          correlatable: false,
          last_seen_at: "2026-11-11T10:00:00Z",
          last_scan_job_id: null,
        },
      ]),
    });
    renderRoutes(routes, `/projects/${PROJECT}/software`);
    const table = await screen.findByRole("table", { name: "Software" });
    expect(within(table).getByRole("link", { name: "correlated" })).toBeInTheDocument();
    expect(within(table).getByText("no version")).toBeInTheDocument();
  });
});
