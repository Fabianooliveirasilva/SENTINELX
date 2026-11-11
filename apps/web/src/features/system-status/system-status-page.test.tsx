import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { jsonResponse, mockFetch, renderWithRouter } from "@/test-utils";

import { SystemStatusPage } from "./system-status-page";

const healthy = {
  status: "ok",
  version: "0.1.0",
  components: {
    database: { status: "ok", latency_ms: 1.25, error: null },
    redis: { status: "ok", latency_ms: 0.4, error: null },
  },
};

const degraded = {
  status: "unavailable",
  version: "0.1.0",
  components: {
    database: { status: "ok", latency_ms: 2, error: null },
    redis: { status: "unavailable", latency_ms: null, error: "timeout" },
  },
};

describe("SystemStatusPage", () => {
  it("shows a loading state, then operational components", async () => {
    mockFetch(jsonResponse(healthy));

    renderWithRouter(<SystemStatusPage />);

    expect(screen.getByRole("status", { name: /loading system status/i })).toBeInTheDocument();
    expect(await screen.findByTestId("overall-status")).toHaveTextContent("Operational");
    const list = screen.getByRole("list", { name: /infrastructure components/i });
    expect(within(list).getByText("PostgreSQL")).toBeInTheDocument();
    expect(within(list).getByText("1.3 ms")).toBeInTheDocument();
    expect(screen.getByText("API version 0.1.0")).toBeInTheDocument();
  });

  it("renders a degraded platform from a 503 readiness report", async () => {
    mockFetch(jsonResponse(degraded, { status: 503 }));

    renderWithRouter(<SystemStatusPage />);

    expect(await screen.findByTestId("overall-status")).toHaveTextContent("Degraded");
    expect(screen.getByText("Unavailable")).toBeInTheDocument();
    expect(screen.getByText("timeout")).toBeInTheDocument();
  });

  it("shows an error with request ID and recovers on retry", async () => {
    const fetchMock = mockFetch(
      jsonResponse(
        { error: { code: "internal_error", message: "Boom.", request_id: "req-xyz", details: [] } },
        { status: 500 },
      ),
      jsonResponse(healthy),
    );

    renderWithRouter(<SystemStatusPage />);

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Unable to retrieve system status");
    expect(alert).toHaveTextContent("Request ID: req-xyz");

    await userEvent.click(within(alert).getByRole("button", { name: /retry/i }));

    expect(await screen.findByTestId("overall-status")).toHaveTextContent("Operational");
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });
});
