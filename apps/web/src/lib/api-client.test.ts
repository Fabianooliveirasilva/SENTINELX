import { describe, expect, it } from "vitest";
import { z } from "zod";

import { jsonResponse, mockFetch } from "@/test-utils";

import { apiRequest, ApiError } from "./api-client";

const schema = z.object({ value: z.number() });

describe("apiRequest", () => {
  it("returns validated data for a successful response", async () => {
    const fetchMock = mockFetch(jsonResponse({ value: 42 }));

    await expect(apiRequest("/thing", schema)).resolves.toEqual({ value: 42 });
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/v1/thing",
      expect.objectContaining({ method: "GET", credentials: "same-origin" }),
    );
  });

  it("sends JSON bodies with the correct content type", async () => {
    const fetchMock = mockFetch(jsonResponse({ value: 1 }));

    await apiRequest("/thing", schema, { method: "POST", body: { name: "x" } });

    const init = fetchMock.mock.calls[0]?.[1];
    expect(init?.body).toBe('{"name":"x"}');
    expect(init?.headers).toMatchObject({ "Content-Type": "application/json" });
  });

  it("maps the API error envelope to ApiError", async () => {
    mockFetch(
      jsonResponse(
        { error: { code: "not_found", message: "Missing.", request_id: "req-123", details: [] } },
        { status: 404 },
      ),
    );

    const error = await apiRequest("/missing", schema).catch((e: unknown) => e);

    expect(error).toBeInstanceOf(ApiError);
    expect(error).toMatchObject({ status: 404, code: "not_found", requestId: "req-123" });
  });

  it("falls back to a generic error when the body is not an envelope", async () => {
    mockFetch(new Response("<html>bad gateway</html>", { status: 502 }));

    await expect(apiRequest("/x", schema)).rejects.toMatchObject({
      status: 502,
      code: "http_error",
    });
  });

  it("rejects responses that violate the schema", async () => {
    mockFetch(jsonResponse({ value: "not-a-number" }, { headers: { "X-Request-ID": "rid-1" } }));

    await expect(apiRequest("/x", schema)).rejects.toMatchObject({
      code: "invalid_response",
      requestId: "rid-1",
    });
  });

  it("reports network failures without leaking low-level details", async () => {
    mockFetch(new TypeError("Failed to fetch"));

    await expect(apiRequest("/x", schema)).rejects.toMatchObject({
      status: 0,
      code: "network_error",
      message: "Unable to reach the SentinelX API.",
    });
  });

  it("treats explicitly accepted non-2xx statuses as payloads", async () => {
    mockFetch(jsonResponse({ value: 7 }, { status: 503 }));

    await expect(apiRequest("/x", schema, { acceptStatuses: [503] })).resolves.toEqual({
      value: 7,
    });
  });
});
