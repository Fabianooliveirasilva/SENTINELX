import { describe, expect, it } from "vitest";

import { ApiError } from "@/lib/api-client";

import { createQueryClient } from "./query-client";

type RetryFn = (failureCount: number, error: Error) => boolean;

const retry = createQueryClient().getDefaultOptions().queries?.retry as RetryFn;

describe("query client retry policy", () => {
  it("does not retry client errors", () => {
    expect(retry(0, new ApiError({ status: 403, code: "forbidden", message: "x" }))).toBe(false);
  });

  it("does not retry contract violations", () => {
    expect(retry(0, new ApiError({ status: 200, code: "invalid_response", message: "x" }))).toBe(
      false,
    );
  });

  it("retries transient failures a bounded number of times", () => {
    const transient = new ApiError({ status: 0, code: "network_error", message: "x" });
    expect(retry(0, transient)).toBe(true);
    expect(retry(1, transient)).toBe(true);
    expect(retry(2, transient)).toBe(false);
  });
});
