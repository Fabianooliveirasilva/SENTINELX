import { z } from "zod";

/**
 * Typed HTTP client for the SentinelX API.
 *
 * Every response body is validated with a Zod schema before reaching UI code,
 * so a backend contract change surfaces as an explicit error instead of
 * silently rendering wrong data.
 */

export const API_BASE_URL: string = import.meta.env.VITE_API_BASE_URL ?? "/api/v1";

const errorEnvelopeSchema = z.object({
  error: z.object({
    code: z.string(),
    message: z.string(),
    request_id: z.string().nullable(),
    details: z
      .array(z.object({ location: z.array(z.string()), message: z.string(), type: z.string() }))
      .default([]),
  }),
});

export type ApiErrorCode = "network_error" | "invalid_response" | (string & {});

export class ApiError extends Error {
  readonly status: number;
  readonly code: ApiErrorCode;
  readonly requestId: string | null;

  constructor(params: {
    status: number;
    code: ApiErrorCode;
    message: string;
    requestId?: string | null;
  }) {
    super(params.message);
    this.name = "ApiError";
    this.status = params.status;
    this.code = params.code;
    this.requestId = params.requestId ?? null;
  }
}

export interface RequestOptions {
  method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  body?: unknown;
  signal?: AbortSignal;
  /** Non-2xx statuses whose body is a valid payload (e.g. 503 from readiness). */
  acceptStatuses?: readonly number[];
}

async function readJson(response: Response): Promise<unknown> {
  const text = await response.text();
  if (!text) return null;
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return undefined;
  }
}

export async function apiRequest<T>(
  path: string,
  schema: z.ZodType<T>,
  options: RequestOptions = {},
): Promise<T> {
  const { method = "GET", body, signal, acceptStatuses = [] } = options;

  let response: Response;
  try {
    response = await fetch(`${API_BASE_URL}${path}`, {
      method,
      credentials: "same-origin",
      headers: {
        Accept: "application/json",
        ...(body === undefined ? {} : { "Content-Type": "application/json" }),
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      ...(signal ? { signal } : {}),
    });
  } catch (cause) {
    if (cause instanceof DOMException && cause.name === "AbortError") throw cause;
    throw new ApiError({
      status: 0,
      code: "network_error",
      message: "Unable to reach the SentinelX API.",
    });
  }

  const requestId = response.headers.get("X-Request-ID");
  const payload = await readJson(response);

  if (!response.ok && !acceptStatuses.includes(response.status)) {
    const envelope = errorEnvelopeSchema.safeParse(payload);
    if (envelope.success) {
      throw new ApiError({
        status: response.status,
        code: envelope.data.error.code,
        message: envelope.data.error.message,
        requestId: envelope.data.error.request_id ?? requestId,
      });
    }
    throw new ApiError({
      status: response.status,
      code: "http_error",
      message: `Request failed with status ${response.status}.`,
      requestId,
    });
  }

  const parsed = schema.safeParse(payload);
  if (!parsed.success) {
    throw new ApiError({
      status: response.status,
      code: "invalid_response",
      message: "The API returned an unexpected response.",
      requestId,
    });
  }
  return parsed.data;
}
