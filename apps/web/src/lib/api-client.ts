import { z } from "zod";

/**
 * Typed HTTP client for the SentinelX API.
 *
 * - Every response body is validated with a Zod schema before reaching UI code.
 * - The in-memory access token is attached automatically. On a 401 the client
 *   asks the registered auth handler to refresh the session once and retries.
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
  query?: Record<string, string | number | boolean | null | undefined>;
  headers?: Record<string, string>;
  /** Non-2xx statuses whose body is a valid payload (e.g. 503 from readiness). */
  acceptStatuses?: readonly number[];
  /** Skip the automatic refresh-and-retry on 401 (used by auth endpoints themselves). */
  skipAuthRefresh?: boolean;
}

export interface AuthHandler {
  getAccessToken: () => string | null;
  /** Attempt to obtain a new access token. Resolves true on success. */
  refresh: () => Promise<boolean>;
}

let authHandler: AuthHandler | null = null;

export function setAuthHandler(handler: AuthHandler | null): void {
  authHandler = handler;
}

export function readCookie(name: string): string | null {
  const prefix = `${name}=`;
  for (const part of document.cookie.split(";")) {
    const cookie = part.trim();
    if (cookie.startsWith(prefix)) return decodeURIComponent(cookie.slice(prefix.length));
  }
  return null;
}

function buildUrl(path: string, query: RequestOptions["query"]): string {
  const url = `${API_BASE_URL}${path}`;
  if (!query) return url;
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value !== undefined && value !== null && value !== "") params.set(key, String(value));
  }
  const qs = params.toString();
  return qs ? `${url}?${qs}` : url;
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

async function send(path: string, options: RequestOptions): Promise<Response> {
  const { method = "GET", body, signal, query, headers = {} } = options;
  const token = authHandler?.getAccessToken();
  try {
    return await fetch(buildUrl(path, query), {
      method,
      credentials: "same-origin",
      headers: {
        Accept: "application/json",
        ...(body === undefined ? {} : { "Content-Type": "application/json" }),
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...headers,
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
}

export async function apiRequest<T>(
  path: string,
  schema: z.ZodType<T>,
  options: RequestOptions = {},
): Promise<T> {
  const { acceptStatuses = [], skipAuthRefresh = false } = options;

  let response = await send(path, options);
  if (response.status === 401 && !skipAuthRefresh && authHandler) {
    if (await authHandler.refresh()) response = await send(path, options);
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

export interface Download {
  blob: Blob;
  filename: string;
  sha256: string | null;
}

/** Fetch a binary attachment (reports) with the same auth and error handling. */
export async function apiDownload(path: string): Promise<Download> {
  const options: RequestOptions = { headers: { Accept: "*/*" } };
  let response = await send(path, options);
  if (response.status === 401 && authHandler) {
    if (await authHandler.refresh()) response = await send(path, options);
  }
  if (!response.ok) {
    const requestId = response.headers.get("X-Request-ID");
    const envelope = errorEnvelopeSchema.safeParse(await readJson(response));
    throw new ApiError({
      status: response.status,
      code: envelope.success ? envelope.data.error.code : "http_error",
      message: envelope.success ? envelope.data.error.message : `Request failed with status ${response.status}.`,
      requestId: envelope.success ? (envelope.data.error.request_id ?? requestId) : requestId,
    });
  }
  const disposition = response.headers.get("Content-Disposition") ?? "";
  const match = /filename="([^"]+)"/.exec(disposition);
  return {
    blob: await response.blob(),
    filename: match?.[1] ?? "report",
    sha256: response.headers.get("X-Content-SHA256"),
  };
}

/** Schema for endpoints that return 204 No Content. */
export const noContent = z.null();

/** Schema for paginated list responses. */
export function pageSchema<T extends z.ZodType>(item: T) {
  return z.object({
    items: z.array(item),
    total: z.number().int().nonnegative(),
    page: z.number().int().positive(),
    page_size: z.number().int().positive(),
  });
}
