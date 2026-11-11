import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { routes } from "@/app/routes";
import { jsonResponse, mockFetch, renderRoutes, tokenResponse } from "@/test-utils";

import { installAuthHandler, logout, refreshSession } from "./api";
import { safeNextPath } from "./navigation";
import { sessionStore } from "./session-store";

const unauthorized = () =>
  jsonResponse(
    { error: { code: "not_authenticated", message: "Session expired.", request_id: "r-1" } },
    { status: 401 },
  );

describe("safeNextPath", () => {
  it.each([
    ["/projects?x=1", "/projects?x=1"],
    [null, "/"],
    ["https://evil.example", "/"],
    ["//evil.example", "/"],
    ["/\\evil.example", "/"],
    ["javascript:alert(1)", "/"],
  ])("maps %s to %s", (input, expected) => {
    expect(safeNextPath(input)).toBe(expected);
  });
});

describe("session management", () => {
  it("shares a single refresh request between concurrent callers", async () => {
    document.cookie = "sentinelx_csrf=csrf-value; path=/";
    const fetchMock = mockFetch(jsonResponse(tokenResponse()));

    const results = await Promise.all([refreshSession(), refreshSession(), refreshSession()]);

    expect(results).toEqual([true, true, true]);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const init = fetchMock.mock.calls[0]?.[1];
    expect(init?.headers).toMatchObject({ "X-CSRF-Token": "csrf-value" });
    expect(sessionStore.getSnapshot()).toMatchObject({ status: "authenticated", accessToken: "fresh-token" });
  });

  it("becomes anonymous when the refresh fails", async () => {
    mockFetch(unauthorized());

    expect(await refreshSession()).toBe(false);
    expect(sessionStore.getSnapshot().status).toBe("anonymous");
  });

  it("clears the session on logout even if the request fails", async () => {
    sessionStore.setSession("token", tokenResponse().user);
    mockFetch(new TypeError("offline"));

    await expect(logout()).rejects.toBeDefined();
    expect(sessionStore.getSnapshot().status).toBe("anonymous");
  });
});

describe("LoginPage", () => {
  it("validates input before calling the API", async () => {
    mockFetch(unauthorized()); // session bootstrap
    renderRoutes(routes, "/login");
    await screen.findByRole("heading", { name: "Sign in" });

    await userEvent.click(screen.getByRole("button", { name: /sign in/i }));

    expect(await screen.findByText("Enter a valid email address.")).toBeInTheDocument();
    expect(screen.getByText("Enter your password.")).toBeInTheDocument();
  });

  it("shows the API error for invalid credentials", async () => {
    mockFetch(
      unauthorized(),
      jsonResponse(
        { error: { code: "not_authenticated", message: "Invalid email or password.", request_id: "req-9" } },
        { status: 401 },
      ),
    );
    renderRoutes(routes, "/login");
    await screen.findByRole("heading", { name: "Sign in" });

    await userEvent.type(screen.getByLabelText("Email"), "a@example.com");
    await userEvent.type(screen.getByLabelText("Password"), "wrong-password");
    await userEvent.click(screen.getByRole("button", { name: /sign in/i }));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Invalid email or password.");
    expect(alert).toHaveTextContent("Request ID: req-9");
  });

  it("signs in and continues to the requested page", async () => {
    installAuthHandler();
    mockFetch(
      unauthorized(),
      jsonResponse(tokenResponse()),
      jsonResponse({ items: [], total: 0, page: 1, page_size: 50 }),
      jsonResponse([]),
    );
    renderRoutes(routes, "/login?next=%2Faudit-logs");
    await screen.findByRole("heading", { name: "Sign in" });

    await userEvent.type(screen.getByLabelText("Email"), "admin@example.com");
    await userEvent.type(screen.getByLabelText("Password"), "correct-password");
    await userEvent.click(screen.getByRole("button", { name: /sign in/i }));

    expect(await screen.findByRole("heading", { name: "Audit Logs" })).toBeInTheDocument();
  });
});

describe("authenticated requests", () => {
  it("refreshes once on 401 and retries with the new token", async () => {
    installAuthHandler();
    sessionStore.setSession("expired-token", tokenResponse().user);
    const fetchMock = mockFetch(
      unauthorized(),
      jsonResponse(tokenResponse()),
      jsonResponse({ id: tokenResponse().user.id, email: "admin@example.com", full_name: "T", role: "admin", permissions: [] }),
    );

    const { fetchCurrentUser } = await import("./api");
    const me = await fetchCurrentUser();

    expect(me.email).toBe("admin@example.com");
    expect(fetchMock).toHaveBeenCalledTimes(3);
    const retryHeaders = fetchMock.mock.calls[2]?.[1]?.headers as Record<string, string>;
    expect(retryHeaders.Authorization).toBe("Bearer fresh-token");
  });

  it("does not loop when the refresh also fails", async () => {
    installAuthHandler();
    sessionStore.setSession("expired-token", tokenResponse().user);
    const fetchMock = mockFetch(unauthorized(), unauthorized());

    const { fetchCurrentUser } = await import("./api");

    await expect(fetchCurrentUser()).rejects.toMatchObject({ status: 401 });
    expect(fetchMock).toHaveBeenCalledTimes(2);
    await waitFor(() => {
      expect(sessionStore.getSnapshot().status).toBe("anonymous");
    });
  });
});
