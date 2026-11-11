import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { routes } from "@/app/routes";
import { jsonResponse, mockApi, mockFetch, renderRoutes, requestBody, requestUrl, signInAs } from "@/test-utils";

const page = <T,>(items: T[]) => ({ items, total: items.length, page: 1, page_size: 25 });

const analyst = {
  id: "00000000-0000-4000-8000-000000000002",
  email: "analyst@example.com",
  full_name: "Ana Lyst",
  role: "security_analyst",
  is_active: true,
  created_at: "2026-11-10T10:00:00Z",
  last_login_at: null,
  locked: true,
};

const roles = [
  { name: "admin", description: "Full", permissions: ["users:manage", "users:read"] },
  { name: "security_analyst", description: "Analyst", permissions: ["scans:execute"] },
  { name: "viewer", description: "Read", permissions: ["projects:read"] },
];

type FetchMock = ReturnType<typeof mockApi>;

function requestOf(fetchMock: FetchMock, index: number) {
  const [url, init] = fetchMock.mock.calls[index] ?? [];
  return { url: requestUrl(url), method: init?.method, body: requestBody(init) };
}

function findRequest(fetchMock: FetchMock, method: string, path: string) {
  const index = fetchMock.mock.calls.findIndex(
    ([url, init]) => (init?.method ?? "GET") === method && requestUrl(url).startsWith(path),
  );
  return requestOf(fetchMock, index);
}

describe("UsersPage", () => {
  it("lists users with status badges and the role catalog", async () => {
    signInAs("admin");
    mockApi({ "GET /api/v1/users": jsonResponse(page([analyst])), "GET /api/v1/roles": jsonResponse(roles) });

    renderRoutes(routes, "/users");

    const table = await screen.findByRole("table", { name: "Users" });
    expect(within(table).getByText("Ana Lyst")).toBeInTheDocument();
    expect(within(table).getByText("Locked")).toBeInTheDocument();
    expect(await screen.findByRole("list", { name: "Admin permissions" })).toHaveTextContent("users:manage");
  });

  it("creates a user through the dialog with validated input", async () => {
    signInAs("admin");
    const fetchMock = mockApi({
      "GET /api/v1/users": [jsonResponse(page([])), jsonResponse(page([analyst]))],
      "GET /api/v1/roles": jsonResponse(roles),
      "POST /api/v1/users": jsonResponse(analyst, { status: 201 }),
    });
    renderRoutes(routes, "/users");
    await screen.findByText("No users match these filters");

    await userEvent.click(screen.getByRole("button", { name: /new user/i }));
    const dialog = await screen.findByRole("dialog", { name: "Create user" });
    await userEvent.type(within(dialog).getByLabelText("Full name"), "Ana Lyst");
    await userEvent.type(within(dialog).getByLabelText("Email"), "analyst@example.com");
    await userEvent.type(within(dialog).getByLabelText("Initial password"), "short");
    await userEvent.click(within(dialog).getByRole("button", { name: "Create user" }));
    expect(await within(dialog).findByText("Use at least 12 characters.")).toBeInTheDocument();

    await userEvent.clear(within(dialog).getByLabelText("Initial password"));
    await userEvent.type(within(dialog).getByLabelText("Initial password"), "a-strong-passphrase");
    await userEvent.selectOptions(within(dialog).getByLabelText("Role"), "security_analyst");
    await userEvent.click(within(dialog).getByRole("button", { name: "Create user" }));

    expect(await screen.findByText("Ana Lyst")).toBeInTheDocument();
    const created = findRequest(fetchMock, "POST", "/api/v1/users");
    expect(created).toMatchObject({ url: "/api/v1/users", method: "POST" });
    expect(created.body).toEqual({
      full_name: "Ana Lyst",
      email: "analyst@example.com",
      password: "a-strong-passphrase",
      role: "security_analyst",
    });
  });

  it("changes a user's role", async () => {
    signInAs("admin");
    const fetchMock = mockApi({
      "GET /api/v1/users": [jsonResponse(page([analyst])), jsonResponse(page([{ ...analyst, role: "viewer" }]))],
      "GET /api/v1/roles": jsonResponse(roles),
      [`PATCH /api/v1/users/${analyst.id}`]: jsonResponse({ ...analyst, role: "viewer" }),
    });
    renderRoutes(routes, "/users");

    await userEvent.selectOptions(await screen.findByLabelText("Role for analyst@example.com"), "viewer");

    await screen.findByDisplayValue("Viewer");
    expect(findRequest(fetchMock, "PATCH", "/api/v1/users/")).toMatchObject({
      url: `/api/v1/users/${analyst.id}`,
      method: "PATCH",
      body: { role: "viewer" },
    });
  });
});

describe("ProjectsPage", () => {
  it("shows an empty state that depends on the user's permissions", async () => {
    signInAs("viewer", ["projects:read"]);
    mockFetch(jsonResponse(page([])));

    renderRoutes(routes, "/projects");

    expect(await screen.findByText("Ask an administrator to add you to a project.")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /new project/i })).not.toBeInTheDocument();
  });

  it("reports missing projects without leaking whether they exist", async () => {
    signInAs("viewer", ["projects:read"]);
    mockFetch(
      jsonResponse({ error: { code: "not_found", message: "Project not found.", request_id: "r" } }, { status: 404 }),
    );

    renderRoutes(routes, "/projects/00000000-0000-4000-8000-00000000abcd");

    expect(await screen.findByText("Project not found or you are not a member.")).toBeInTheDocument();
  });
});

describe("AuditLogsPage", () => {
  it("lists entries and filters by action", async () => {
    signInAs("admin");
    const entry = {
      id: "00000000-0000-4000-8000-0000000000aa",
      created_at: "2026-11-10T10:00:00Z",
      action: "auth.login",
      outcome: "failure",
      actor_id: null,
      actor_email: null,
      target_type: "user",
      target_id: "00000000-0000-4000-8000-000000000002",
      project_id: null,
      ip_address: "10.0.0.5",
      user_agent: "pytest",
      request_id: "abcdef1234567890",
      details: { reason: "invalid_password" },
    };
    const fetchMock = mockApi({
      "GET /api/v1/audit-logs": [jsonResponse({ ...page([entry]), page_size: 50 }), jsonResponse({ ...page([]), page_size: 50 })],
      "GET /api/v1/audit-logs/actions": jsonResponse(["auth.login", "project.created"]),
    });
    renderRoutes(routes, "/audit-logs");

    const table = await screen.findByRole("table", { name: "Audit log entries" });
    expect(within(table).getByText("auth.login")).toBeInTheDocument();
    expect(within(table).getByText("failure")).toBeInTheDocument();
    expect(within(table).getByText("anonymous")).toBeInTheDocument();
    expect(within(table).getByText(/invalid_password/)).toBeInTheDocument();

    await screen.findByRole("option", { name: "project.created" });
    await userEvent.selectOptions(screen.getByLabelText("Filter by action"), "project.created");

    expect(await screen.findByText("No audit entries match these filters")).toBeInTheDocument();
    expect(fetchMock.mock.calls.some(([url]) => requestUrl(url).includes("action=project.created"))).toBe(true);
  });
});
