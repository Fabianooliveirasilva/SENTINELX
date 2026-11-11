import { expect, test } from "@playwright/test";

import { ADMIN_EMAIL, ADMIN_PASSWORD, signIn, signOut } from "./helpers";

test.describe.configure({ mode: "serial" });

const viewerEmail = `viewer-${Date.now()}@sentinelx.example.com`;
const viewerPassword = "viewer-e2e-passphrase";

test("anonymous visitors are sent to the login page", async ({ page }) => {
  await page.goto("/audit-logs");

  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
  expect(new URL(page.url()).searchParams.get("next")).toBe("/audit-logs");
});

test("invalid credentials show a generic error", async ({ page }) => {
  await page.goto("/login");
  await page.getByLabel("Email").fill(ADMIN_EMAIL);
  await page.getByLabel("Password").fill("definitely-wrong-password");
  await page.getByRole("button", { name: /sign in/i }).click();

  await expect(page.getByRole("alert")).toContainText("Invalid email or password.");
});

test("session survives a reload via the HttpOnly refresh cookie, and logout ends it", async ({ page, context }) => {
  await signIn(page, ADMIN_EMAIL, ADMIN_PASSWORD);

  const cookies = await context.cookies();
  const refresh = cookies.find((c) => c.name === "sentinelx_refresh");
  expect(refresh?.httpOnly).toBe(true);
  expect(refresh?.sameSite).toBe("Strict");
  expect(refresh?.path).toBe("/api/v1/auth");

  await page.reload();
  await expect(page.getByRole("navigation", { name: "Primary" })).toBeVisible();

  await signOut(page);
  await page.reload();
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
});

test("admin creates a viewer who only gets read-only navigation", async ({ page }) => {
  await signIn(page, ADMIN_EMAIL, ADMIN_PASSWORD);
  await page.getByRole("link", { name: "Users & Roles" }).click();
  await page.getByRole("button", { name: /new user/i }).click();
  const dialog = page.getByRole("dialog", { name: "Create user" });
  await dialog.getByLabel("Full name").fill("E2E Viewer");
  await dialog.getByLabel("Email").fill(viewerEmail);
  await dialog.getByLabel("Initial password").fill(viewerPassword);
  await dialog.getByLabel("Role").selectOption("viewer");
  await dialog.getByRole("button", { name: "Create user" }).click();
  await expect(dialog).toBeHidden();
  await expect(page.getByRole("table", { name: "Users" })).toContainText(viewerEmail);
  await signOut(page);

  await signIn(page, viewerEmail, viewerPassword);
  const nav = page.getByRole("navigation", { name: "Primary" });
  await expect(nav).toContainText("Projects");
  await expect(nav).not.toContainText("Users & Roles");
  await expect(nav).not.toContainText("Audit Logs");

  await page.goto("/users");
  await expect(page.getByRole("heading", { name: "Access denied" })).toBeVisible();
});

test("admin sees the actions in the audit log", async ({ page }) => {
  await signIn(page, ADMIN_EMAIL, ADMIN_PASSWORD);
  await page.getByRole("link", { name: "Audit Logs" }).click();

  const table = page.getByRole("table", { name: "Audit log entries" });
  await expect(table).toContainText("user.created");
  await expect(table).toContainText("auth.login");
});
