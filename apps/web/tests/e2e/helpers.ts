import { expect, type Page } from "@playwright/test";

export const ADMIN_EMAIL = process.env.E2E_ADMIN_EMAIL ?? "admin@sentinelx.example.com";
export const ADMIN_PASSWORD = process.env.E2E_ADMIN_PASSWORD ?? "";

export async function signIn(page: Page, email: string, password: string): Promise<void> {
  await page.goto("/login");
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: /sign in/i }).click();
  await expect(page.getByRole("navigation", { name: "Primary" })).toBeVisible();
}

export async function signOut(page: Page): Promise<void> {
  await page.getByRole("button", { name: /sign out/i }).first().click();
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
}
