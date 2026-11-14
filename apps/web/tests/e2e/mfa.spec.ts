import { createHmac } from "node:crypto";

import { expect, test } from "@playwright/test";

import { ADMIN_EMAIL, ADMIN_PASSWORD, signIn, signOut } from "./helpers";

test.describe.configure({ mode: "serial" });

const email = `mfa-${Date.now()}@example.com`;
const password = "E2e-Mfa-Pass-77!zq";

/** RFC 6238 TOTP (SHA-1, 6 digits, 30 s) for a base32 secret. */
function totp(secret: string, at = Date.now()): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const char of secret.replace(/=+$/, "")) bits += alphabet.indexOf(char).toString(2).padStart(5, "0");
  const key = Buffer.from(bits.match(/.{8}/g)?.map((b) => parseInt(b, 2)) ?? []);
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(at / 1000 / 30)));
  const digest = createHmac("sha1", key).update(counter).digest();
  const offset = (digest[digest.length - 1] ?? 0) & 0x0f;
  const value = digest.readUInt32BE(offset) & 0x7fffffff;
  return String(value % 1_000_000).padStart(6, "0");
}

let secret = "";
let recovery: string[] = [];

test("a user turns on two-factor authentication and gets recovery codes", async ({ page }) => {
  await signIn(page, ADMIN_EMAIL, ADMIN_PASSWORD);
  await page.getByRole("link", { name: "Users & Roles" }).click();
  await page.getByRole("button", { name: /new user/i }).click();
  const dialog = page.getByRole("dialog", { name: "Create user" });
  await dialog.getByLabel("Full name").fill("E2E MFA");
  await dialog.getByLabel("Email").fill(email);
  await dialog.getByLabel("Initial password").fill(password);
  await dialog.getByLabel("Role").selectOption("viewer");
  await dialog.getByRole("button", { name: "Create user" }).click();
  await expect(dialog).toBeHidden();
  await signOut(page);

  await signIn(page, email, password);
  await page.goto("/settings/account");
  await page.getByRole("button", { name: "Set up two-factor authentication" }).waitFor();
  await page.getByLabel("Current password").first().fill(password);
  await page.getByRole("button", { name: "Set up two-factor authentication" }).click();
  secret = (await page.getByLabel("Setup key").innerText()).trim();
  expect(secret).toMatch(/^[A-Z2-7]{32}$/);
  await page.getByLabel("Verification code").fill(totp(secret));
  await page.getByRole("button", { name: "Turn on" }).click();
  const list = page.getByRole("list", { name: "Recovery codes" });
  await expect(list.getByRole("listitem")).toHaveCount(10);
  recovery = await list.getByRole("listitem").allInnerTexts();
  await page.getByRole("button", { name: "I saved them" }).click();
  await expect(page.getByText("Enabled")).toBeVisible();
  await signOut(page);
});

test("sign-in now needs a second factor; a wrong code is refused, a recovery code works once", async ({ page }) => {
  await page.goto("/login");
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: /sign in/i }).click();
  await expect(page.getByRole("heading", { name: "Verification code" })).toBeVisible();

  await page.getByLabel("Code").fill("000000");
  await page.getByRole("button", { name: "Verify" }).click();
  await expect(page.getByRole("alert")).toContainText("Invalid or expired verification code.");
  await expect(page.getByRole("navigation", { name: "Primary" })).toHaveCount(0);

  await page.getByLabel("Code").fill(recovery[0] ?? "");
  await page.getByRole("button", { name: "Verify" }).click();
  await expect(page.getByRole("navigation", { name: "Primary" })).toBeVisible();
  await signOut(page);

  // The same recovery code cannot be used again.
  await page.goto("/login");
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: /sign in/i }).click();
  await page.getByLabel("Code").fill(recovery[0] ?? "");
  await page.getByRole("button", { name: "Verify" }).click();
  await expect(page.getByRole("alert")).toContainText("Invalid or expired verification code.");
});

test("an administrator can reset the second factor", async ({ page }) => {
  await signIn(page, ADMIN_EMAIL, ADMIN_PASSWORD);
  await page.getByRole("link", { name: "Users & Roles" }).click();
  page.once("dialog", (d) => void d.accept());
  await page.getByRole("button", { name: `Reset two-factor authentication for ${email}` }).click();
  await expect(page.getByText("MFA reset")).toBeVisible();
  await signOut(page);

  await signIn(page, email, password); // password alone works again
});
