import { expect, test } from "@playwright/test";

import { ADMIN_EMAIL, ADMIN_PASSWORD, signIn } from "./helpers";

test.describe.configure({ mode: "serial" });

const projectName = `Scope E2E ${Date.now()}`;

test("register an asset, authorize it and verify scope decisions", async ({ page }) => {
  await signIn(page, ADMIN_EMAIL, ADMIN_PASSWORD);

  // Project
  await page.getByRole("link", { name: "Projects" }).click();
  await page.getByRole("button", { name: /new project/i }).click();
  await page.getByRole("dialog").getByLabel("Name").fill(projectName);
  await page.getByRole("dialog").getByRole("button", { name: "Create project" }).click();
  await page.getByRole("navigation", { name: "Project sections" }).getByRole("link", { name: "Assets" }).click();

  // Internal addresses cannot be registered.
  await page.getByRole("button", { name: /register asset/i }).click();
  let dialog = page.getByRole("dialog", { name: "Register asset" });
  await dialog.getByLabel("Type").selectOption("ip_address");
  await dialog.getByLabel("Value").fill("169.254.169.254");
  await dialog.getByRole("button", { name: "Register asset" }).click();
  await expect(dialog.getByRole("alert")).toContainText("not publicly routable");

  // A public IP can be registered.
  await dialog.getByLabel("Value").fill("93.184.215.14");
  await dialog.getByRole("button", { name: "Register asset" }).click();
  await expect(page.getByRole("heading", { name: "93.184.215.14" })).toBeVisible();
  await expect(page.getByRole("list", { name: "Testing eligibility" })).toContainText("✕ passive");

  // Record an authorization permitting active testing.
  await page.getByRole("button", { name: /add authorization/i }).click();
  dialog = page.getByRole("dialog", { name: "Record authorization" });
  await dialog.getByLabel("Authorized by").fill("Jane Owner");
  await dialog.getByLabel("Organization").fill("Example Org");
  await dialog.getByLabel("Reference").fill("SOW-E2E-1");
  await dialog.getByRole("checkbox", { name: /^Active testing/ }).check();
  await dialog.getByRole("button", { name: "Record authorization" }).click();
  await expect(dialog).toBeHidden();
  await expect(page.getByRole("table", { name: "Authorizations" })).toContainText("SOW-E2E-1");
  await expect(page.getByRole("list", { name: "Testing eligibility" })).toContainText("✓ active");
  await expect(page.getByRole("list", { name: "Asset history" })).toContainText("asset.authorization_added");

  // Scope checks (no traffic is sent to targets).
  await page.getByRole("navigation", { name: "Project sections" }).getByRole("link", { name: "Scope check" }).click();
  await page.getByLabel("Target").fill("93.184.215.14");
  await page.getByRole("button", { name: /check/i }).click();
  await expect(page.getByTestId("scope-verdict")).toHaveText("In scope");

  await page.getByLabel("Target").fill("http://127.0.0.1:8080/");
  await page.getByRole("button", { name: /check/i }).click();
  await expect(page.getByTestId("scope-verdict")).toHaveText("Out of scope");

  await page.getByLabel("Technique").selectOption("intrusive");
  await page.getByLabel("Target").fill("93.184.215.14");
  await page.getByRole("button", { name: /check/i }).click();
  await expect(page.getByTestId("scope-verdict")).toHaveText("Out of scope");
  await expect(page.getByRole("list", { name: "Decision reasons" })).toContainText("technique_not_authorized");

  // Scan configuration only offers scanners the asset is eligible for. No scan is
  // started here: E2E runs must never send traffic to public hosts.
  await page.getByRole("navigation", { name: "Project sections" }).getByRole("link", { name: "Scans" }).click();
  await expect(page.getByText("No scans yet")).toBeVisible();
  await page.getByRole("button", { name: /new scan/i }).click();
  dialog = page.getByRole("dialog", { name: "New scan" });
  await dialog.getByLabel("Asset").selectOption({ label: "93.184.215.14" });
  const scanner = dialog.getByLabel("Scanner");
  await expect(scanner.getByRole("option", { name: "nmap (active)" })).toBeAttached();
  await expect(scanner.getByRole("option", { name: /^dns/ })).toHaveCount(0);
  await scanner.selectOption("nmap");
  await expect(dialog.getByLabel("Profile")).toHaveValue("quick");
  await page.keyboard.press("Escape");

  // Emergency stop blocks new scans until an administrator resumes scanning.
  await page.getByRole("button", { name: /emergency stop/i }).click();
  dialog = page.getByRole("dialog", { name: "Emergency stop" });
  await dialog.getByLabel("Reason").fill("E2E drill");
  await dialog.getByRole("button", { name: "Stop all scans" }).click();
  await expect(page.getByRole("alert").filter({ hasText: "halted platform-wide" })).toBeVisible();
  await expect(page.getByRole("button", { name: /new scan/i })).toBeDisabled();
  await page.getByRole("button", { name: "Resume scanning" }).click();
  await expect(page.getByRole("button", { name: /new scan/i })).toBeEnabled();

  // Findings start empty for a project that has not been scanned.
  await page.getByRole("navigation", { name: "Project sections" }).getByRole("link", { name: "Findings" }).click();
  await expect(page.getByRole("list", { name: "Open findings by severity" })).toBeVisible();
  await expect(page.getByText("No findings match these filters")).toBeVisible();
});
