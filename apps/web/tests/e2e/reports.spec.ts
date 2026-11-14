import { readFile } from "node:fs/promises";

import { expect, test } from "@playwright/test";

import { ADMIN_EMAIL, ADMIN_PASSWORD, signIn } from "./helpers";

test.describe.configure({ mode: "serial" });

const projectName = `Reports E2E ${Date.now()}`;

test("generate a PDF report and download it", async ({ page }) => {
  await signIn(page, ADMIN_EMAIL, ADMIN_PASSWORD);
  await page.getByRole("link", { name: "Projects" }).click();
  await page.getByRole("button", { name: /new project/i }).click();
  await page.getByRole("dialog").getByLabel("Name").fill(projectName);
  await page.getByRole("dialog").getByRole("button", { name: "Create project" }).click();
  await page.getByRole("navigation", { name: "Project sections" }).getByRole("link", { name: "Reports" }).click();

  await page.getByLabel("Title (optional)").fill("E2E assessment");
  await page.getByRole("button", { name: "Generate report" }).click();
  const table = page.getByRole("table", { name: "Reports" });
  await expect(table).toContainText("E2E assessment");
  // The orchestrator worker renders it; the list polls until it completes.
  await expect(table.getByText("completed")).toBeVisible({ timeout: 30_000 });

  const downloadPromise = page.waitForEvent("download");
  await table.getByRole("button", { name: "Download" }).click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toMatch(/^sentinelx-report-project-.*\.pdf$/);
  const path = await download.path();
  const bytes = await readFile(path);
  expect(bytes.subarray(0, 5).toString()).toBe("%PDF-");
});
