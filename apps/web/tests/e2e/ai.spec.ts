import { expect, test } from "@playwright/test";

import { ADMIN_EMAIL, ADMIN_PASSWORD, signIn } from "./helpers";

test.describe.configure({ mode: "serial" });

const projectName = `AI E2E ${Date.now()}`;

// Runs against a stack without an AI provider key: analyses are deterministic, so
// the test is reproducible and nothing is sent to a third party.
test("project summaries are labelled, advisory and reviewable", async ({ page }) => {
  await signIn(page, ADMIN_EMAIL, ADMIN_PASSWORD);
  await page.getByRole("link", { name: "Projects" }).click();
  await page.getByRole("button", { name: /new project/i }).click();
  await page.getByRole("dialog").getByLabel("Name").fill(projectName);
  await page.getByRole("dialog").getByRole("button", { name: "Create project" }).click();
  await page.getByRole("navigation", { name: "Project sections" }).getByRole("link", { name: "AI analyst" }).click();

  await expect(page.getByLabel("AI usage today")).toContainText("tokens today");
  await page.getByRole("button", { name: "Analyze" }).first().click();
  const summary = page.getByRole("article", { name: "Executive summary" }).first();
  await expect(summary).toContainText("No active findings in this project.");
  await expect(summary).toContainText("Deterministic");
  await expect(summary).toContainText("A person must review it");
  await summary.getByRole("button", { name: "Mark as reviewed" }).click();
  await expect(summary).toContainText("Reviewed by");
  await expect(page.getByRole("table", { name: "AI analyses" })).toContainText("Executive summary");
});
