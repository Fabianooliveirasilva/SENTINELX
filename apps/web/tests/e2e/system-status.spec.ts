import { expect, test } from "@playwright/test";

import { ADMIN_EMAIL, ADMIN_PASSWORD, signIn } from "./helpers";

/**
 * Smoke test against a running stack. With E2E_EXPECT_OPERATIONAL=1 (CI with
 * docker compose) the platform must report every dependency as operational.
 */
test("system status page reflects real backend readiness", async ({ page }) => {
  await signIn(page, ADMIN_EMAIL, ADMIN_PASSWORD);
  await page.getByRole("link", { name: "System Status" }).click();

  await expect(page.getByRole("heading", { name: "System Status" })).toBeVisible();
  const overall = page.getByTestId("overall-status");
  await expect(overall).toBeVisible();

  if (process.env.E2E_EXPECT_OPERATIONAL === "1") {
    await expect(overall).toHaveText("Operational");
    await expect(page.getByText("PostgreSQL")).toBeVisible();
    await expect(page.getByText("Redis")).toBeVisible();
  } else {
    await expect(overall).toHaveText(/Operational|Degraded/);
  }
});

test("unknown routes render the 404 page", async ({ page }) => {
  await signIn(page, ADMIN_EMAIL, ADMIN_PASSWORD);
  await page.goto("/definitely-not-a-page");

  await expect(page.getByRole("heading", { name: "Page not found" })).toBeVisible();
});
