import { createRequire } from "node:module";

import { expect, test, type Page } from "@playwright/test";

import { ADMIN_EMAIL, ADMIN_PASSWORD, signIn } from "./helpers";

const require = createRequire(import.meta.url);
const AXE_PATH = require.resolve("axe-core/axe.min.js");

/** Real-browser axe audit (WCAG 2.x A/AA), including colour contrast. */
async function audit(page: Page, label: string): Promise<void> {
  await page.addScriptTag({ path: AXE_PATH });
  // A string expression keeps this file free of DOM typings (the e2e tsconfig has no DOM lib).
  const violations = await page.evaluate<string[]>(`(async () => {
    const results = await window.axe.run(document, { runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"] } });
    return results.violations.map((v) => v.id + ": " + v.help + " (" + v.nodes.slice(0, 3).map((n) => n.target.join(" ")).join(" | ") + ")");
  })()`);
  expect(violations, `axe violations on ${label}`).toEqual([]);
}

const projectName = `A11y E2E ${Date.now()}`;
const pages: { path: string; ready: RegExp | string }[] = [
  { path: "/", ready: "Dashboard" },
  { path: "/vulnerabilities", ready: "Vulnerabilities" },
  { path: "/reconnaissance", ready: "Reconnaissance" },
  { path: "/projects", ready: "Projects" },
  { path: "/intelligence", ready: /threat intelligence/i },
  { path: "/risk-model", ready: /risk model/i },
  { path: "/users", ready: /users/i },
  { path: "/audit-logs", ready: /audit/i },
  { path: "/system-status", ready: "System Status" },
  { path: "/settings/account", ready: /account/i },
];

for (const scheme of ["light", "dark"] as const) {
  test(`pages pass axe in ${scheme} mode`, async ({ page }) => {
    test.setTimeout(120_000);
    await page.emulateMedia({ colorScheme: scheme });
    await signIn(page, ADMIN_EMAIL, ADMIN_PASSWORD);
    if (scheme === "light") {
      await page.getByRole("link", { name: "Projects" }).click();
      await page.getByRole("button", { name: /new project/i }).click();
      await page.getByRole("dialog").getByLabel("Name").fill(projectName);
      await page.getByRole("dialog").getByRole("button", { name: "Create project" }).click();
      await expect(page.getByRole("heading", { name: projectName })).toBeVisible();
    }
    for (const { path, ready } of pages) {
      await page.goto(path);
      await expect(page.getByRole("heading", { level: 1 }).first()).toBeVisible();
      await expect(page.getByRole("heading", { name: ready }).first()).toBeVisible();
      await expect(page.getByRole("status")).toHaveCount(0, { timeout: 15_000 }); // loading skeletons gone
      await audit(page, `${path} (${scheme})`);
    }
  });
}

test("skip link moves focus to the main content", async ({ page }) => {
  await signIn(page, ADMIN_EMAIL, ADMIN_PASSWORD);
  await page.keyboard.press("Tab");
  const skip = page.getByRole("link", { name: "Skip to main content" });
  await expect(skip).toBeFocused();
  await expect(skip).toBeVisible();
  await page.keyboard.press("Enter");
  await expect(page.locator("#main-content")).toBeFocused();
});

test("layout has no horizontal scroll on a phone-sized viewport", async ({ page }) => {
  await page.setViewportSize({ width: 375, height: 800 });
  await signIn(page, ADMIN_EMAIL, ADMIN_PASSWORD);
  for (const path of ["/", "/vulnerabilities", "/reconnaissance"]) {
    await page.goto(path);
    await expect(page.getByRole("heading", { level: 1 }).first()).toBeVisible();
    const overflow = await page.evaluate<number>("document.documentElement.scrollWidth - document.documentElement.clientWidth");
    expect(overflow, `horizontal overflow on ${path}`).toBeLessThanOrEqual(0);
  }
});

test("dashboard with populated charts passes axe", async ({ page }) => {
  test.setTimeout(60_000);
  const day = (n: number) => `2026-11-${String(n).padStart(2, "0")}`;
  const dashboard = {
    generated_at: "2026-11-14T10:00:00Z",
    scope: { project_id: null, projects: 2 },
    totals: { assets: 7, active_scans: 1, active_findings: 12, critical_findings: 2, high_findings: 3, known_exploited_findings: 1 },
    posture: { score: 81.4, band: "critical", worst_project: { id: "00000000-0000-4000-8000-0000000000f1", name: "Acme" } },
    posture_trend: Array.from({ length: 10 }, (_, i) => ({ day: day(i + 1), score: 55 + i * 3 })),
    risk_distribution: { critical: 2, high: 3, medium: 4, low: 2, info: 1 },
    assets_by_exposure: { external: 5, internal: 2, unknown: 0 },
    scan_activity: Array.from({ length: 14 }, (_, i) => ({ day: day(i + 1), completed: i % 4, failed: i % 5 === 0 ? 1 : 0, cancelled: 0, active: 0 })),
    remediation: {
      weekly: Array.from({ length: 8 }, (_, i) => ({ week: day(i * 2 + 1), opened: i + 1, resolved: i })),
      by_status: { open: 10, acknowledged: 2, resolved: 6, false_positive: 1, accepted_risk: 1 },
      closed_ratio: 0.4,
    },
    recent_findings: [
      { id: "00000000-0000-4000-8000-0000000000b1", project_id: "00000000-0000-4000-8000-0000000000f1", project_name: "Acme", title: "Exposed admin panel", severity: "critical", risk_band: "critical", risk_score: 88, asset: "app.example.com", first_seen_at: "2026-11-12T10:00:00Z" },
    ],
    projects: [
      { id: "00000000-0000-4000-8000-0000000000f1", name: "Acme", score: 81.4, band: "critical", active: 9 },
      { id: "00000000-0000-4000-8000-0000000000f2", name: "Beta", score: 30, band: "low", active: 3 },
    ],
    empty: false,
  };
  await page.route("**/api/v1/dashboard**", (route) => route.fulfill({ json: dashboard }));
  await signIn(page, ADMIN_EMAIL, ADMIN_PASSWORD);
  await page.goto("/");
  await expect(page.getByRole("region", { name: "Key figures" })).toBeVisible();
  await expect(page.getByRole("img", { name: /Risk distribution/ })).toBeVisible();
  await audit(page, "dashboard with data");
});
