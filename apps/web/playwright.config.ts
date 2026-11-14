import { defineConfig, devices } from "@playwright/test";

/**
 * End-to-end tests run against a fully started stack (docker compose or local
 * API + Vite). They never target public hosts.
 *
 *   E2E_BASE_URL=http://localhost:8080 pnpm test:e2e
 */
export default defineConfig({
  testDir: "./tests/e2e",
  fullyParallel: true,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI
    ? [["list"], ["html", { open: "never" }], ...(process.env.PLAYWRIGHT_JSON_OUTPUT_NAME ? [["json"] as const] : [])]
    : "list",
  use: {
    baseURL: process.env.E2E_BASE_URL ?? "http://localhost:8080",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});
