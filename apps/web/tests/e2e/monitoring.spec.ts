import { expect, test } from "@playwright/test";

import { ADMIN_EMAIL, ADMIN_PASSWORD, signIn } from "./helpers";

test.describe.configure({ mode: "serial" });

const projectName = `Monitoring E2E ${Date.now()}`;

test("timeline, alert configuration and scan schedules", async ({ page }) => {
  await signIn(page, ADMIN_EMAIL, ADMIN_PASSWORD);
  const sections = page.getByRole("navigation", { name: "Project sections" });

  // Project with an authorized asset: both changes appear in the timeline.
  await page.getByRole("link", { name: "Projects" }).click();
  await page.getByRole("button", { name: /new project/i }).click();
  await page.getByRole("dialog").getByLabel("Name").fill(projectName);
  await page.getByRole("dialog").getByRole("button", { name: "Create project" }).click();
  await sections.getByRole("link", { name: "Assets" }).click();
  await page.getByRole("button", { name: /register asset/i }).click();
  let dialog = page.getByRole("dialog", { name: "Register asset" });
  await dialog.getByLabel("Type").selectOption("ip_address");
  await dialog.getByLabel("Value").fill("93.184.215.14");
  await dialog.getByRole("button", { name: "Register asset" }).click();
  await page.getByRole("button", { name: /add authorization/i }).click();
  dialog = page.getByRole("dialog", { name: "Record authorization" });
  await dialog.getByLabel("Authorized by").fill("Jane Owner");
  await dialog.getByLabel("Organization").fill("Example Org");
  await dialog.getByLabel("Reference").fill("SOW-E2E-MON");
  await dialog.getByRole("checkbox", { name: /^Active testing/ }).check();
  await dialog.getByRole("button", { name: "Record authorization" }).click();
  await expect(dialog).toBeHidden();

  await sections.getByRole("link", { name: "Events" }).click();
  const timeline = page.getByRole("list", { name: "Security events" });
  await expect(timeline).toContainText("Asset registered: 93.184.215.14");
  await expect(timeline).toContainText("SOW-E2E-MON");

  // Alerts: an e-mail channel and a rule routed to it. No delivery is attempted
  // against external systems.
  await sections.getByRole("link", { name: "Alerts" }).click();
  await page.getByRole("button", { name: "New channel" }).click();
  dialog = page.getByRole("dialog", { name: "New notification channel" });
  await dialog.getByLabel("Name").fill("SOC mail");
  await dialog.getByLabel("Recipients").fill("soc@example.com");
  await dialog.getByRole("button", { name: "Create channel" }).click();
  await expect(page.getByRole("table", { name: "Notification channels" })).toContainText("soc@example.com");

  // Webhooks must use https in production-like deployments and never embed credentials.
  await page.getByRole("button", { name: "New channel" }).click();
  dialog = page.getByRole("dialog", { name: "New notification channel" });
  await dialog.getByLabel("Name").fill("Bad hook");
  await dialog.getByLabel("Type").selectOption("webhook");
  await dialog.getByLabel("URL").fill("https://user:pass@hooks.example.com/x");
  await dialog.getByRole("button", { name: "Create channel" }).click();
  await expect(dialog.getByRole("alert")).toContainText("Credentials in the URL");
  await dialog.getByLabel("URL").fill("https://hooks.example.com/sentinelx");
  await dialog.getByRole("button", { name: "Create channel" }).click();
  const secret = page.getByRole("dialog", { name: "Webhook signing secret" });
  await expect(secret).toContainText("whsec_");
  await secret.getByRole("button", { name: "I have stored it" }).click();

  await page.getByRole("button", { name: "New rule" }).click();
  dialog = page.getByRole("dialog", { name: "New alert rule" });
  await dialog.getByLabel("Name").fill("Critical findings");
  await dialog.getByLabel("Minimum severity").selectOption("critical");
  await dialog.getByRole("checkbox", { name: "Finding created" }).check();
  await dialog.getByRole("checkbox", { name: /SOC mail/ }).check();
  await dialog.getByRole("button", { name: "Create rule" }).click();
  await expect(page.getByRole("table", { name: "Alert rules" })).toContainText("Critical findings");

  // Schedules: the first run is a week away and the schedule is then paused, so
  // no scan is ever sent to a public host during E2E.
  await sections.getByRole("link", { name: "Schedules" }).click();
  await page.getByRole("button", { name: "New schedule" }).click();
  dialog = page.getByRole("dialog", { name: "Schedule a recurring scan" });
  await dialog.getByLabel("Asset").selectOption({ label: "93.184.215.14" });
  await dialog.getByLabel("Scanner").selectOption("nmap");
  await dialog.getByLabel("Frequency").selectOption("168");
  await dialog.getByLabel("First run").selectOption("later");
  await dialog.getByRole("button", { name: "Create schedule" }).click();
  const schedules = page.getByRole("table", { name: "Scan schedules" });
  await expect(schedules).toContainText("Weekly");
  await schedules.getByRole("button", { name: "Pause" }).click();
  await expect(schedules).toContainText("paused");
});
