import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { routes } from "@/app/routes";
import { jsonResponse, mockApi, renderRoutes, requestUrl, signInAs } from "@/test-utils";
import { expectNoA11yViolations } from "@/test-axe";

const wait = { timeout: 10_000 };
const sessions = jsonResponse([]);

describe("Two-factor authentication card", () => {
  it("enrols with the password, confirms a code and shows recovery codes once", async () => {
    signInAs("security_analyst", ["projects:read"]);
    const fetchMock = mockApi({
      "GET /api/v1/auth/mfa": [
        jsonResponse({ enabled: false, pending_enrollment: false, recovery_codes_remaining: 0 }),
        jsonResponse({ enabled: true, pending_enrollment: false, recovery_codes_remaining: 2 }),
      ],
      "GET /api/v1/auth/sessions": sessions,
      "POST /api/v1/auth/mfa/enroll": jsonResponse({ secret: "JBSWY3DPEHPK3PXP", otpauth_uri: "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP" }),
      "POST /api/v1/auth/mfa/confirm": jsonResponse({ recovery_codes: ["aaaaa-bbbbb", "ccccc-ddddd"] }),
    });
    const { container } = renderRoutes(routes, "/settings/account");
    await screen.findByText("Two-factor authentication", {}, wait);
    const setup = await screen.findByRole("button", { name: "Set up two-factor authentication" }, wait);
    const form = setup.closest("form");
    if (!form) throw new Error("form missing");
    await userEvent.type(within(form).getByLabelText("Current password"), "correct-password");
    await userEvent.click(screen.getByRole("button", { name: "Set up two-factor authentication" }));

    expect(await screen.findByLabelText("Setup key", {}, wait)).toHaveTextContent("JBSWY3DPEHPK3PXP");
    await userEvent.type(screen.getByLabelText("Verification code"), "123456");
    await userEvent.click(screen.getByRole("button", { name: "Turn on" }));

    const list = await screen.findByRole("list", { name: "Recovery codes" }, wait);
    expect(list).toHaveTextContent("aaaaa-bbbbb");
    await expectNoA11yViolations(container);
    const enroll = fetchMock.mock.calls.find(([input]) => requestUrl(input).endsWith("/auth/mfa/enroll"));
    expect(JSON.parse(enroll?.[1]?.body as string)).toEqual({ password: "correct-password" });

    await userEvent.click(screen.getByRole("button", { name: "I saved them" }));
    expect(screen.queryByRole("list", { name: "Recovery codes" })).not.toBeInTheDocument();
  }, 30_000);
});
