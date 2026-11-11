import "@testing-library/jest-dom/vitest";

import { cleanup } from "@testing-library/react";
import { afterEach, vi } from "vitest";

import { sessionStore } from "@/features/auth/session-store";
import { setAuthHandler } from "@/lib/api-client";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  sessionStore.reset();
  setAuthHandler(null);
  document.cookie = "sentinelx_csrf=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/";
});
