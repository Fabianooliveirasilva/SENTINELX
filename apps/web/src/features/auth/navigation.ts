import { useEffect } from "react";

import { refreshSession } from "./api";
import { sessionStore } from "./session-store";

/**
 * Only same-application paths are accepted as post-login destinations, which
 * prevents open redirects such as `?next=//evil.example` or `?next=https://…`.
 */
export function safeNextPath(next: string | null): string {
  if (!next?.startsWith("/") || next.startsWith("//") || next.startsWith("/\\")) return "/";
  return next;
}

/** Restores the session from the refresh cookie on first load. */
export function useSessionBootstrap(): void {
  useEffect(() => {
    if (sessionStore.getSnapshot().status === "loading") void refreshSession();
  }, []);
}
