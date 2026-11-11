import { z } from "zod";

import { apiRequest, noContent, readCookie, setAuthHandler } from "@/lib/api-client";

import {
  currentUserSchema,
  messageSchema,
  sessionSchema,
  tokenResponseSchema,
  type TokenResponse,
} from "./schemas";
import { sessionStore } from "./session-store";

const CSRF_COOKIE = "sentinelx_csrf";

function csrfHeaders(): Record<string, string> {
  const token = readCookie(CSRF_COOKIE);
  return token ? { "X-CSRF-Token": token } : {};
}

function applyTokens(tokens: TokenResponse): void {
  sessionStore.setSession(tokens.access_token, tokens.user);
}

export async function login(email: string, password: string): Promise<TokenResponse> {
  const tokens = await apiRequest("/auth/login", tokenResponseSchema, {
    method: "POST",
    body: { email, password },
    skipAuthRefresh: true,
  });
  applyTokens(tokens);
  return tokens;
}

let inflightRefresh: Promise<boolean> | null = null;

/**
 * Rotate the refresh token. Concurrent callers share one request: the backend
 * treats re-use of a rotated refresh token as theft, so parallel refreshes
 * would otherwise revoke the session.
 */
export function refreshSession(): Promise<boolean> {
  inflightRefresh ??= (async () => {
    try {
      const tokens = await apiRequest("/auth/refresh", tokenResponseSchema, {
        method: "POST",
        headers: csrfHeaders(),
        skipAuthRefresh: true,
      });
      applyTokens(tokens);
      return true;
    } catch {
      sessionStore.clear();
      return false;
    } finally {
      inflightRefresh = null;
    }
  })();
  return inflightRefresh;
}

export async function logout(): Promise<void> {
  try {
    await apiRequest("/auth/logout", noContent, {
      method: "POST",
      headers: csrfHeaders(),
      skipAuthRefresh: true,
    });
  } finally {
    sessionStore.clear();
  }
}

export function fetchCurrentUser() {
  return apiRequest("/auth/me", currentUserSchema);
}

export function changePassword(currentPassword: string, newPassword: string) {
  return apiRequest("/auth/change-password", noContent, {
    method: "POST",
    body: { current_password: currentPassword, new_password: newPassword },
  });
}

export function requestPasswordReset(email: string) {
  return apiRequest("/auth/password-reset/request", messageSchema, {
    method: "POST",
    body: { email },
    skipAuthRefresh: true,
  });
}

export function confirmPasswordReset(token: string, newPassword: string) {
  return apiRequest("/auth/password-reset/confirm", noContent, {
    method: "POST",
    body: { token, new_password: newPassword },
    skipAuthRefresh: true,
  });
}

export function listSessions() {
  return apiRequest("/auth/sessions", z.array(sessionSchema));
}

export function revokeSession(sessionId: string) {
  return apiRequest(`/auth/sessions/${encodeURIComponent(sessionId)}`, noContent, {
    method: "DELETE",
  });
}

/** Wire the API client to the session store (called once at startup). */
export function installAuthHandler(): void {
  setAuthHandler({
    getAccessToken: () => sessionStore.getSnapshot().accessToken,
    refresh: refreshSession,
  });
}
