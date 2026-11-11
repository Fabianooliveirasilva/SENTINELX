import type { CurrentUser } from "./schemas";

/**
 * In-memory session state. The access token is intentionally never persisted
 * (no localStorage/sessionStorage) so it cannot be exfiltrated by injected
 * scripts after a reload; the HttpOnly refresh cookie restores the session.
 */

export type AuthStatus = "loading" | "authenticated" | "anonymous";

export interface SessionState {
  status: AuthStatus;
  accessToken: string | null;
  user: CurrentUser | null;
}

type Listener = () => void;

const ANONYMOUS: SessionState = { status: "anonymous", accessToken: null, user: null };

let state: SessionState = { status: "loading", accessToken: null, user: null };
const listeners = new Set<Listener>();

function emit(next: SessionState): void {
  state = next;
  for (const listener of listeners) listener();
}

export const sessionStore = {
  getSnapshot: (): SessionState => state,
  subscribe: (listener: Listener): (() => void) => {
    listeners.add(listener);
    return () => listeners.delete(listener);
  },
  setSession(accessToken: string, user: CurrentUser): void {
    emit({ status: "authenticated", accessToken, user });
  },
  clear(): void {
    emit(ANONYMOUS);
  },
  /** Test helper: reset to the initial loading state. */
  reset(): void {
    emit({ status: "loading", accessToken: null, user: null });
  },
};
