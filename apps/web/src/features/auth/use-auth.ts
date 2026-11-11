import { useSyncExternalStore } from "react";

import type { Permission } from "./schemas";
import { sessionStore, type SessionState } from "./session-store";

export function useSession(): SessionState {
  return useSyncExternalStore(sessionStore.subscribe, sessionStore.getSnapshot);
}

/** UI-only permission check. The API enforces authorization independently. */
export function useCan(permission: Permission): boolean {
  const { user } = useSession();
  return user?.permissions.includes(permission) ?? false;
}
