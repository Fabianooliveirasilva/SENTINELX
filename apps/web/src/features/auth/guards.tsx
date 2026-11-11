import { ShieldAlert } from "lucide-react";
import type { ReactNode } from "react";
import { Navigate, Outlet, useLocation, useSearchParams } from "react-router";

import { safeNextPath, useSessionBootstrap } from "./navigation";
import type { Permission } from "./schemas";
import { useCan, useSession } from "./use-auth";

function FullPageStatus({ label }: { label: string }) {
  return (
    <div role="status" className="flex min-h-dvh items-center justify-center">
      <span className="text-sm text-muted-foreground">{label}</span>
    </div>
  );
}

export function RequireAuth() {
  useSessionBootstrap();
  const { status } = useSession();
  const location = useLocation();

  if (status === "loading") return <FullPageStatus label="Restoring session…" />;
  if (status === "anonymous") {
    const next = `${location.pathname}${location.search}`;
    return <Navigate to={`/login?next=${encodeURIComponent(next)}`} replace />;
  }
  return <Outlet />;
}

/** Redirects authenticated users away from public auth pages (e.g. /login). */
export function RedirectIfAuthenticated({ children }: { children: ReactNode }) {
  useSessionBootstrap();
  const { status } = useSession();
  const [params] = useSearchParams();
  if (status === "loading") return <FullPageStatus label="Loading…" />;
  if (status === "authenticated") return <Navigate to={safeNextPath(params.get("next"))} replace />;
  return <>{children}</>;
}

export function RequirePermission({
  permission,
  children,
}: {
  permission: Permission;
  children: ReactNode;
}) {
  const allowed = useCan(permission);
  if (!allowed) {
    return (
      <div role="alert" className="flex flex-col items-start gap-2 py-16">
        <ShieldAlert className="size-5 text-status-down" aria-hidden="true" />
        <h1 className="text-lg font-semibold">Access denied</h1>
        <p className="text-sm text-muted-foreground">
          Your role does not include the permission required to view this page.
        </p>
      </div>
    );
  }
  return <>{children}</>;
}
