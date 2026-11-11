import { lazy, Suspense, type ReactNode } from "react";

// Route-level code splitting: management pages are loaded on first visit.
const ProjectsPage = lazy(() => import("@/features/projects/projects-page").then((m) => ({ default: m.ProjectsPage })));
const ProjectDetailPage = lazy(() =>
  import("@/features/projects/project-detail-page").then((m) => ({ default: m.ProjectDetailPage })),
);
const UsersPage = lazy(() => import("@/features/users/users-page").then((m) => ({ default: m.UsersPage })));
const AuditLogsPage = lazy(() => import("@/features/audit/audit-logs-page").then((m) => ({ default: m.AuditLogsPage })));
const AssetsPage = lazy(() => import("@/features/assets/assets-page").then((m) => ({ default: m.AssetsPage })));
const AssetDetailPage = lazy(() =>
  import("@/features/assets/asset-detail-page").then((m) => ({ default: m.AssetDetailPage })),
);
const ScopeCheckPage = lazy(() =>
  import("@/features/assets/scope-check-page").then((m) => ({ default: m.ScopeCheckPage })),
);
const AccountPage = lazy(() => import("@/features/settings/account-page").then((m) => ({ default: m.AccountPage })));

function Loading({ children }: { children: ReactNode }) {
  return (
    <Suspense fallback={<p role="status" className="text-sm text-muted-foreground">Loading…</p>}>{children}</Suspense>
  );
}

export const ProjectsRoute = () => (
  <Loading>
    <ProjectsPage />
  </Loading>
);
export const ProjectDetailRoute = () => (
  <Loading>
    <ProjectDetailPage />
  </Loading>
);
export const UsersRoute = () => (
  <Loading>
    <UsersPage />
  </Loading>
);
export const AuditLogsRoute = () => (
  <Loading>
    <AuditLogsPage />
  </Loading>
);
export const AccountRoute = () => (
  <Loading>
    <AccountPage />
  </Loading>
);
export const AssetsRoute = () => (
  <Loading>
    <AssetsPage />
  </Loading>
);
export const AssetDetailRoute = () => (
  <Loading>
    <AssetDetailPage />
  </Loading>
);
export const ScopeCheckRoute = () => (
  <Loading>
    <ScopeCheckPage />
  </Loading>
);
