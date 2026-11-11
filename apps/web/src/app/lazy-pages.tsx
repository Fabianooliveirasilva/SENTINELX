import { lazy, Suspense, type ReactNode } from "react";

// Route-level code splitting: management pages are loaded on first visit.
const ProjectsPage = lazy(() => import("@/features/projects/projects-page").then((m) => ({ default: m.ProjectsPage })));
const ProjectDetailPage = lazy(() =>
  import("@/features/projects/project-detail-page").then((m) => ({ default: m.ProjectDetailPage })),
);
const UsersPage = lazy(() => import("@/features/users/users-page").then((m) => ({ default: m.UsersPage })));
const AuditLogsPage = lazy(() => import("@/features/audit/audit-logs-page").then((m) => ({ default: m.AuditLogsPage })));
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
