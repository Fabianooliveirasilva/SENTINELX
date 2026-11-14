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
const ScansPage = lazy(() => import("@/features/scans/scans-page").then((m) => ({ default: m.ScansPage })));
const ScanDetailPage = lazy(() =>
  import("@/features/scans/scan-detail-page").then((m) => ({ default: m.ScanDetailPage })),
);
const FindingsPage = lazy(() =>
  import("@/features/findings/findings-page").then((m) => ({ default: m.FindingsPage })),
);
const FindingDetailPage = lazy(() =>
  import("@/features/findings/finding-detail-page").then((m) => ({ default: m.FindingDetailPage })),
);
const IntelligencePage = lazy(() =>
  import("@/features/intelligence/intelligence-page").then((m) => ({ default: m.IntelligencePage })),
);
const CveDetailPage = lazy(() =>
  import("@/features/intelligence/cve-detail-page").then((m) => ({ default: m.CveDetailPage })),
);
const SoftwarePage = lazy(() =>
  import("@/features/intelligence/software-page").then((m) => ({ default: m.SoftwarePage })),
);
const ProjectRiskPage = lazy(() =>
  import("@/features/risk/project-risk-page").then((m) => ({ default: m.ProjectRiskPage })),
);
const RiskModelPage = lazy(() => import("@/features/risk/risk-model-page").then((m) => ({ default: m.RiskModelPage })));
const EventsPage = lazy(() => import("@/features/monitoring/events-page").then((m) => ({ default: m.EventsPage })));
const AlertsPage = lazy(() => import("@/features/monitoring/alerts-page").then((m) => ({ default: m.AlertsPage })));
const SchedulesPage = lazy(() =>
  import("@/features/monitoring/schedules-page").then((m) => ({ default: m.SchedulesPage })),
);
const AIAnalystPage = lazy(() => import("@/features/ai/ai-page").then((m) => ({ default: m.AIAnalystPage })));
const ReportsPage = lazy(() => import("@/features/reports/reports-page").then((m) => ({ default: m.ReportsPage })));
const DashboardPage = lazy(() => import("@/features/dashboard/dashboard-page").then((m) => ({ default: m.DashboardPage })));
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
export const ScansRoute = () => (
  <Loading>
    <ScansPage />
  </Loading>
);
export const ScanDetailRoute = () => (
  <Loading>
    <ScanDetailPage />
  </Loading>
);
export const FindingsRoute = () => (
  <Loading>
    <FindingsPage />
  </Loading>
);
export const FindingDetailRoute = () => (
  <Loading>
    <FindingDetailPage />
  </Loading>
);
export const IntelligenceRoute = () => (
  <Loading>
    <IntelligencePage />
  </Loading>
);
export const CveDetailRoute = () => (
  <Loading>
    <CveDetailPage />
  </Loading>
);
export const SoftwareRoute = () => (
  <Loading>
    <SoftwarePage />
  </Loading>
);
export const ProjectRiskRoute = () => (
  <Loading>
    <ProjectRiskPage />
  </Loading>
);
export const RiskModelRoute = () => (
  <Loading>
    <RiskModelPage />
  </Loading>
);
export const EventsRoute = () => (
  <Loading>
    <EventsPage />
  </Loading>
);
export const AlertsRoute = () => (
  <Loading>
    <AlertsPage />
  </Loading>
);
export const SchedulesRoute = () => (
  <Loading>
    <SchedulesPage />
  </Loading>
);
export const AIAnalystRoute = () => (
  <Loading>
    <AIAnalystPage />
  </Loading>
);
export const ReportsRoute = () => (
  <Loading>
    <ReportsPage />
  </Loading>
);
const VulnerabilitiesPage = lazy(() =>
  import("@/features/portfolio/vulnerabilities-page").then((m) => ({ default: m.VulnerabilitiesPage })),
);
const ReconPage = lazy(() => import("@/features/portfolio/recon-page").then((m) => ({ default: m.ReconPage })));
export const VulnerabilitiesRoute = () => (
  <Loading>
    <VulnerabilitiesPage />
  </Loading>
);
export const ReconRoute = () => (
  <Loading>
    <ReconPage />
  </Loading>
);
export const DashboardRoute = () => (
  <Loading>
    <DashboardPage />
  </Loading>
);
