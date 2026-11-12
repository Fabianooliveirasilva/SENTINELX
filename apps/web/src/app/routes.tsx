import type { RouteObject } from "react-router";

import {
  AccountRoute,
  AssetDetailRoute,
  AssetsRoute,
  AuditLogsRoute,
  CveDetailRoute,
  FindingDetailRoute,
  FindingsRoute,
  IntelligenceRoute,
  ProjectDetailRoute,
  ProjectRiskRoute,
  EventsRoute,
  AlertsRoute,
  SchedulesRoute,
  ProjectsRoute,
  RiskModelRoute,
  ScanDetailRoute,
  ScansRoute,
  ScopeCheckRoute,
  SoftwareRoute,
  UsersRoute,
} from "@/app/lazy-pages";
import { NotFoundPage } from "@/app/not-found-page";
import { ForgotPasswordPage } from "@/features/auth/forgot-password-page";
import { RedirectIfAuthenticated, RequireAuth, RequirePermission } from "@/features/auth/guards";
import { LoginPage } from "@/features/auth/login-page";
import { ResetPasswordPage } from "@/features/auth/reset-password-page";
import { SystemStatusPage } from "@/features/system-status/system-status-page";
import { AppLayout } from "@/layouts/app-layout";

export const routes: RouteObject[] = [
  {
    path: "/login",
    element: (
      <RedirectIfAuthenticated>
        <LoginPage />
      </RedirectIfAuthenticated>
    ),
  },
  { path: "/forgot-password", element: <ForgotPasswordPage /> },
  { path: "/reset-password", element: <ResetPasswordPage /> },
  {
    element: <RequireAuth />,
    children: [
      {
        element: <AppLayout />,
        children: [
          { index: true, element: <SystemStatusPage /> },
          {
            path: "projects",
            element: (
              <RequirePermission permission="projects:read">
                <ProjectsRoute />
              </RequirePermission>
            ),
          },
          {
            path: "projects/:projectId",
            element: (
              <RequirePermission permission="projects:read">
                <ProjectDetailRoute />
              </RequirePermission>
            ),
          },
          {
            path: "projects/:projectId/assets",
            element: (
              <RequirePermission permission="assets:read">
                <AssetsRoute />
              </RequirePermission>
            ),
          },
          {
            path: "projects/:projectId/assets/:assetId",
            element: (
              <RequirePermission permission="assets:read">
                <AssetDetailRoute />
              </RequirePermission>
            ),
          },
          {
            path: "projects/:projectId/scope",
            element: (
              <RequirePermission permission="assets:read">
                <ScopeCheckRoute />
              </RequirePermission>
            ),
          },
          {
            path: "projects/:projectId/scans",
            element: (
              <RequirePermission permission="scans:read">
                <ScansRoute />
              </RequirePermission>
            ),
          },
          {
            path: "projects/:projectId/scans/:scanId",
            element: (
              <RequirePermission permission="scans:read">
                <ScanDetailRoute />
              </RequirePermission>
            ),
          },
          {
            path: "projects/:projectId/findings",
            element: (
              <RequirePermission permission="findings:read">
                <FindingsRoute />
              </RequirePermission>
            ),
          },
          {
            path: "projects/:projectId/findings/:findingId",
            element: (
              <RequirePermission permission="findings:read">
                <FindingDetailRoute />
              </RequirePermission>
            ),
          },
          {
            path: "projects/:projectId/software",
            element: (
              <RequirePermission permission="assets:read">
                <SoftwareRoute />
              </RequirePermission>
            ),
          },
          {
            path: "intelligence",
            element: (
              <RequirePermission permission="intelligence:read">
                <IntelligenceRoute />
              </RequirePermission>
            ),
          },
          {
            path: "intelligence/cves/:cveId",
            element: (
              <RequirePermission permission="intelligence:read">
                <CveDetailRoute />
              </RequirePermission>
            ),
          },
          {
            path: "projects/:projectId/risk",
            element: (
              <RequirePermission permission="findings:read">
                <ProjectRiskRoute />
              </RequirePermission>
            ),
          },
          {
            path: "projects/:projectId/events",
            element: (
              <RequirePermission permission="events:read">
                <EventsRoute />
              </RequirePermission>
            ),
          },
          {
            path: "projects/:projectId/alerts",
            element: (
              <RequirePermission permission="events:read">
                <AlertsRoute />
              </RequirePermission>
            ),
          },
          {
            path: "projects/:projectId/schedules",
            element: (
              <RequirePermission permission="scans:read">
                <SchedulesRoute />
              </RequirePermission>
            ),
          },
          {
            path: "risk-model",
            element: (
              <RequirePermission permission="findings:read">
                <RiskModelRoute />
              </RequirePermission>
            ),
          },
          {
            path: "users",
            element: (
              <RequirePermission permission="users:read">
                <UsersRoute />
              </RequirePermission>
            ),
          },
          {
            path: "audit-logs",
            element: (
              <RequirePermission permission="audit:read">
                <AuditLogsRoute />
              </RequirePermission>
            ),
          },
          { path: "settings/account", element: <AccountRoute /> },
          { path: "*", element: <NotFoundPage /> },
        ],
      },
    ],
  },
];
