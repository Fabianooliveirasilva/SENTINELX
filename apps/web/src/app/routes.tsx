import type { RouteObject } from "react-router";

import { NotFoundPage } from "@/app/not-found-page";
import { SystemStatusPage } from "@/features/system-status/system-status-page";
import { AppLayout } from "@/layouts/app-layout";

export const routes: RouteObject[] = [
  {
    element: <AppLayout />,
    children: [
      { index: true, element: <SystemStatusPage /> },
      { path: "*", element: <NotFoundPage /> },
    ],
  },
];
