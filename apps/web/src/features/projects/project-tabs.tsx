import { NavLink } from "react-router";

import { cn } from "@/lib/utils";

const tabs = [
  { to: "", label: "Overview", end: true },
  { to: "assets", label: "Assets", end: false },
  { to: "scope", label: "Scope check", end: true },
  { to: "scans", label: "Scans", end: false },
  { to: "schedules", label: "Schedules", end: true },
  { to: "findings", label: "Findings", end: false },
  { to: "risk", label: "Risk", end: true },
  { to: "events", label: "Events", end: true },
  { to: "alerts", label: "Alerts", end: true },
  { to: "ai", label: "AI analyst", end: true },
  { to: "reports", label: "Reports", end: true },
  { to: "software", label: "Software", end: true },
] as const;

export function ProjectTabs({ projectId }: { projectId: string }) {
  return (
    <nav aria-label="Project sections" className="flex gap-1 overflow-x-auto border-b border-border">
      {tabs.map((tab) => (
        <NavLink
          key={tab.label}
          to={`/projects/${projectId}${tab.to ? `/${tab.to}` : ""}`}
          end={tab.end}
          className={({ isActive }) =>
            cn(
              "-mb-px shrink-0 border-b-2 px-3 py-2 text-sm transition-colors",
              isActive ? "border-primary text-foreground" : "border-transparent text-muted-foreground hover:text-foreground",
            )
          }
        >
          {tab.label}
        </NavLink>
      ))}
    </nav>
  );
}
