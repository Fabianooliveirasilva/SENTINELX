import { Activity, ShieldHalf } from "lucide-react";
import { NavLink, Outlet } from "react-router";

import { cn } from "@/lib/utils";

const navigation = [{ to: "/", label: "System Status", icon: Activity }] as const;

export function AppLayout() {
  return (
    <div className="flex min-h-dvh flex-col md:flex-row">
      <aside className="flex shrink-0 flex-col border-b border-border bg-surface md:w-60 md:border-r md:border-b-0">
        <div className="flex h-14 items-center gap-2.5 px-5">
          <ShieldHalf className="size-5 text-primary" aria-hidden="true" />
          <span className="font-semibold tracking-tight">SentinelX</span>
        </div>
        <nav aria-label="Primary" className="flex gap-1 px-3 pb-3 md:flex-col">
          {navigation.map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              end
              className={({ isActive }) =>
                cn(
                  "flex items-center gap-2.5 rounded-md px-3 py-2 text-sm text-muted-foreground transition-colors hover:bg-surface-raised hover:text-foreground",
                  isActive && "bg-surface-raised text-foreground",
                )
              }
            >
              <Icon className="size-4" aria-hidden="true" />
              {label}
            </NavLink>
          ))}
        </nav>
      </aside>
      <main className="min-w-0 flex-1 px-4 py-6 sm:px-8">
        <div className="mx-auto max-w-6xl">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
