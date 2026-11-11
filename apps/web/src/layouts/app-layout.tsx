import { Activity, FolderKanban, LogOut, ScrollText, ShieldHalf, UserCog, Users, type LucideIcon } from "lucide-react";
import { NavLink, Outlet } from "react-router";

import { Button } from "@/components/ui/button";
import { logout } from "@/features/auth/api";
import { ROLE_LABELS, type Permission } from "@/features/auth/schemas";
import { useSession } from "@/features/auth/use-auth";
import { cn } from "@/lib/utils";

interface NavItem {
  to: string;
  label: string;
  icon: LucideIcon;
  permission?: Permission;
  end?: boolean;
}

const navigation: NavItem[] = [
  { to: "/", label: "System Status", icon: Activity, end: true },
  { to: "/projects", label: "Projects", icon: FolderKanban, permission: "projects:read" },
  { to: "/users", label: "Users & Roles", icon: Users, permission: "users:read" },
  { to: "/audit-logs", label: "Audit Logs", icon: ScrollText, permission: "audit:read" },
  { to: "/settings/account", label: "Account", icon: UserCog },
];

export function AppLayout() {
  const { user } = useSession();
  // Navigation hides what the user cannot use; the API still enforces every permission.
  const items = navigation.filter((item) => !item.permission || user?.permissions.includes(item.permission));

  return (
    <div className="flex min-h-dvh flex-col md:flex-row">
      <aside className="flex shrink-0 flex-col border-b border-border bg-surface md:sticky md:top-0 md:h-dvh md:w-60 md:border-r md:border-b-0">
        <div className="flex h-14 items-center gap-2.5 px-5">
          <ShieldHalf className="size-5 text-primary" aria-hidden="true" />
          <span className="font-semibold tracking-tight">SentinelX</span>
        </div>
        <nav aria-label="Primary" className="flex gap-1 overflow-x-auto px-3 pb-3 md:flex-1 md:flex-col md:overflow-visible">
          {items.map(({ to, label, icon: Icon, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end ?? false}
              className={({ isActive }) =>
                cn(
                  "flex shrink-0 items-center gap-2.5 rounded-md px-3 py-2 text-sm text-muted-foreground transition-colors hover:bg-surface-raised hover:text-foreground",
                  isActive && "bg-surface-raised text-foreground",
                )
              }
            >
              <Icon className="size-4" aria-hidden="true" />
              {label}
            </NavLink>
          ))}
        </nav>
        {user ? (
          <div className="hidden border-t border-border p-3 md:block">
            <div className="px-2 pb-2">
              <p className="truncate text-sm font-medium">{user.full_name}</p>
              <p className="truncate text-xs text-muted-foreground">
                {user.email} · {ROLE_LABELS[user.role]}
              </p>
            </div>
            <Button
              variant="ghost"
              size="sm"
              className="w-full justify-start"
              onClick={() => {
                void logout();
              }}
            >
              <LogOut aria-hidden="true" />
              Sign out
            </Button>
          </div>
        ) : null}
      </aside>
      <main className="min-w-0 flex-1 px-4 py-6 sm:px-8">
        {user ? (
          <div className="mb-4 flex justify-end md:hidden">
            <Button
              variant="ghost"
              size="sm"
              onClick={() => {
                void logout();
              }}
            >
              <LogOut aria-hidden="true" />
              Sign out
            </Button>
          </div>
        ) : null}
        <div className="mx-auto max-w-6xl">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
