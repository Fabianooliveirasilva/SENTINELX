import { ShieldHalf } from "lucide-react";
import type { ReactNode } from "react";

export function AuthLayout({ title, subtitle, children }: { title: string; subtitle?: string; children: ReactNode }) {
  return (
    <main className="flex min-h-dvh items-center justify-center px-4 py-10">
      <div className="w-full max-w-sm space-y-6">
        <div className="flex items-center gap-2.5">
          <ShieldHalf className="size-6 text-primary" aria-hidden="true" />
          <span className="text-lg font-semibold tracking-tight">SentinelX</span>
        </div>
        <div className="space-y-1">
          <h1 className="text-xl font-semibold tracking-tight">{title}</h1>
          {subtitle ? <p className="text-sm text-muted-foreground">{subtitle}</p> : null}
        </div>
        <div className="rounded-lg border border-border bg-surface p-6">{children}</div>
        <p className="text-center text-xs text-muted-foreground">
          Authorized use only. Activity is recorded in the security audit log.
        </p>
      </div>
    </main>
  );
}
