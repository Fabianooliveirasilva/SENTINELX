import { cva, type VariantProps } from "class-variance-authority";
import type { ComponentProps } from "react";

import { cn } from "@/lib/utils";

export const badgeVariants = cva(
  "inline-flex items-center gap-1.5 rounded-sm border px-2 py-0.5 font-mono text-[11px] font-medium uppercase tracking-wider",
  {
    variants: {
      tone: {
        neutral: "border-border bg-muted text-muted-foreground",
        ok: "border-status-ok/30 bg-status-ok/10 text-status-ok",
        degraded: "border-status-degraded/30 bg-status-degraded/10 text-status-degraded",
        down: "border-status-down/30 bg-status-down/10 text-status-down",
      },
    },
    defaultVariants: { tone: "neutral" },
  },
);

export interface BadgeProps extends ComponentProps<"span">, VariantProps<typeof badgeVariants> {}

export function Badge({ className, tone, ...props }: BadgeProps) {
  return <span className={cn(badgeVariants({ tone }), className)} {...props} />;
}
