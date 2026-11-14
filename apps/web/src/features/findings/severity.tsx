import { cn } from "@/lib/utils";

import type { Severity } from "./api";

const CLASSES: Record<Severity, string> = {
  critical: "border-severity-critical/40 bg-severity-critical/15 text-severity-critical",
  high: "border-severity-high/40 bg-severity-high/15 text-severity-high",
  medium: "border-severity-medium/40 bg-severity-medium/15 text-severity-medium",
  low: "border-severity-low/40 bg-severity-low/15 text-severity-low",
  info: "border-severity-info/40 bg-severity-info/15 text-severity-info",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-sm border px-2 py-0.5 font-mono text-[11px] font-medium tracking-wider uppercase",
        CLASSES[severity],
      )}
    >
      {severity}
    </span>
  );
}
