import { Badge } from "@/components/ui/badge";

import type { ScanStatus } from "./api";

const TONES = {
  pending: "neutral",
  queued: "neutral",
  running: "degraded",
  completed: "ok",
  failed: "down",
  cancelled: "neutral",
} as const satisfies Record<ScanStatus, "neutral" | "ok" | "degraded" | "down">;

export function ScanStatusBadge({ status }: { status: ScanStatus }) {
  return <Badge tone={TONES[status]}>{status}</Badge>;
}

/** Human label for a machine attention flag, e.g. "missing_hsts" → "missing hsts". */
export function AttentionBadge({ flag }: { flag: string }) {
  return <Badge tone="degraded">{flag.replaceAll("_", " ")}</Badge>;
}
