import { SEVERITIES, type Severity } from "@/features/findings/api";

/** Map an NVD severity string onto the shared severity scale ("none" → info). */
export function asSeverity(value: string | null): Severity {
  const lowered = (value ?? "").toLowerCase();
  return (SEVERITIES as readonly string[]).includes(lowered) ? (lowered as Severity) : "info";
}
