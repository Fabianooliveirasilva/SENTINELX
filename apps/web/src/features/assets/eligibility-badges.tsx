import { Badge } from "@/components/ui/badge";

import type { Asset } from "./api";

export function EligibilityBadges({ eligibility }: { eligibility: Asset["eligibility"] }) {
  const items = [
    ["passive", eligibility.passive],
    ["active", eligibility.active],
    ["intrusive", eligibility.intrusive],
  ] as const;
  return (
    <ul className="flex flex-wrap gap-1" aria-label="Testing eligibility">
      {items.map(([name, allowed]) => (
        <li key={name}>
          <Badge tone={allowed ? "ok" : "neutral"} title={allowed ? `${name} testing allowed` : `${name} testing not allowed`}>
            {allowed ? "✓" : "✕"} {name}
          </Badge>
        </li>
      ))}
    </ul>
  );
}
