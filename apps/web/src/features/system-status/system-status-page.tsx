import { AlertTriangle, Database, RefreshCw, Server, type LucideIcon } from "lucide-react";

import { PageHeader } from "@/components/shared/page-header";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { ApiError } from "@/lib/api-client";

import { useReadiness } from "./api";
import type { ComponentHealth } from "./schemas";

const COMPONENT_META: Record<string, { label: string; icon: LucideIcon }> = {
  database: { label: "PostgreSQL", icon: Database },
  redis: { label: "Redis", icon: Server },
};

function ComponentRow({ name, health }: { name: string; health: ComponentHealth }) {
  const meta = COMPONENT_META[name] ?? { label: name, icon: Server };
  const Icon = meta.icon;
  const ok = health.status === "ok";
  return (
    <li className="flex items-center justify-between gap-4 py-3">
      <div className="flex items-center gap-3">
        <Icon className="size-4 text-muted-foreground" aria-hidden="true" />
        <span className="text-sm font-medium">{meta.label}</span>
      </div>
      <div className="flex items-center gap-3">
        <span className="font-mono text-xs text-muted-foreground">
          {ok && health.latency_ms !== null ? `${health.latency_ms.toFixed(1)} ms` : health.error}
        </span>
        <Badge tone={ok ? "ok" : "down"}>{ok ? "Operational" : "Unavailable"}</Badge>
      </div>
    </li>
  );
}

function LoadingState() {
  return (
    <div role="status" aria-label="Loading system status" className="space-y-3">
      <Skeleton className="h-6 w-40" />
      <Skeleton className="h-12 w-full" />
      <Skeleton className="h-12 w-full" />
    </div>
  );
}

function ErrorState({ error, onRetry }: { error: Error; onRetry: () => void }) {
  const requestId = error instanceof ApiError ? error.requestId : null;
  return (
    <div role="alert" className="flex flex-col items-start gap-3">
      <div className="flex items-center gap-2 text-status-down">
        <AlertTriangle className="size-4" aria-hidden="true" />
        <span className="text-sm font-medium">Unable to retrieve system status</span>
      </div>
      <p className="text-sm text-muted-foreground">{error.message}</p>
      {requestId ? (
        <p className="font-mono text-xs text-muted-foreground">Request ID: {requestId}</p>
      ) : null}
      <Button variant="outline" size="sm" onClick={onRetry}>
        <RefreshCw aria-hidden="true" />
        Retry
      </Button>
    </div>
  );
}

export function SystemStatusPage() {
  const { data, error, isPending, isFetching, refetch } = useReadiness();
  const retry = () => void refetch();

  return (
    <div className="space-y-6">
      <PageHeader
        title="System Status"
        description="Live readiness of the SentinelX platform and its infrastructure dependencies."
        actions={
          <Button variant="ghost" size="sm" onClick={retry} disabled={isFetching}>
            <RefreshCw className={isFetching ? "animate-spin" : undefined} aria-hidden="true" />
            Refresh
          </Button>
        }
      />

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between gap-4">
            <CardTitle>Platform readiness</CardTitle>
            {data ? (
              <Badge tone={data.status === "ok" ? "ok" : "degraded"} data-testid="overall-status">
                {data.status === "ok" ? "Operational" : "Degraded"}
              </Badge>
            ) : null}
          </div>
          {data ? <CardDescription>API version {data.version}</CardDescription> : null}
        </CardHeader>
        <CardContent>
          {isPending ? (
            <LoadingState />
          ) : error ? (
            <ErrorState error={error} onRetry={retry} />
          ) : Object.keys(data.components).length === 0 ? (
            <p className="text-sm text-muted-foreground">No components reported.</p>
          ) : (
            <ul className="divide-y divide-border" aria-label="Infrastructure components">
              {Object.entries(data.components).map(([name, health]) => (
                <ComponentRow key={name} name={name} health={health} />
              ))}
            </ul>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
