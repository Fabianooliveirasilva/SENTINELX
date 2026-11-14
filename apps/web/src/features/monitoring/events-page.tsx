import { useQuery } from "@tanstack/react-query";
import { Activity } from "lucide-react";
import { useState } from "react";
import { Link, useParams } from "react-router";

import { EmptyState } from "@/components/shared/empty-state";
import { ErrorAlert } from "@/components/shared/inline-alert";
import { PageHeader } from "@/components/shared/page-header";
import { Pagination } from "@/components/shared/pagination";
import { Card, CardContent } from "@/components/ui/card";
import { Select } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { SEVERITIES, type Severity } from "@/features/findings/api";
import { SeverityBadge } from "@/features/findings/severity";
import { ProjectTabs } from "@/features/projects/project-tabs";
import { formatDateTime } from "@/lib/format";

import {
  eventLabel,
  eventSummary,
  listEvents,
  listEventTypes,
  monitoringKeys,
  type EventFilters,
  type SecurityEvent,
} from "./api";

const PERIODS = [
  { days: 1, label: "Last 24 hours" },
  { days: 7, label: "Last 7 days" },
  { days: 30, label: "Last 30 days" },
  { days: 0, label: "All time" },
] as const;

const REFRESH_MS = 30_000;
// Detail keys worth showing inline; everything else stays in the API payload.
const DETAIL_KEYS = ["reason", "error_message", "from", "to", "location", "cve_id", "target"] as const;

function EventLinks({ projectId, event }: { projectId: string; event: SecurityEvent }) {
  const links: { to: string; label: string }[] = [];
  if (event.finding_id) links.push({ to: `/projects/${projectId}/findings/${event.finding_id}`, label: "Finding" });
  if (event.scan_job_id) links.push({ to: `/projects/${projectId}/scans/${event.scan_job_id}`, label: "Scan" });
  if (event.asset_id) links.push({ to: `/projects/${projectId}/assets/${event.asset_id}`, label: "Asset" });
  if (links.length === 0) return null;
  return (
    <span className="flex gap-3 text-xs">
      {links.map((link) => (
        <Link key={link.label} to={link.to} className="text-primary hover:underline">
          {link.label}
        </Link>
      ))}
    </span>
  );
}

function EventDetails({ event }: { event: SecurityEvent }) {
  const shown = DETAIL_KEYS.flatMap((key) => {
    const value = event.details[key];
    return typeof value === "string" && value !== "" ? [[key, value] as const] : [];
  });
  if (shown.length === 0) return null;
  return (
    <dl className="mt-1 flex flex-wrap gap-x-4 gap-y-0.5 text-xs text-muted-foreground">
      {shown.map(([key, value]) => (
        <div key={key} className="flex gap-1">
          <dt className="capitalize">{key.replace("_", " ")}:</dt>
          {/* Scanner-derived text: rendered as plain text only. */}
          <dd className="max-w-md truncate font-mono" title={value}>
            {value}
          </dd>
        </div>
      ))}
    </dl>
  );
}

function SummaryTiles({ projectId }: { projectId: string }) {
  const summary = useQuery({ queryKey: monitoringKeys.summary(projectId), queryFn: () => eventSummary(projectId) });
  if (!summary.data) return null;
  return (
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-5" aria-label="Events in the last 7 days by severity">
      {SEVERITIES.map((severity) => (
        <Card key={severity}>
          <CardContent className="flex items-center justify-between py-3">
            <SeverityBadge severity={severity} />
            <span className="font-mono text-lg tabular-nums">{summary.data.by_severity[severity] ?? 0}</span>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

export function EventsPage() {
  const { projectId = "" } = useParams();
  const [filters, setFilters] = useState<EventFilters>({
    page: 1,
    eventType: "",
    minSeverity: "",
    assetId: "",
    days: 7,
  });
  const types = useQuery({ queryKey: monitoringKeys.types, queryFn: listEventTypes, staleTime: Infinity });
  const events = useQuery({
    queryKey: monitoringKeys.events(projectId, filters),
    queryFn: () => listEvents(projectId, filters),
    refetchInterval: REFRESH_MS,
  });
  const update = (patch: Partial<EventFilters>) => {
    setFilters({ ...filters, ...patch, page: 1 });
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Security events"
        description="Timeline of findings, risk changes, scans, scope decisions and configuration changes in this project."
      />
      <ProjectTabs projectId={projectId} />
      <SummaryTiles projectId={projectId} />
      <Card>
        <CardContent className="pt-5">
          <div className="mb-4 flex flex-col gap-2 sm:flex-row sm:justify-end">
            <Select
              aria-label="Filter by event type"
              className="sm:w-56"
              value={filters.eventType}
              onChange={(e) => {
                update({ eventType: e.target.value });
              }}
            >
              <option value="">All event types</option>
              {(types.data ?? []).map((t) => (
                <option key={t.type} value={t.type}>
                  {eventLabel(t.type)}
                </option>
              ))}
            </Select>
            <Select
              aria-label="Minimum severity"
              className="sm:w-40"
              value={filters.minSeverity}
              onChange={(e) => {
                update({ minSeverity: e.target.value as Severity | "" });
              }}
            >
              <option value="">Any severity</option>
              {SEVERITIES.filter((s) => s !== "info").map((s) => (
                <option key={s} value={s}>
                  {s} and above
                </option>
              ))}
            </Select>
            <Select
              aria-label="Period"
              className="sm:w-40"
              value={String(filters.days)}
              onChange={(e) => {
                update({ days: Number(e.target.value) });
              }}
            >
              {PERIODS.map((p) => (
                <option key={p.days} value={p.days}>
                  {p.label}
                </option>
              ))}
            </Select>
          </div>
          {events.isPending ? (
            <div role="status" aria-label="Loading events" className="space-y-2">
              <Skeleton className="h-14 w-full" />
              <Skeleton className="h-14 w-full" />
            </div>
          ) : events.isError ? (
            <ErrorAlert error={events.error} />
          ) : events.data.items.length === 0 ? (
            <EmptyState icon={Activity} title="No events match these filters">
              Events are recorded as scans run, findings change and assets are updated.
            </EmptyState>
          ) : (
            <>
              <ol aria-label="Security events" className="divide-y divide-border">
                {events.data.items.map((event) => (
                  <li key={event.id} className="flex flex-col gap-1 py-3 sm:flex-row sm:items-start sm:gap-4">
                    <time
                      dateTime={event.occurred_at}
                      className="w-40 shrink-0 font-mono text-xs text-muted-foreground tabular-nums"
                    >
                      {formatDateTime(event.occurred_at)}
                    </time>
                    <div className="w-20 shrink-0">
                      <SeverityBadge severity={event.severity} />
                    </div>
                    <div className="min-w-0 flex-1">
                      <p className="text-xs tracking-wide text-muted-foreground uppercase">{eventLabel(event.event_type)}</p>
                      <p className="text-sm break-words">{event.title}</p>
                      <EventDetails event={event} />
                      <div className="mt-1 flex flex-wrap items-center gap-3">
                        <EventLinks projectId={projectId} event={event} />
                        {event.actor_email ? (
                          <span className="text-xs text-muted-foreground">by {event.actor_email}</span>
                        ) : null}
                      </div>
                    </div>
                  </li>
                ))}
              </ol>
              <Pagination
                page={filters.page}
                pageSize={events.data.page_size}
                total={events.data.total}
                onPageChange={(page) => {
                  setFilters({ ...filters, page });
                }}
              />
            </>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
