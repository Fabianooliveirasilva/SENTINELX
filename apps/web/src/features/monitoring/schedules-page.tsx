import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CalendarClock, Plus } from "lucide-react";
import { useState } from "react";
import { Link, useParams } from "react-router";

import { EmptyState } from "@/components/shared/empty-state";
import { FormField } from "@/components/shared/form-field";
import { ErrorAlert, InlineAlert } from "@/components/shared/inline-alert";
import { PageHeader } from "@/components/shared/page-header";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Dialog, DialogContent, DialogTrigger } from "@/components/ui/dialog";
import { Select } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { listAssets, type Asset } from "@/features/assets/api";
import { useCan } from "@/features/auth/use-auth";
import { ProjectTabs } from "@/features/projects/project-tabs";
import { listScanners, scansKeys, type ScannerInfo } from "@/features/scans/api";
import { formatDateTime } from "@/lib/format";

import { createSchedule, deleteSchedule, listSchedules, monitoringKeys, updateSchedule, type Schedule } from "./api";

const INTERVALS = [
  { hours: 6, label: "Every 6 hours" },
  { hours: 12, label: "Every 12 hours" },
  { hours: 24, label: "Daily" },
  { hours: 72, label: "Every 3 days" },
  { hours: 168, label: "Weekly" },
  { hours: 720, label: "Every 30 days" },
] as const;

function intervalLabel(hours: number): string {
  return INTERVALS.find((i) => i.hours === hours)?.label ?? `Every ${hours} h`;
}

function eligible(asset: Asset, scanner: ScannerInfo): boolean {
  return asset.eligibility[scanner.technique] && scanner.supported_asset_types.includes(asset.type);
}

function useProjectAssets(projectId: string, enabled = true) {
  return useQuery({
    queryKey: ["assets", projectId, "scan-targets"],
    queryFn: () => listAssets(projectId, { page: 1, type: "", status: "active", search: "" }),
    enabled,
  });
}

function NewScheduleDialog({ projectId }: { projectId: string }) {
  const [open, setOpen] = useState(false);
  const [assetId, setAssetId] = useState("");
  const [scannerName, setScannerName] = useState("");
  const [profile, setProfile] = useState("");
  const [interval, setInterval] = useState(24);
  const [startNow, setStartNow] = useState(true);
  const queryClient = useQueryClient();
  const scanners = useQuery({ queryKey: scansKeys.scanners, queryFn: listScanners, enabled: open, staleTime: Infinity });
  const assets = useProjectAssets(projectId, open);
  const asset = assets.data?.items.find((a) => a.id === assetId);
  const available = (scanners.data ?? []).filter((s) => (asset ? eligible(asset, s) : false));
  const scanner = available.find((s) => s.name === scannerName);
  const profiles = scanner && asset ? scanner.profiles.filter((p) => asset.eligibility[p.technique]) : [];
  const mutation = useMutation({
    mutationFn: () =>
      createSchedule(projectId, {
        asset_id: assetId,
        scanner: scannerName,
        profile,
        interval_hours: interval,
        ...(startNow ? {} : { first_run_at: new Date(Date.now() + interval * 3_600_000).toISOString() }),
      }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: monitoringKeys.schedules(projectId) });
      setOpen(false);
    },
  });

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        setOpen(next);
        if (!next) {
          setAssetId("");
          setScannerName("");
          setProfile("");
          mutation.reset();
        }
      }}
    >
      <DialogTrigger asChild>
        <Button size="sm">
          <Plus aria-hidden="true" />
          New schedule
        </Button>
      </DialogTrigger>
      <DialogContent
        title="Schedule a recurring scan"
        description="Runs with your authority. Every run re-checks your project access, the asset's authorization window, quotas and the emergency stop; a run that is not allowed is skipped and recorded."
      >
        <form
          noValidate
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault();
            mutation.mutate();
          }}
        >
          {mutation.isError ? <ErrorAlert error={mutation.error} /> : null}
          {assets.isError ? <ErrorAlert error={assets.error} /> : null}
          <FormField label="Asset">
            <Select
              value={assetId}
              onChange={(e) => {
                setAssetId(e.target.value);
                setScannerName("");
                setProfile("");
              }}
            >
              <option value="">Select an asset…</option>
              {(assets.data?.items ?? [])
                .filter((a) => a.eligibility.passive)
                .map((a) => (
                  <option key={a.id} value={a.id}>
                    {a.value}
                  </option>
                ))}
            </Select>
          </FormField>
          {asset && available.length === 0 ? (
            <InlineAlert>No scanner is permitted for this asset under its current authorizations.</InlineAlert>
          ) : null}
          <FormField label="Scanner" hint={scanner?.description}>
            <Select
              value={scannerName}
              disabled={!asset}
              onChange={(e) => {
                const next = available.find((s) => s.name === e.target.value);
                setScannerName(e.target.value);
                setProfile(next?.default_profile ?? "");
              }}
            >
              <option value="">Select a scanner…</option>
              {available.map((s) => (
                <option key={s.name} value={s.name}>
                  {s.name} ({s.technique})
                </option>
              ))}
            </Select>
          </FormField>
          <div className="grid gap-4 sm:grid-cols-2">
            <FormField label="Profile">
              <Select
                value={profile}
                disabled={!scanner}
                onChange={(e) => {
                  setProfile(e.target.value);
                }}
              >
                {profiles.map((p) => (
                  <option key={p.name} value={p.name}>
                    {p.name}
                  </option>
                ))}
              </Select>
            </FormField>
            <FormField label="Frequency">
              <Select
                value={String(interval)}
                onChange={(e) => {
                  setInterval(Number(e.target.value));
                }}
              >
                {INTERVALS.map((i) => (
                  <option key={i.hours} value={i.hours}>
                    {i.label}
                  </option>
                ))}
              </Select>
            </FormField>
          </div>
          <FormField label="First run">
            <Select
              value={startNow ? "now" : "later"}
              onChange={(e) => {
                setStartNow(e.target.value === "now");
              }}
            >
              <option value="now">As soon as possible</option>
              <option value="later">After one interval</option>
            </Select>
          </FormField>
          <div className="flex justify-end">
            <Button type="submit" disabled={!scanner || !profile || mutation.isPending}>
              {mutation.isPending ? "Saving…" : "Create schedule"}
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function LastRun({ projectId, schedule }: { projectId: string; schedule: Schedule }) {
  if (!schedule.last_run_at) return <span className="text-xs text-muted-foreground">Never</span>;
  return (
    <div className="space-y-0.5">
      <div className="flex items-center gap-2">
        <Badge tone={schedule.last_status === "started" ? "ok" : "degraded"}>{schedule.last_status ?? "—"}</Badge>
        {schedule.last_scan_job_id && schedule.last_status === "started" ? (
          <Link to={`/projects/${projectId}/scans/${schedule.last_scan_job_id}`} className="text-xs text-primary hover:underline">
            View scan
          </Link>
        ) : null}
      </div>
      <p className="text-xs text-muted-foreground">{formatDateTime(schedule.last_run_at)}</p>
      {schedule.last_message ? <p className="max-w-xs text-xs text-status-degraded">{schedule.last_message}</p> : null}
    </div>
  );
}

export function SchedulesPage() {
  const { projectId = "" } = useParams();
  const canExecute = useCan("scans:execute");
  const queryClient = useQueryClient();
  const schedules = useQuery({ queryKey: monitoringKeys.schedules(projectId), queryFn: () => listSchedules(projectId) });
  const assets = useProjectAssets(projectId);
  const assetName = (id: string) => assets.data?.items.find((a) => a.id === id)?.value ?? id;
  const invalidate = () => queryClient.invalidateQueries({ queryKey: monitoringKeys.schedules(projectId) });
  const toggle = useMutation({
    mutationFn: (s: Schedule) => updateSchedule(projectId, s.id, { enabled: !s.enabled }),
    onSuccess: invalidate,
  });
  const remove = useMutation({ mutationFn: (id: string) => deleteSchedule(projectId, id), onSuccess: invalidate });

  return (
    <div className="space-y-6">
      <PageHeader
        title="Scan schedules"
        description="Recurring scans of authorized assets. Results feed findings, risk and the event timeline like any other scan."
        actions={canExecute ? <NewScheduleDialog projectId={projectId} /> : null}
      />
      <ProjectTabs projectId={projectId} />
      <Card>
        <CardContent className="space-y-3 pt-5">
          {toggle.isError ? <ErrorAlert error={toggle.error} /> : null}
          {remove.isError ? <ErrorAlert error={remove.error} /> : null}
          {schedules.isPending ? (
            <div role="status" aria-label="Loading schedules" className="space-y-2">
              <Skeleton className="h-10 w-full" />
            </div>
          ) : schedules.isError ? (
            <ErrorAlert error={schedules.error} />
          ) : schedules.data.items.length === 0 ? (
            <EmptyState icon={CalendarClock} title="No scheduled scans">
              {canExecute ? "Schedule a recurring scan on an asset with a current authorization." : null}
            </EmptyState>
          ) : (
            <Table aria-label="Scan schedules">
              <THead>
                <tr>
                  <TH>Asset</TH>
                  <TH>Scanner</TH>
                  <TH>Frequency</TH>
                  <TH>Next run</TH>
                  <TH>Last run</TH>
                  <TH>State</TH>
                  {canExecute ? <TH className="text-right">Actions</TH> : null}
                </tr>
              </THead>
              <TBody>
                {schedules.data.items.map((s) => (
                  <TR key={s.id}>
                    <TD className="font-mono text-sm">{assetName(s.asset_id)}</TD>
                    <TD className="text-sm">
                      {s.scanner} <span className="text-muted-foreground">· {s.profile}</span>
                    </TD>
                    <TD className="text-sm">{intervalLabel(s.interval_hours)}</TD>
                    <TD className="text-xs text-muted-foreground">{s.enabled ? formatDateTime(s.next_run_at) : "—"}</TD>
                    <TD>
                      <LastRun projectId={projectId} schedule={s} />
                    </TD>
                    <TD>
                      <Badge tone={s.enabled ? "ok" : "neutral"}>{s.enabled ? "active" : "paused"}</Badge>
                    </TD>
                    {canExecute ? (
                      <TD>
                        <div className="flex justify-end gap-1">
                          <Button size="sm" variant="ghost" onClick={() => { toggle.mutate(s); }}>
                            {s.enabled ? "Pause" : "Resume"}
                          </Button>
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => {
                              if (window.confirm("Delete this schedule? Past scans are kept.")) remove.mutate(s.id);
                            }}
                          >
                            Delete
                          </Button>
                        </div>
                      </TD>
                    ) : null}
                  </TR>
                ))}
              </TBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
