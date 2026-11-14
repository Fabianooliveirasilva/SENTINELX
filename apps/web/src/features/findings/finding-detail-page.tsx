import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type ReactNode } from "react";
import { Link, useParams } from "react-router";

import { FormField } from "@/components/shared/form-field";
import { ErrorAlert } from "@/components/shared/inline-alert";
import { PageHeader } from "@/components/shared/page-header";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, DialogTrigger } from "@/components/ui/dialog";
import { Select, Textarea } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { useCan } from "@/features/auth/use-auth";
import { ProjectTabs } from "@/features/projects/project-tabs";
import { formatDateTime } from "@/lib/format";

import {
  changeFindingStatus,
  FINDING_STATUSES,
  findingsKeys,
  getFinding,
  REASON_REQUIRED,
  STATUS_LABELS,
  type FindingDetail,
  type FindingStatus,
} from "./api";
import { SeverityBadge } from "./severity";

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <dt className="text-xs text-muted-foreground uppercase">{label}</dt>
      <dd className="mt-0.5 text-sm break-words">{children}</dd>
    </div>
  );
}

function TriageDialog({ projectId, finding }: { projectId: string; finding: FindingDetail }) {
  const [open, setOpen] = useState(false);
  const firstOther = FINDING_STATUSES.find((s) => s !== finding.status) ?? "acknowledged";
  const [status, setStatus] = useState<FindingStatus>(firstOther);
  const [reason, setReason] = useState("");
  const queryClient = useQueryClient();
  const mutation = useMutation({
    mutationFn: () => changeFindingStatus(projectId, finding.id, status, reason),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: findingsKeys.all(projectId) });
      setOpen(false);
      setReason("");
    },
  });
  const needsReason = REASON_REQUIRED.includes(status);

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        setOpen(next);
        if (!next) mutation.reset();
      }}
    >
      <DialogTrigger asChild>
        <Button size="sm">Change status</Button>
      </DialogTrigger>
      <DialogContent title="Change finding status" description="Every change is kept in the finding history and the audit log.">
        <form
          noValidate
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault();
            mutation.mutate();
          }}
        >
          {mutation.isError ? <ErrorAlert error={mutation.error} /> : null}
          <FormField label="New status">
            <Select
              value={status}
              onChange={(e) => {
                setStatus(e.target.value as FindingStatus);
              }}
            >
              {FINDING_STATUSES.filter((s) => s !== finding.status).map((s) => (
                <option key={s} value={s}>
                  {STATUS_LABELS[s]}
                </option>
              ))}
            </Select>
          </FormField>
          <FormField label="Reason" hint={needsReason ? "Required for this status." : "Optional."}>
            <Textarea
              value={reason}
              maxLength={2000}
              onChange={(e) => {
                setReason(e.target.value);
              }}
            />
          </FormField>
          <div className="flex justify-end">
            <Button type="submit" disabled={mutation.isPending || (needsReason && reason.trim().length < 3)}>
              Save
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}

export function FindingDetailPage() {
  const { projectId = "", findingId = "" } = useParams();
  const canWrite = useCan("findings:write");
  const finding = useQuery({
    queryKey: findingsKeys.detail(projectId, findingId),
    queryFn: () => getFinding(projectId, findingId),
  });
  const f = finding.data;

  return (
    <div className="space-y-6">
      <PageHeader
        title={f?.title ?? "Finding"}
        description={f ? `${f.rule_id} · ruleset ${f.ruleset_version}` : ""}
        actions={canWrite && f ? <TriageDialog projectId={projectId} finding={f} /> : null}
      />
      <ProjectTabs projectId={projectId} />
      <Link to={`/projects/${projectId}/findings`} className="text-sm text-primary hover:underline">
        ← All findings
      </Link>
      {finding.isPending ? (
        <Skeleton className="h-24 w-full" />
      ) : finding.isError ? (
        <ErrorAlert error={finding.error} />
      ) : f ? (
        <>
          <Card>
            <CardContent className="pt-5">
              <dl className="grid gap-4 sm:grid-cols-3">
                <Field label="Severity">
                  <SeverityBadge severity={f.severity} />
                </Field>
                <Field label="Status">
                  {STATUS_LABELS[f.status]}
                  {f.status_reason ? <span className="block text-xs text-muted-foreground">{f.status_reason}</span> : null}
                </Field>
                <Field label="Confidence">{f.confidence}</Field>
                <Field label="Location">
                  <span className="font-mono">{f.location}</span>
                </Field>
                <Field label="Source">{f.source}</Field>
                <Field label="CWE">{f.cwe ? `CWE-${String(f.cwe)}` : "—"}</Field>
                <Field label="First seen">{formatDateTime(f.first_seen_at)}</Field>
                <Field label="Last seen">{formatDateTime(f.last_seen_at)}</Field>
                <Field label="Occurrences">{f.occurrence_count}</Field>
              </dl>
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>Description and remediation</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3 text-sm">
              {/* Text may come from third-party scanners: rendered as plain text. */}
              <p className="whitespace-pre-wrap">{f.description || "—"}</p>
              <p className="font-medium">Remediation</p>
              <p className="whitespace-pre-wrap">{f.remediation || "—"}</p>
              {f.references.length > 0 ? (
                <ul aria-label="References" className="list-disc pl-5">
                  {f.references.map((r) => (
                    <li key={r} className="font-mono text-xs break-all">
                      {r}
                    </li>
                  ))}
                </ul>
              ) : null}
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>Evidence (latest occurrences)</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              {f.occurrences.map((o) => (
                <details key={o.id} className="rounded-md border border-border p-3">
                  <summary className="cursor-pointer text-sm">
                    {formatDateTime(o.observed_at)}
                    {o.scan_job_id ? (
                      <>
                        {" · "}
                        <Link to={`/projects/${projectId}/scans/${o.scan_job_id}`} className="text-primary hover:underline">
                          scan
                        </Link>
                      </>
                    ) : null}
                  </summary>
                  <pre className="mt-2 max-h-80 overflow-auto text-xs whitespace-pre-wrap">{JSON.stringify(o.observation, null, 2)}</pre>
                </details>
              ))}
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>History</CardTitle>
            </CardHeader>
            <CardContent>
              <ol aria-label="Status history" className="space-y-2 text-sm">
                {f.history.map((h) => (
                  <li key={h.id}>
                    <span className="text-muted-foreground">{formatDateTime(h.created_at)}</span> —{" "}
                    {h.from_status ? `${STATUS_LABELS[h.from_status]} → ` : ""}
                    {STATUS_LABELS[h.to_status]} by {h.changed_by_email ?? "SentinelX"}
                    {h.reason ? <span className="block text-xs text-muted-foreground">{h.reason}</span> : null}
                  </li>
                ))}
              </ol>
            </CardContent>
          </Card>
        </>
      ) : null}
    </div>
  );
}
