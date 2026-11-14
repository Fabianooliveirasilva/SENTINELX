import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { Link, useParams } from "react-router";

import { ErrorAlert, InlineAlert } from "@/components/shared/inline-alert";
import { PageHeader } from "@/components/shared/page-header";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { useCan } from "@/features/auth/use-auth";
import { ProjectTabs } from "@/features/projects/project-tabs";
import { formatDateTime } from "@/lib/format";

import { cancelScan, getScan, isActive, POLL_INTERVAL_MS, scansKeys, type ScanDetail } from "./api";
import { AttentionBadge, ScanStatusBadge } from "./scan-status";

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <dt className="text-xs text-muted-foreground uppercase">{label}</dt>
      <dd className="mt-0.5 text-sm break-words">{children}</dd>
    </div>
  );
}

function Overview({ scan }: { scan: ScanDetail }) {
  return (
    <Card>
      <CardContent className="pt-5">
        <dl className="grid gap-4 sm:grid-cols-3">
          <Field label="Status">
            <ScanStatusBadge status={scan.status} />
          </Field>
          <Field label="Scanner">
            {scan.scanner} · {scan.profile} ({scan.technique})
          </Field>
          <Field label="Target">
            <span className="font-mono">{scan.target}</span>
          </Field>
          <Field label="Requested">{formatDateTime(scan.created_at)}</Field>
          <Field label="Started">{formatDateTime(scan.started_at)}</Field>
          <Field label="Finished">{formatDateTime(scan.finished_at)}</Field>
          <Field label="Pinned addresses">
            <span className="font-mono">{scan.pinned_addresses.length ? scan.pinned_addresses.join(", ") : "—"}</span>
          </Field>
          <Field label="Tool versions">
            <span className="font-mono text-xs">
              {Object.entries(scan.tool_versions)
                .map(([k, v]) => `${k} ${v}`)
                .join(" · ") || "—"}
            </span>
          </Field>
          <Field label="Correlation ID">
            <span className="font-mono text-xs">{scan.correlation_id ?? "—"}</span>
          </Field>
        </dl>
        {scan.error_message ? (
          <div className="mt-4">
            <InlineAlert>
              {scan.error_message} <span className="font-mono text-[11px] opacity-80">({scan.error_code})</span>
            </InlineAlert>
          </div>
        ) : null}
      </CardContent>
    </Card>
  );
}

function ScopeDecisionCard({ scan }: { scan: ScanDetail }) {
  const decision = scan.scope_decision;
  if (!decision) return null;
  return (
    <Card>
      <CardHeader>
        <CardTitle>Execution-time scope decision</CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        <Badge tone={decision.allowed ? "ok" : "down"}>{decision.allowed ? "allowed" : "denied"}</Badge>
        {decision.reasons.length > 0 ? (
          <ul className="list-disc pl-5 text-sm">
            {decision.reasons.map((r) => (
              <li key={r.code}>{r.message}</li>
            ))}
          </ul>
        ) : null}
        {decision.addresses.length > 0 ? (
          <Table aria-label="Resolved addresses">
            <THead>
              <tr>
                <TH>Address</TH>
                <TH>Verdict</TH>
              </tr>
            </THead>
            <TBody>
              {decision.addresses.map((a) => (
                <TR key={a.address}>
                  <TD className="font-mono text-sm">{a.address}</TD>
                  <TD className="text-sm">{a.allowed ? "authorized" : (a.reason ?? "blocked")}</TD>
                </TR>
              ))}
            </TBody>
          </Table>
        ) : null}
      </CardContent>
    </Card>
  );
}

function Results({ scan }: { scan: ScanDetail }) {
  if (scan.status !== "completed") return null;
  return (
    <Card>
      <CardHeader>
        <CardTitle>Observations ({scan.results.length})</CardTitle>
      </CardHeader>
      <CardContent>
        {scan.results.length === 0 ? (
          <p className="text-sm text-muted-foreground">The scan completed without observations.</p>
        ) : (
          <Table aria-label="Observations">
            <THead>
              <tr>
                <TH>Kind</TH>
                <TH>Key</TH>
                <TH>Attention</TH>
                <TH>Data</TH>
              </tr>
            </THead>
            <TBody>
              {scan.results.map((r) => (
                <TR key={r.id}>
                  <TD className="text-sm">{r.kind}</TD>
                  <TD className="font-mono text-sm break-all">{r.key}</TD>
                  <TD>
                    <div className="flex flex-wrap gap-1">
                      {r.attention.map((flag) => (
                        <AttentionBadge key={flag} flag={flag} />
                      ))}
                    </div>
                  </TD>
                  <TD>
                    <details>
                      <summary className="cursor-pointer text-xs text-muted-foreground">details</summary>
                      {/* Untrusted scanner output: rendered as text only. */}
                      <pre className="mt-2 max-h-64 max-w-md overflow-auto text-xs whitespace-pre-wrap">
                        {JSON.stringify(r.data, null, 2)}
                      </pre>
                    </details>
                  </TD>
                </TR>
              ))}
            </TBody>
          </Table>
        )}
      </CardContent>
    </Card>
  );
}

function EvidenceList({ scan }: { scan: ScanDetail }) {
  if (scan.evidence.length === 0) return null;
  return (
    <Card>
      <CardHeader>
        <CardTitle>Evidence</CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        {scan.evidence.map((e) => (
          <details key={e.id} className="rounded-md border border-border p-3">
            <summary className="cursor-pointer text-sm">{e.label}</summary>
            {/* Untrusted scanner output: rendered as text only. */}
            <pre className="mt-2 max-h-96 overflow-auto text-xs whitespace-pre-wrap">{e.content}</pre>
          </details>
        ))}
      </CardContent>
    </Card>
  );
}

export function ScanDetailPage() {
  const { projectId = "", scanId = "" } = useParams();
  const canExecute = useCan("scans:execute");
  const queryClient = useQueryClient();
  const scan = useQuery({
    queryKey: scansKeys.detail(projectId, scanId),
    queryFn: () => getScan(projectId, scanId),
    refetchInterval: (query) => (query.state.data && isActive(query.state.data.status) ? POLL_INTERVAL_MS : false),
  });
  const cancel = useMutation({
    mutationFn: () => cancelScan(projectId, scanId),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: scansKeys.all(projectId) }),
  });

  return (
    <div className="space-y-6">
      <PageHeader
        title="Scan details"
        description="Scope decision, normalized observations and bounded raw evidence."
        actions={
          canExecute && scan.data && isActive(scan.data.status) ? (
            <Button
              size="sm"
              variant="outline"
              disabled={cancel.isPending}
              onClick={() => {
                cancel.mutate();
              }}
            >
              Cancel scan
            </Button>
          ) : null
        }
      />
      <ProjectTabs projectId={projectId} />
      <Link to={`/projects/${projectId}/scans`} className="text-sm text-primary hover:underline">
        ← All scans
      </Link>
      {cancel.isError ? <ErrorAlert error={cancel.error} /> : null}
      {scan.isPending ? (
        <div role="status" aria-label="Loading scan" className="space-y-2">
          <Skeleton className="h-24 w-full" />
        </div>
      ) : scan.isError ? (
        <ErrorAlert error={scan.error} />
      ) : (
        <>
          <Overview scan={scan.data} />
          <ScopeDecisionCard scan={scan.data} />
          <Results scan={scan.data} />
          <EvidenceList scan={scan.data} />
        </>
      )}
    </div>
  );
}
