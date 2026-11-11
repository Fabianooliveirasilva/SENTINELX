import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Archive, ArchiveRestore, ArrowLeft, History } from "lucide-react";
import { Link, useParams } from "react-router";

import { EmptyState } from "@/components/shared/empty-state";
import { ErrorAlert, InlineAlert } from "@/components/shared/inline-alert";
import { PageHeader } from "@/components/shared/page-header";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Select } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { useCan, useSession } from "@/features/auth/use-auth";
import { ProjectTabs } from "@/features/projects/project-tabs";
import { ApiError } from "@/lib/api-client";
import { formatDateTime } from "@/lib/format";

import {
  ASSET_TYPE_LABELS,
  assetHistory,
  assetsKeys,
  CRITICALITIES,
  EXPOSURES,
  getAsset,
  updateAsset,
  type AssetDetail,
  type Authorization,
} from "./api";
import { AddAuthorizationDialog, RevokeAuthorizationDialog } from "./authorization-dialogs";
import { EligibilityBadges } from "./eligibility-badges";

const STATUS_TONE: Record<Authorization["status"], "ok" | "degraded" | "neutral" | "down"> = {
  active: "ok",
  scheduled: "degraded",
  expired: "neutral",
  revoked: "down",
};

function techniques(auth: Authorization): string {
  return ["passive", auth.allow_active ? "active" : null, auth.allow_intrusive ? "intrusive" : null].filter(Boolean).join(", ");
}

function AuthorizationsCard({ asset, canWrite, isAdmin }: { asset: AssetDetail; canWrite: boolean; isAdmin: boolean }) {
  return (
    <Card>
      <CardHeader>
        <div className="flex items-start justify-between gap-4">
          <div className="space-y-1">
            <CardTitle>Authorizations</CardTitle>
            <CardDescription>Testing is permitted only inside an active authorization window.</CardDescription>
          </div>
          {canWrite && asset.status === "active" ? <AddAuthorizationDialog asset={asset} isAdmin={isAdmin} /> : null}
        </div>
      </CardHeader>
      <CardContent>
        {asset.authorizations.length === 0 ? (
          <EmptyState icon={History} title="No authorization recorded">
            This asset cannot be tested until its owner&apos;s permission is recorded.
          </EmptyState>
        ) : (
          <Table aria-label="Authorizations">
            <THead>
              <tr>
                <TH>Reference</TH>
                <TH>Window</TH>
                <TH>Techniques</TH>
                <TH>IP ranges</TH>
                <TH>
                  <span className="sr-only">Actions</span>
                </TH>
              </tr>
            </THead>
            <TBody>
              {asset.authorizations.map((auth) => (
                <TR key={auth.id}>
                  <TD>
                    <div className="flex items-center gap-2">
                      <span className="font-medium">{auth.reference}</span>
                      <Badge tone={STATUS_TONE[auth.status]}>{auth.status}</Badge>
                    </div>
                    <div className="text-xs text-muted-foreground">
                      {auth.authorized_by} · {auth.organization}
                    </div>
                    {auth.revocation_reason ? <div className="text-xs text-status-down">Revoked: {auth.revocation_reason}</div> : null}
                  </TD>
                  <TD className="text-xs text-muted-foreground">
                    {formatDateTime(auth.valid_from)}
                    <br />→ {formatDateTime(auth.valid_until)}
                  </TD>
                  <TD className="text-xs">
                    {techniques(auth)}
                    {auth.include_subdomains ? <div className="text-muted-foreground">+ subdomains</div> : null}
                  </TD>
                  <TD className="font-mono text-xs">{auth.ip_ranges.length ? auth.ip_ranges.join(", ") : "—"}</TD>
                  <TD className="text-right">
                    {canWrite && (auth.status === "active" || auth.status === "scheduled") ? (
                      <RevokeAuthorizationDialog asset={asset} authorization={auth} />
                    ) : null}
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

function HistoryCard({ asset }: { asset: AssetDetail }) {
  const history = useQuery({
    queryKey: assetsKeys.history(asset.project_id, asset.id),
    queryFn: () => assetHistory(asset.project_id, asset.id),
  });
  return (
    <Card>
      <CardHeader>
        <CardTitle>History</CardTitle>
        <CardDescription>From the append-only audit log.</CardDescription>
      </CardHeader>
      <CardContent>
        {history.isPending ? (
          <Skeleton className="h-16 w-full" />
        ) : history.isError ? (
          <ErrorAlert error={history.error} />
        ) : (
          <ol className="space-y-3 border-l border-border pl-4" aria-label="Asset history">
            {history.data.map((entry) => (
              <li key={entry.id} className="text-sm">
                <span className="font-mono text-xs">{entry.action}</span>
                <span className="text-muted-foreground"> · {entry.actor_email ?? "system"}</span>
                <div className="text-xs text-muted-foreground">{formatDateTime(entry.created_at)}</div>
              </li>
            ))}
          </ol>
        )}
      </CardContent>
    </Card>
  );
}

export function AssetDetailPage() {
  const { projectId = "", assetId = "" } = useParams();
  const canWrite = useCan("assets:write");
  const { user } = useSession();
  const queryClient = useQueryClient();
  const asset = useQuery({ queryKey: assetsKeys.detail(projectId, assetId), queryFn: () => getAsset(projectId, assetId) });
  const update = useMutation({
    mutationFn: (changes: Parameters<typeof updateAsset>[2]) => updateAsset(projectId, assetId, changes),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: assetsKeys.all(projectId) }),
  });

  const back = (
    <Link to={`/projects/${projectId}/assets`} className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
      <ArrowLeft className="size-4" aria-hidden="true" />
      Assets
    </Link>
  );

  if (asset.isPending) {
    return (
      <div role="status" aria-label="Loading asset" className="space-y-4">
        {back}
        <Skeleton className="h-8 w-72" />
        <Skeleton className="h-40 w-full" />
      </div>
    );
  }
  if (asset.isError) {
    const notFound = asset.error instanceof ApiError && asset.error.status === 404;
    return (
      <div className="space-y-4">
        {back}
        {notFound ? <InlineAlert>Asset not found.</InlineAlert> : <ErrorAlert error={asset.error} />}
      </div>
    );
  }

  const data = asset.data;
  const archived = data.status === "archived";
  return (
    <div className="space-y-6">
      {back}
      <PageHeader
        title={data.value}
        description={`${ASSET_TYPE_LABELS[data.type]}${data.description ? ` — ${data.description}` : ""}`}
        actions={
          canWrite ? (
            <Button
              variant="outline"
              size="sm"
              disabled={update.isPending}
              onClick={() => {
                update.mutate({ status: archived ? "active" : "archived" });
              }}
            >
              {archived ? <ArchiveRestore aria-hidden="true" /> : <Archive aria-hidden="true" />}
              {archived ? "Restore" : "Archive"}
            </Button>
          ) : null
        }
      />
      <ProjectTabs projectId={projectId} />
      {update.isError ? <ErrorAlert error={update.error} /> : null}
      <div className="grid gap-6 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Testing eligibility</CardTitle>
            <CardDescription>Computed from authorizations and the network policy. Resolved addresses are re-checked at scan time.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {archived ? <Badge>Archived</Badge> : <EligibilityBadges eligibility={data.eligibility} />}
            {data.eligibility.reasons.length > 0 ? (
              <ul className="list-disc space-y-1 pl-5 text-sm text-muted-foreground">
                {data.eligibility.reasons.map((reason) => (
                  <li key={reason}>{reason}</li>
                ))}
              </ul>
            ) : null}
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Classification</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <label className="block space-y-1 text-xs text-muted-foreground">
              Criticality
              <Select
                value={data.criticality}
                disabled={!canWrite || update.isPending}
                onChange={(e) => {
                  update.mutate({ criticality: e.target.value as AssetDetail["criticality"] });
                }}
              >
                {CRITICALITIES.map((c) => (
                  <option key={c} value={c}>
                    {c}
                  </option>
                ))}
              </Select>
            </label>
            <label className="block space-y-1 text-xs text-muted-foreground">
              Exposure
              <Select
                value={data.exposure}
                disabled={!canWrite || update.isPending}
                onChange={(e) => {
                  update.mutate({ exposure: e.target.value as AssetDetail["exposure"] });
                }}
              >
                {EXPOSURES.map((x) => (
                  <option key={x} value={x}>
                    {x}
                  </option>
                ))}
              </Select>
            </label>
            {data.tags.length ? (
              <div className="flex flex-wrap gap-1">
                {data.tags.map((tag) => (
                  <Badge key={tag}>{tag}</Badge>
                ))}
              </div>
            ) : null}
          </CardContent>
        </Card>
      </div>
      <AuthorizationsCard asset={data} canWrite={canWrite} isAdmin={user?.role === "admin"} />
      <HistoryCard asset={data} />
    </div>
  );
}
