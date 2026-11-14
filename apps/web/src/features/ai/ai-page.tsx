import { useQuery } from "@tanstack/react-query";
import { Bot } from "lucide-react";
import { useState } from "react";
import { useParams } from "react-router";

import { EmptyState } from "@/components/shared/empty-state";
import { ErrorAlert, InlineAlert } from "@/components/shared/inline-alert";
import { PageHeader } from "@/components/shared/page-header";
import { Pagination } from "@/components/shared/pagination";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { ProjectTabs } from "@/features/projects/project-tabs";
import { formatDateTime } from "@/lib/format";

import { aiKeys, aiUsage, KIND_LABELS, listAnalyses, type Analysis } from "./api";
import { AnalysisPanel } from "./analysis-panel";
import { AnalysisView } from "./analysis-view";

function UsageCard({ projectId }: { projectId: string }) {
  const usage = useQuery({ queryKey: aiKeys.usage(projectId), queryFn: () => aiUsage(projectId) });
  if (usage.isError) return <ErrorAlert error={usage.error} />;
  if (!usage.data) return null;
  const u = usage.data;
  const percent = u.daily_token_budget ? Math.min(100, (u.tokens_today / u.daily_token_budget) * 100) : 100;
  return (
    <Card>
      <CardContent className="flex flex-col gap-3 py-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="space-y-1">
          <p className="text-sm font-medium">{u.enabled ? `AI provider: ${u.model ?? ""}` : "AI provider disabled"}</p>
          <p className="text-xs text-muted-foreground">
            {u.enabled
              ? "Analyses run asynchronously. Over the daily budget, analyses are produced deterministically."
              : "Every analysis is produced deterministically from the assessment data; nothing leaves the platform."}
          </p>
        </div>
        <div className="min-w-56 space-y-1" aria-label="AI usage today">
          <div className="flex justify-between text-xs text-muted-foreground">
            <span>
              {u.tokens_today.toLocaleString("en-US")} / {u.daily_token_budget.toLocaleString("en-US")} tokens today
            </span>
            <span>${u.cost_today_usd.toFixed(2)}</span>
          </div>
          <div
            className="h-1.5 overflow-hidden rounded-full bg-muted"
            role="progressbar"
            aria-label="Daily AI token budget used"
            aria-valuenow={Math.round(percent)}
            aria-valuemin={0}
            aria-valuemax={100}
          >
            <div className="h-full bg-primary" style={{ width: `${String(percent)}%` }} />
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function History({ projectId }: { projectId: string }) {
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<Analysis | null>(null);
  const history = useQuery({
    queryKey: aiKeys.list(projectId, "", "", page),
    queryFn: () => listAnalyses(projectId, { page }),
  });
  return (
    <Card>
      <CardHeader>
        <CardTitle>History</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {history.isPending ? (
          <Skeleton className="h-10 w-full" />
        ) : history.isError ? (
          <ErrorAlert error={history.error} />
        ) : history.data.items.length === 0 ? (
          <EmptyState icon={Bot} title="No analyses yet" />
        ) : (
          <>
            <Table aria-label="AI analyses">
              <THead>
                <tr>
                  <TH>Requested</TH>
                  <TH>Kind</TH>
                  <TH>Produced by</TH>
                  <TH>Status</TH>
                  <TH>Review</TH>
                  <TH className="text-right">Open</TH>
                </tr>
              </THead>
              <TBody>
                {history.data.items.map((a) => (
                  <TR key={a.id}>
                    <TD className="text-xs text-muted-foreground">{formatDateTime(a.created_at)}</TD>
                    <TD className="text-sm">{KIND_LABELS[a.kind]}</TD>
                    <TD className="text-xs">
                      {a.provider === "anthropic" ? a.model : a.provider === "deterministic" ? "deterministic" : "—"}
                    </TD>
                    <TD>
                      <Badge tone={a.status === "completed" ? "ok" : a.status === "failed" ? "down" : "degraded"}>
                        {a.status}
                      </Badge>
                    </TD>
                    <TD className="text-xs">{a.reviewed_by_email ?? "pending"}</TD>
                    <TD className="text-right">
                      <Button
                        size="sm"
                        variant="ghost"
                        disabled={!a.output}
                        onClick={() => {
                          setSelected(a);
                        }}
                      >
                        View
                      </Button>
                    </TD>
                  </TR>
                ))}
              </TBody>
            </Table>
            <Pagination
              page={page}
              pageSize={history.data.page_size}
              total={history.data.total}
              onPageChange={setPage}
            />
          </>
        )}
        {selected ? (
          <div className="rounded-md border border-border p-4">
            <AnalysisView analysis={selected} />
          </div>
        ) : null}
      </CardContent>
    </Card>
  );
}

export function AIAnalystPage() {
  const { projectId = "" } = useParams();
  return (
    <div className="space-y-6">
      <PageHeader
        title="AI analyst"
        description="Evidence-bound explanations and summaries. Every statement is labelled as confirmed evidence, scanner hypothesis, external intelligence or AI recommendation."
      />
      <ProjectTabs projectId={projectId} />
      <InlineAlert tone="success">
        AI output is advisory. Hostnames, IP addresses and e-mail addresses are replaced by placeholders before
        anything is sent to the provider, and scanned content is passed as untrusted data.
      </InlineAlert>
      <UsageCard projectId={projectId} />
      <div className="grid gap-6 xl:grid-cols-2">
        <AnalysisPanel
          projectId={projectId}
          kind="executive_summary"
          subjectId={projectId}
          description="Plain-language posture, top risks and decisions needed."
        />
        <AnalysisPanel
          projectId={projectId}
          kind="technical_summary"
          subjectId={projectId}
          description="Finding distribution, highest-risk issues with their evidence basis, and coverage gaps."
        />
      </div>
      <History projectId={projectId} />
    </div>
  );
}
