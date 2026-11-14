import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Sparkles } from "lucide-react";

import { ErrorAlert } from "@/components/shared/inline-alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { useCan } from "@/features/auth/use-auth";

import { aiKeys, isRunning, KIND_LABELS, listAnalyses, requestAnalysis, type AnalysisKind } from "./api";
import { AnalysisView } from "./analysis-view";

const POLL_MS = 3_000;

interface AnalysisPanelProps {
  projectId: string;
  kind: AnalysisKind;
  subjectId: string;
  compareWith?: string;
  description?: string;
  disabled?: boolean;
}

/** Latest analysis of one subject, with a button to request (or refresh) it. */
export function AnalysisPanel({ projectId, kind, subjectId, compareWith, description, disabled }: AnalysisPanelProps) {
  const canUse = useCan("ai:use");
  const queryClient = useQueryClient();
  const latest = useQuery({
    queryKey: aiKeys.list(projectId, subjectId, kind, 1),
    queryFn: () => listAnalyses(projectId, { subjectId, kind }),
    refetchInterval: (query) => (query.state.data?.items[0] && isRunning(query.state.data.items[0]) ? POLL_MS : false),
  });
  const request = useMutation({
    mutationFn: (refresh: boolean) =>
      requestAnalysis(projectId, {
        kind,
        subject_id: subjectId,
        ...(compareWith ? { compare_with: compareWith } : {}),
        refresh,
      }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: aiKeys.all(projectId) }),
  });
  const analysis = latest.data?.items[0];
  const running = analysis ? isRunning(analysis) : false;

  return (
    <Card>
      <CardHeader className="flex flex-row items-start justify-between gap-4">
        <div>
          <CardTitle>AI analyst · {KIND_LABELS[kind]}</CardTitle>
          <CardDescription>
            {description ??
              "Explains the assessment data with every statement labelled by its basis. Identifying values are withheld from the AI provider."}
          </CardDescription>
        </div>
        {canUse ? (
          <Button
            size="sm"
            variant={analysis ? "outline" : "default"}
            disabled={disabled === true || running || request.isPending}
            onClick={() => { request.mutate(Boolean(analysis)); }}
          >
            <Sparkles aria-hidden="true" />
            {analysis ? "Regenerate" : "Analyze"}
          </Button>
        ) : null}
      </CardHeader>
      <CardContent className="space-y-3">
        {request.isError ? <ErrorAlert error={request.error} /> : null}
        {latest.isPending ? (
          <Skeleton className="h-16 w-full" />
        ) : latest.isError ? (
          <ErrorAlert error={latest.error} />
        ) : !analysis ? (
          <p className="text-sm text-muted-foreground">No analysis yet.</p>
        ) : running ? (
          <p role="status" className="text-sm text-muted-foreground">
            Analysis in progress…
          </p>
        ) : analysis.status === "failed" ? (
          <ErrorAlert error={new Error(analysis.error ?? "The analysis failed.")} />
        ) : (
          <AnalysisView analysis={analysis} />
        )}
      </CardContent>
    </Card>
  );
}
