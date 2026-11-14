import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Bot, CheckCircle2, ShieldAlert } from "lucide-react";

import { ErrorAlert } from "@/components/shared/inline-alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { useCan } from "@/features/auth/use-auth";
import { formatDateTime } from "@/lib/format";
import { cn } from "@/lib/utils";

import { aiKeys, BASIS_LABELS, reviewAnalysis, type Analysis, type Basis } from "./api";

const BASIS_CLASSES: Record<Basis, string> = {
  confirmed_evidence: "border-status-ok/40 bg-status-ok/10 text-status-ok",
  scanner_hypothesis: "border-status-degraded/40 bg-status-degraded/10 text-status-degraded",
  external_intelligence: "border-primary/40 bg-primary/10 text-primary",
  ai_recommendation: "border-border bg-muted text-muted-foreground",
};

const PRIORITY_LABELS = { immediate: "Immediate", short_term: "Short term", long_term: "Long term" } as const;

export function BasisBadge({ basis }: { basis: Basis }) {
  return (
    <span
      className={cn(
        "inline-flex shrink-0 items-center rounded-sm border px-1.5 py-0.5 font-mono text-[10px] tracking-wider uppercase",
        BASIS_CLASSES[basis],
      )}
    >
      {BASIS_LABELS[basis]}
    </span>
  );
}

function Refs({ refs }: { refs: string[] }) {
  if (refs.length === 0) return null;
  return <span className="font-mono text-[11px] text-muted-foreground">[{refs.join(", ")}]</span>;
}

function Provenance({ analysis }: { analysis: Analysis }) {
  if (analysis.provider === "anthropic") {
    return (
      <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
        <Badge tone="degraded">
          <Bot className="size-3" aria-hidden="true" />
          AI-generated
        </Badge>
        <span>
          {analysis.model} · {analysis.prompt_version} · {analysis.input_tokens + analysis.output_tokens} tokens · $
          {analysis.cost_usd.toFixed(4)}
        </span>
      </div>
    );
  }
  return (
    <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
      <Badge tone="neutral">Deterministic</Badge>
      <span>No AI model was used{analysis.error ? `: ${analysis.error}` : "."}</span>
    </div>
  );
}

function Review({ analysis }: { analysis: Analysis }) {
  const canUse = useCan("ai:use");
  const queryClient = useQueryClient();
  const review = useMutation({
    mutationFn: () => reviewAnalysis(analysis.project_id, analysis.id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: aiKeys.all(analysis.project_id) }),
  });
  if (analysis.reviewed_at) {
    return (
      <p className="flex items-center gap-1.5 text-xs text-status-ok">
        <CheckCircle2 className="size-3.5" aria-hidden="true" />
        Reviewed by {analysis.reviewed_by_email} on {formatDateTime(analysis.reviewed_at)}
      </p>
    );
  }
  return (
    <div className="space-y-2">
      <p className="flex items-start gap-1.5 text-xs text-status-degraded">
        <ShieldAlert className="mt-0.5 size-3.5 shrink-0" aria-hidden="true" />
        Advisory output. A person must review it before any operational change is made.
      </p>
      {review.isError ? <ErrorAlert error={review.error} /> : null}
      {canUse ? (
        <Button size="sm" variant="outline" disabled={review.isPending} onClick={() => { review.mutate(); }}>
          Mark as reviewed
        </Button>
      ) : null}
    </div>
  );
}

/** Renders an analysis. All text is rendered as text: it may echo scanner output. */
export function AnalysisView({ analysis }: { analysis: Analysis }) {
  const output = analysis.output;
  if (!output) return null;
  return (
    <article aria-label={output.title} className="space-y-4">
      <header className="space-y-1">
        <h3 className="text-base font-semibold">{output.title}</h3>
        <Provenance analysis={analysis} />
        <p className="text-sm">{output.summary}</p>
      </header>
      {output.sections.map((section) => (
        <section key={section.heading} className="space-y-1.5">
          <h4 className="text-sm font-medium">{section.heading}</h4>
          <ul className="space-y-1.5">
            {section.claims.map((claim, index) => (
              <li key={index} className="flex flex-col gap-1 text-sm sm:flex-row sm:items-start sm:gap-2">
                <BasisBadge basis={claim.basis} />
                <span className="break-words">
                  {claim.text} <Refs refs={claim.references} />
                </span>
              </li>
            ))}
          </ul>
        </section>
      ))}
      {output.recommended_actions.length > 0 ? (
        <section className="space-y-1.5">
          <h4 className="text-sm font-medium">Recommended actions</h4>
          <ol aria-label="Recommended actions" className="list-decimal space-y-1.5 pl-5 text-sm">
            {output.recommended_actions.map((action, index) => (
              <li key={index}>
                <span className="font-medium">{action.action}</span>{" "}
                <span className="text-xs text-muted-foreground">({PRIORITY_LABELS[action.priority]})</span>
                <span className="block text-xs text-muted-foreground">
                  {action.rationale} <Refs refs={action.references} />
                </span>
              </li>
            ))}
          </ol>
        </section>
      ) : null}
      {output.investigation_steps.length > 0 ? (
        <section className="space-y-1.5">
          <h4 className="text-sm font-medium">Investigation steps</h4>
          <ul className="list-disc space-y-1 pl-5 text-sm">
            {output.investigation_steps.map((step, index) => (
              <li key={index}>{step}</li>
            ))}
          </ul>
        </section>
      ) : null}
      {output.limitations.length > 0 || analysis.warnings.length > 0 ? (
        <section className="space-y-1.5">
          <h4 className="text-sm font-medium">Limitations</h4>
          <ul className="list-disc space-y-1 pl-5 text-xs text-muted-foreground">
            {output.limitations.map((item, index) => (
              <li key={`l${String(index)}`}>{item}</li>
            ))}
            {analysis.warnings.map((item, index) => (
              <li key={`w${String(index)}`}>Validation: {item}</li>
            ))}
          </ul>
        </section>
      ) : null}
      <p className="text-xs text-muted-foreground">
        Confidence: {output.confidence}. References point to items of the assessment data (F = finding, E = evidence,
        I = intelligence, S = scan).
      </p>
      <Review analysis={analysis} />
    </article>
  );
}
