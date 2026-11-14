import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import { ErrorAlert, InlineAlert } from "@/components/shared/inline-alert";
import { PageHeader } from "@/components/shared/page-header";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input, Label } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { useCan } from "@/features/auth/use-auth";

import { getRiskModel, resetWeights, riskKeys, updateWeights, type RiskModel } from "./api";

function WeightsForm({ model }: { model: RiskModel }) {
  const queryClient = useQueryClient();
  const [values, setValues] = useState<Record<string, string>>(() =>
    Object.fromEntries(Object.entries(model.weights).map(([k, v]) => [k, String(v)])),
  );
  const [result, setResult] = useState<number | null>(null);
  const done = async (data: { rescored: number }) => {
    setResult(data.rescored);
    await queryClient.invalidateQueries({ queryKey: ["risk"] });
    await queryClient.invalidateQueries({ queryKey: ["findings"] });
  };
  const save = useMutation({
    mutationFn: () => updateWeights(Object.fromEntries(Object.entries(values).map(([k, v]) => [k, Number(v)]))),
    onSuccess: done,
  });
  const reset = useMutation({
    mutationFn: resetWeights,
    onSuccess: async (data) => {
      setValues(Object.fromEntries(Object.entries(data.weights).map(([k, v]) => [k, String(v)])));
      await done(data);
    },
  });

  return (
    <form
      noValidate
      className="space-y-4"
      onSubmit={(e) => {
        e.preventDefault();
        save.mutate();
      }}
    >
      {save.isError ? <ErrorAlert error={save.error} /> : null}
      {reset.isError ? <ErrorAlert error={reset.error} /> : null}
      {result !== null ? (
        <InlineAlert tone="success">Weights saved; {result} finding scores changed.</InlineAlert>
      ) : null}
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {Object.keys(model.weights).map((key) => {
          const bounds = model.bounds[key];
          return (
            <div key={key} className="space-y-1">
              <Label htmlFor={`w-${key}`}>{key.replaceAll("_", " ")}</Label>
              <Input
                id={`w-${key}`}
                type="number"
                step="any"
                min={bounds?.min}
                max={bounds?.max}
                value={values[key] ?? ""}
                onChange={(e) => {
                  setValues({ ...values, [key]: e.target.value });
                }}
              />
              <p className="text-xs text-muted-foreground">
                default {model.defaults[key]} · {bounds?.min}–{bounds?.max}
              </p>
            </div>
          );
        })}
      </div>
      <div className="flex justify-end gap-2">
        <Button
          type="button"
          variant="outline"
          disabled={reset.isPending}
          onClick={() => {
            reset.mutate();
          }}
        >
          Restore defaults
        </Button>
        <Button type="submit" disabled={save.isPending}>
          Save and rescore
        </Button>
      </div>
    </form>
  );
}

export function RiskModelPage() {
  const canManage = useCan("settings:manage");
  const model = useQuery({ queryKey: riskKeys.model, queryFn: getRiskModel });

  return (
    <div className="space-y-6">
      <PageHeader
        title="Risk model"
        description="Deterministic and versioned: the same inputs always produce the same score."
      />
      {model.isPending ? (
        <Skeleton className="h-32 w-full" />
      ) : model.isError ? (
        <ErrorAlert error={model.error} />
      ) : (
        <>
          <Card>
            <CardHeader>
              <CardTitle>Model {model.data.model_version}</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2 text-sm">
              <p data-testid="risk-formula">{model.data.formula}</p>
              <p className="text-muted-foreground">
                Bands:{" "}
                {Object.entries(model.data.bands)
                  .map(([band, threshold]) => `${band} ≥ ${String(threshold)}`)
                  .join(" · ")}
              </p>
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>Weights</CardTitle>
            </CardHeader>
            <CardContent>
              {canManage ? (
                <WeightsForm model={model.data} />
              ) : (
                <dl aria-label="Current weights" className="grid gap-2 text-sm sm:grid-cols-3">
                  {Object.entries(model.data.weights).map(([k, v]) => (
                    <div key={k}>
                      <dt className="text-xs text-muted-foreground">{k.replaceAll("_", " ")}</dt>
                      <dd className="font-mono">{v}</dd>
                    </div>
                  ))}
                </dl>
              )}
            </CardContent>
          </Card>
        </>
      )}
    </div>
  );
}
