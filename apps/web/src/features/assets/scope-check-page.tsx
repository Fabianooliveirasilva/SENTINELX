import { zodResolver } from "@hookform/resolvers/zod";
import { useMutation } from "@tanstack/react-query";
import { CheckCircle2, Crosshair, XCircle } from "lucide-react";
import { useForm } from "react-hook-form";
import { useParams } from "react-router";
import { z } from "zod";

import { FormField } from "@/components/shared/form-field";
import { ErrorAlert } from "@/components/shared/inline-alert";
import { PageHeader } from "@/components/shared/page-header";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input, Select } from "@/components/ui/input";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { ProjectTabs } from "@/features/projects/project-tabs";
import { cn } from "@/lib/utils";

import { checkScope, TECHNIQUES, type ScopeDecision } from "./api";

const schema = z.object({
  target: z.string().trim().min(1, "Enter a hostname, IP, host:port or URL.").max(2048),
  technique: z.enum(TECHNIQUES),
});
type Values = z.infer<typeof schema>;

function DecisionCard({ decision }: { decision: ScopeDecision }) {
  const Icon = decision.allowed ? CheckCircle2 : XCircle;
  return (
    <Card className={cn(decision.allowed ? "border-status-ok/40" : "border-status-down/40")}>
      <CardHeader>
        <div className="flex items-center gap-2">
          <Icon className={cn("size-5", decision.allowed ? "text-status-ok" : "text-status-down")} aria-hidden="true" />
          <CardTitle data-testid="scope-verdict">{decision.allowed ? "In scope" : "Out of scope"}</CardTitle>
          <Badge>{decision.technique}</Badge>
        </div>
        <CardDescription className="font-mono">{decision.target}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <ul className="space-y-1.5" aria-label="Decision reasons">
          {decision.reasons.map((reason, index) => (
            <li key={`${reason.code}-${String(index)}`} className="text-sm">
              <span className="mr-2 font-mono text-xs text-muted-foreground">{reason.code}</span>
              {reason.message}
            </li>
          ))}
        </ul>
        {decision.addresses.length > 0 ? (
          <Table aria-label="Resolved addresses">
            <THead>
              <tr>
                <TH>Address</TH>
                <TH>Verdict</TH>
              </tr>
            </THead>
            <TBody>
              {decision.addresses.map((address) => (
                <TR key={address.address}>
                  <TD className="font-mono text-xs">{address.address}</TD>
                  <TD>
                    <Badge tone={address.allowed ? "ok" : "down"}>{address.allowed ? "permitted" : (address.reason ?? "blocked")}</Badge>
                  </TD>
                </TR>
              ))}
            </TBody>
          </Table>
        ) : null}
      </CardContent>
    </Card>
  );
}

export function ScopeCheckPage() {
  const { projectId = "" } = useParams();
  const form = useForm<Values>({ resolver: zodResolver(schema), defaultValues: { target: "", technique: "active" } });
  const mutation = useMutation({ mutationFn: (values: Values) => checkScope(projectId, values.target, values.technique) });

  return (
    <div className="space-y-6">
      <PageHeader
        title="Scope check"
        description="Explains whether a target may be tested. No traffic is sent to the target; hostnames are resolved via DNS."
      />
      <ProjectTabs projectId={projectId} />
      <Card>
        <CardContent className="pt-5">
          <form
            noValidate
            className="flex flex-col gap-3 sm:flex-row sm:items-start"
            onSubmit={form.handleSubmit((values) => {
              mutation.mutate(values);
            })}
          >
            <div className="flex-1">
              <FormField label="Target" error={form.formState.errors.target?.message}>
                <Input className="font-mono" placeholder="https://app.example.com/login" autoComplete="off" {...form.register("target")} />
              </FormField>
            </div>
            <div className="sm:w-40">
              <FormField label="Technique">
                <Select {...form.register("technique")}>
                  {TECHNIQUES.map((t) => (
                    <option key={t} value={t}>
                      {t}
                    </option>
                  ))}
                </Select>
              </FormField>
            </div>
            <Button type="submit" className="sm:mt-[22px]" disabled={mutation.isPending}>
              <Crosshair aria-hidden="true" />
              Check
            </Button>
          </form>
        </CardContent>
      </Card>
      {mutation.isError ? <ErrorAlert error={mutation.error} /> : null}
      {mutation.data ? <DecisionCard decision={mutation.data} /> : null}
    </div>
  );
}
