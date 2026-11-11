import { zodResolver } from "@hookform/resolvers/zod";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { ShieldPlus } from "lucide-react";
import { useState } from "react";
import { useForm } from "react-hook-form";
import { z } from "zod";

import { FormField } from "@/components/shared/form-field";
import { ErrorAlert } from "@/components/shared/inline-alert";
import { Button } from "@/components/ui/button";
import { Dialog, DialogClose, DialogContent, DialogTrigger } from "@/components/ui/dialog";
import { Input, Textarea } from "@/components/ui/input";

import { addAuthorization, assetsKeys, revokeAuthorization, type AssetDetail, type Authorization } from "./api";

function toLocalInput(date: Date): string {
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

const schema = z
  .object({
    authorized_by: z.string().trim().min(1, "Who granted permission?").max(200),
    organization: z.string().trim().min(1, "Which organization owns the asset?").max(200),
    reference: z.string().trim().min(1, "Contract, ticket or engagement reference.").max(200),
    notes: z.string().max(4000),
    valid_from: z.string().min(1, "Required."),
    valid_until: z.string().min(1, "Required."),
    allow_active: z.boolean(),
    allow_intrusive: z.boolean(),
    include_subdomains: z.boolean(),
    ip_ranges: z.string().max(4000),
  })
  .refine((v) => new Date(v.valid_until) > new Date(v.valid_from), {
    message: "Must end after it starts.",
    path: ["valid_until"],
  });
type Values = z.infer<typeof schema>;

function Checkbox({ label, hint, ...props }: React.ComponentProps<"input"> & { label: string; hint?: string }) {
  return (
    <label className="flex items-start gap-2.5 text-sm">
      <input type="checkbox" className="mt-0.5 size-4 accent-[var(--primary)]" {...props} />
      <span>
        {label}
        {hint ? <span className="block text-xs text-muted-foreground">{hint}</span> : null}
      </span>
    </label>
  );
}

export function AddAuthorizationDialog({ asset, isAdmin }: { asset: AssetDetail; isAdmin: boolean }) {
  const [open, setOpen] = useState(false);
  const queryClient = useQueryClient();
  const now = new Date();
  const form = useForm<Values>({
    resolver: zodResolver(schema),
    defaultValues: {
      authorized_by: "",
      organization: "",
      reference: "",
      notes: "",
      valid_from: toLocalInput(now),
      valid_until: toLocalInput(new Date(now.getTime() + 30 * 24 * 3600 * 1000)),
      allow_active: false,
      allow_intrusive: false,
      include_subdomains: false,
      ip_ranges: "",
    },
  });
  const mutation = useMutation({
    mutationFn: (values: Values) =>
      addAuthorization(asset.project_id, asset.id, {
        ...values,
        valid_from: new Date(values.valid_from).toISOString(),
        valid_until: new Date(values.valid_until).toISOString(),
        ip_ranges: values.ip_ranges
          .split(/[\s,]+/)
          .map((r) => r.trim())
          .filter(Boolean),
      }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: assetsKeys.all(asset.project_id) });
      setOpen(false);
      form.reset();
    },
  });
  const { errors } = form.formState;
  const isHost = asset.type === "domain" || asset.type === "subdomain";

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        setOpen(next);
        if (!next) mutation.reset();
      }}
    >
      <DialogTrigger asChild>
        <Button size="sm">
          <ShieldPlus aria-hidden="true" />
          Add authorization
        </Button>
      </DialogTrigger>
      <DialogContent
        title="Record authorization"
        description="Records are immutable and audited. Only revocation changes them."
        className="max-h-[90dvh] overflow-y-auto"
      >
        <form
          noValidate
          className="space-y-4"
          onSubmit={form.handleSubmit((values) => {
            mutation.mutate(values);
          })}
        >
          {mutation.isError ? <ErrorAlert error={mutation.error} /> : null}
          <div className="grid gap-4 sm:grid-cols-2">
            <FormField label="Authorized by" error={errors.authorized_by?.message}>
              <Input {...form.register("authorized_by")} />
            </FormField>
            <FormField label="Organization" error={errors.organization?.message}>
              <Input {...form.register("organization")} />
            </FormField>
          </div>
          <FormField label="Reference" error={errors.reference?.message} hint="Contract, statement of work or ticket ID.">
            <Input {...form.register("reference")} />
          </FormField>
          <div className="grid gap-4 sm:grid-cols-2">
            <FormField label="Valid from" error={errors.valid_from?.message}>
              <Input type="datetime-local" {...form.register("valid_from")} />
            </FormField>
            <FormField label="Valid until" error={errors.valid_until?.message}>
              <Input type="datetime-local" {...form.register("valid_until")} />
            </FormField>
          </div>
          <fieldset className="space-y-3 rounded-md border border-border p-3">
            <legend className="px-1 text-xs font-medium text-muted-foreground">Permitted techniques</legend>
            <p className="text-xs text-muted-foreground">Passive techniques are always permitted while the authorization is valid.</p>
            <Checkbox label="Active testing" hint="Port and service discovery, TLS and HTTP checks, baseline DAST." {...form.register("allow_active")} />
            {isAdmin ? (
              <Checkbox label="Intrusive testing" hint="Active DAST. Requires active testing. Administrators only." {...form.register("allow_intrusive")} />
            ) : null}
            {isHost ? (
              <Checkbox label="Include subdomains" hint="Covers *.domain; each subdomain still needs authorized addresses." {...form.register("include_subdomains")} />
            ) : null}
          </fieldset>
          <FormField
            label="Authorized IP ranges"
            error={errors.ip_ranges?.message}
            hint="CIDR, one per line (e.g. 203.0.113.0/24). Active tests only reach addresses listed here or registered as authorized IP assets."
          >
            <Textarea className="font-mono" {...form.register("ip_ranges")} />
          </FormField>
          <FormField label="Notes" error={errors.notes?.message}>
            <Textarea {...form.register("notes")} />
          </FormField>
          <div className="flex justify-end">
            <Button type="submit" disabled={mutation.isPending}>
              {mutation.isPending ? "Recording…" : "Record authorization"}
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}

export function RevokeAuthorizationDialog({ asset, authorization }: { asset: AssetDetail; authorization: Authorization }) {
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState("");
  const queryClient = useQueryClient();
  const mutation = useMutation({
    mutationFn: () => revokeAuthorization(asset.project_id, asset.id, authorization.id, reason),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: assetsKeys.all(asset.project_id) });
      setOpen(false);
    },
  });
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="outline" size="sm" aria-label={`Revoke authorization ${authorization.reference}`}>
          Revoke
        </Button>
      </DialogTrigger>
      <DialogContent title={`Revoke “${authorization.reference}”?`} description="Testing under this authorization stops immediately.">
        <form
          className="space-y-4"
          onSubmit={(event) => {
            event.preventDefault();
            mutation.mutate();
          }}
        >
          {mutation.isError ? <ErrorAlert error={mutation.error} /> : null}
          <FormField label="Reason" hint="At least 3 characters; recorded in the audit log.">
            <Input
              value={reason}
              onChange={(e) => {
                setReason(e.target.value);
              }}
            />
          </FormField>
          <div className="flex justify-end gap-2">
            <DialogClose asChild>
              <Button type="button" variant="ghost">
                Cancel
              </Button>
            </DialogClose>
            <Button type="submit" className="bg-status-down text-white hover:bg-status-down/90" disabled={reason.trim().length < 3 || mutation.isPending}>
              Revoke
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}
