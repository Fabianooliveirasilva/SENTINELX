import { zodResolver } from "@hookform/resolvers/zod";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Plus } from "lucide-react";
import { useState } from "react";
import { useForm, useWatch } from "react-hook-form";
import { useNavigate } from "react-router";
import { z } from "zod";

import { FormField } from "@/components/shared/form-field";
import { ErrorAlert } from "@/components/shared/inline-alert";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogTrigger } from "@/components/ui/dialog";
import { Input, Select, Textarea } from "@/components/ui/input";

import {
  ASSET_TYPE_LABELS,
  ASSET_TYPE_PLACEHOLDERS,
  ASSET_TYPES,
  assetsKeys,
  createAsset,
  CRITICALITIES,
  EXPOSURES,
} from "./api";

const schema = z.object({
  type: z.enum(ASSET_TYPES),
  value: z.string().trim().min(1, "Enter the asset value.").max(2048),
  description: z.string().max(2000),
  tags: z.string().max(400),
  criticality: z.enum(CRITICALITIES),
  exposure: z.enum(EXPOSURES),
});
type Values = z.infer<typeof schema>;

export function RegisterAssetDialog({ projectId }: { projectId: string }) {
  const [open, setOpen] = useState(false);
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const form = useForm<Values>({
    resolver: zodResolver(schema),
    defaultValues: { type: "domain", value: "", description: "", tags: "", criticality: "medium", exposure: "external" },
  });
  const mutation = useMutation({
    mutationFn: (values: Values) =>
      createAsset(projectId, {
        ...values,
        tags: values.tags
          .split(",")
          .map((t) => t.trim())
          .filter(Boolean),
      }),
    onSuccess: async (asset) => {
      await queryClient.invalidateQueries({ queryKey: assetsKeys.all(projectId) });
      setOpen(false);
      form.reset();
      void navigate(`/projects/${projectId}/assets/${asset.id}`);
    },
  });
  const { errors } = form.formState;
  const type = useWatch({ control: form.control, name: "type" });

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
          <Plus aria-hidden="true" />
          Register asset
        </Button>
      </DialogTrigger>
      <DialogContent
        title="Register asset"
        description="Registering an asset does not authorize testing it. Add an authorization record next."
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
            <FormField label="Type" error={errors.type?.message}>
              <Select {...form.register("type")}>
                {ASSET_TYPES.map((t) => (
                  <option key={t} value={t}>
                    {ASSET_TYPE_LABELS[t]}
                  </option>
                ))}
              </Select>
            </FormField>
            <FormField label="Criticality" error={errors.criticality?.message}>
              <Select {...form.register("criticality")}>
                {CRITICALITIES.map((c) => (
                  <option key={c} value={c}>
                    {c}
                  </option>
                ))}
              </Select>
            </FormField>
          </div>
          <FormField label="Value" error={errors.value?.message}>
            <Input autoComplete="off" placeholder={ASSET_TYPE_PLACEHOLDERS[type]} {...form.register("value")} />
          </FormField>
          <div className="grid gap-4 sm:grid-cols-2">
            <FormField label="Exposure" error={errors.exposure?.message}>
              <Select {...form.register("exposure")}>
                {EXPOSURES.map((e) => (
                  <option key={e} value={e}>
                    {e}
                  </option>
                ))}
              </Select>
            </FormField>
            <FormField label="Tags" error={errors.tags?.message} hint="Comma-separated, e.g. prod, pci">
              <Input autoComplete="off" {...form.register("tags")} />
            </FormField>
          </div>
          <FormField label="Description" error={errors.description?.message}>
            <Textarea {...form.register("description")} />
          </FormField>
          <div className="flex justify-end">
            <Button type="submit" disabled={mutation.isPending}>
              {mutation.isPending ? "Registering…" : "Register asset"}
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}
