import { zodResolver } from "@hookform/resolvers/zod";
import { useForm } from "react-hook-form";
import { z } from "zod";

import { FormField } from "@/components/shared/form-field";
import { Button } from "@/components/ui/button";
import { Input, Textarea } from "@/components/ui/input";

const projectFormSchema = z.object({
  name: z.string().trim().min(1, "Enter a project name.").max(120),
  description: z.string().trim().max(2000),
});
export type ProjectFormValues = z.infer<typeof projectFormSchema>;

export function ProjectForm({
  defaultValues,
  submitLabel,
  pending,
  onSubmit,
}: {
  defaultValues: ProjectFormValues;
  submitLabel: string;
  pending: boolean;
  onSubmit: (values: ProjectFormValues) => void;
}) {
  const form = useForm<ProjectFormValues>({
    resolver: zodResolver(projectFormSchema),
    defaultValues,
  });
  const { errors } = form.formState;
  return (
    <form
      noValidate
      className="space-y-4"
      onSubmit={form.handleSubmit((values) => {
        onSubmit(values);
      })}
    >
      <FormField label="Name" error={errors.name?.message}>
        <Input {...form.register("name")} />
      </FormField>
      <FormField label="Description" error={errors.description?.message} hint="Scope, owner and engagement notes.">
        <Textarea {...form.register("description")} />
      </FormField>
      <div className="flex justify-end">
        <Button type="submit" disabled={pending}>
          {submitLabel}
        </Button>
      </div>
    </form>
  );
}
