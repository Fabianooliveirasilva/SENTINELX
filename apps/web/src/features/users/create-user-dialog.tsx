import { zodResolver } from "@hookform/resolvers/zod";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { UserPlus } from "lucide-react";
import { useState } from "react";
import { useForm } from "react-hook-form";
import { z } from "zod";

import { FormField } from "@/components/shared/form-field";
import { ErrorAlert } from "@/components/shared/inline-alert";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogTrigger } from "@/components/ui/dialog";
import { Input, Select } from "@/components/ui/input";
import { newPasswordSchema, ROLE_LABELS, ROLES, roleSchema } from "@/features/auth/schemas";

import { createUser, usersKeys } from "./api";

const schema = z.object({
  email: z.email("Enter a valid email address."),
  full_name: z.string().trim().min(1, "Enter the user's name.").max(200),
  password: newPasswordSchema,
  role: roleSchema,
});
type Values = z.infer<typeof schema>;

export function CreateUserDialog() {
  const [open, setOpen] = useState(false);
  const queryClient = useQueryClient();
  const form = useForm<Values>({
    resolver: zodResolver(schema),
    defaultValues: { email: "", full_name: "", password: "", role: "viewer" },
  });
  const mutation = useMutation({
    mutationFn: createUser,
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: usersKeys.all });
      form.reset();
      setOpen(false);
    },
  });
  const { errors } = form.formState;

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
          <UserPlus aria-hidden="true" />
          New user
        </Button>
      </DialogTrigger>
      <DialogContent title="Create user" description="Share the initial password through a secure channel.">
        <form
          noValidate
          className="space-y-4"
          onSubmit={form.handleSubmit((values) => {
            mutation.mutate(values);
          })}
        >
          {mutation.isError ? <ErrorAlert error={mutation.error} /> : null}
          <FormField label="Full name" error={errors.full_name?.message}>
            <Input autoComplete="off" {...form.register("full_name")} />
          </FormField>
          <FormField label="Email" error={errors.email?.message}>
            <Input type="email" autoComplete="off" {...form.register("email")} />
          </FormField>
          <FormField label="Initial password" error={errors.password?.message} hint="At least 12 characters.">
            <Input type="password" autoComplete="new-password" {...form.register("password")} />
          </FormField>
          <FormField label="Role" error={errors.role?.message}>
            <Select {...form.register("role")}>
              {ROLES.map((role) => (
                <option key={role} value={role}>
                  {ROLE_LABELS[role]}
                </option>
              ))}
            </Select>
          </FormField>
          <div className="flex justify-end gap-2 pt-2">
            <Button type="submit" disabled={mutation.isPending}>
              {mutation.isPending ? "Creating…" : "Create user"}
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}
