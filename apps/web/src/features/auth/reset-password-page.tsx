import { zodResolver } from "@hookform/resolvers/zod";
import { useMutation } from "@tanstack/react-query";
import { useState } from "react";
import { useForm } from "react-hook-form";
import { Link } from "react-router";
import { z } from "zod";

import { FormField } from "@/components/shared/form-field";
import { ErrorAlert, InlineAlert } from "@/components/shared/inline-alert";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

import { confirmPasswordReset } from "./api";
import { AuthLayout } from "./auth-layout";
import { newPasswordSchema } from "./schemas";

const schema = z
  .object({ password: newPasswordSchema, confirm: z.string() })
  .refine((v) => v.password === v.confirm, { message: "Passwords do not match.", path: ["confirm"] });
type Values = z.infer<typeof schema>;

/**
 * The reset token arrives in the URL fragment (never sent to servers). It is
 * read once and the fragment is removed from the address bar and history.
 */
function takeTokenFromFragment(): string | null {
  const token = new URLSearchParams(window.location.hash.slice(1)).get("token");
  if (token) window.history.replaceState(null, "", window.location.pathname);
  return token;
}

export function ResetPasswordPage() {
  const [token] = useState(takeTokenFromFragment);
  const form = useForm<Values>({
    resolver: zodResolver(schema),
    defaultValues: { password: "", confirm: "" },
  });
  const mutation = useMutation({
    mutationFn: (values: Values) => confirmPasswordReset(token ?? "", values.password),
  });
  const { errors } = form.formState;

  if (!token) {
    return (
      <AuthLayout title="Reset password">
        <div className="space-y-4">
          <InlineAlert>This reset link is invalid. Request a new one.</InlineAlert>
          <Link to="/forgot-password" className="text-sm text-primary hover:underline">
            Request a new link
          </Link>
        </div>
      </AuthLayout>
    );
  }

  return (
    <AuthLayout title="Choose a new password" subtitle="All existing sessions will be signed out.">
      {mutation.isSuccess ? (
        <div className="space-y-4">
          <InlineAlert tone="success">Your password has been updated.</InlineAlert>
          <Link to="/login" className="text-sm text-primary hover:underline">
            Sign in
          </Link>
        </div>
      ) : (
        <form
          noValidate
          className="space-y-4"
          onSubmit={form.handleSubmit((values) => {
            mutation.mutate(values);
          })}
        >
          {mutation.isError ? <ErrorAlert error={mutation.error} /> : null}
          <FormField label="New password" error={errors.password?.message} hint="At least 12 characters.">
            <Input type="password" autoComplete="new-password" autoFocus {...form.register("password")} />
          </FormField>
          <FormField label="Confirm password" error={errors.confirm?.message}>
            <Input type="password" autoComplete="new-password" {...form.register("confirm")} />
          </FormField>
          <Button type="submit" className="w-full" disabled={mutation.isPending}>
            Update password
          </Button>
        </form>
      )}
    </AuthLayout>
  );
}
