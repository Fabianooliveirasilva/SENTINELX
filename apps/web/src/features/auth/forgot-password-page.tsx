import { zodResolver } from "@hookform/resolvers/zod";
import { useMutation } from "@tanstack/react-query";
import { useForm } from "react-hook-form";
import { Link } from "react-router";
import { z } from "zod";

import { FormField } from "@/components/shared/form-field";
import { ErrorAlert, InlineAlert } from "@/components/shared/inline-alert";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

import { requestPasswordReset } from "./api";
import { AuthLayout } from "./auth-layout";

const schema = z.object({ email: z.email("Enter a valid email address.") });
type Values = z.infer<typeof schema>;

export function ForgotPasswordPage() {
  const form = useForm<Values>({ resolver: zodResolver(schema), defaultValues: { email: "" } });
  const mutation = useMutation({ mutationFn: (values: Values) => requestPasswordReset(values.email) });

  return (
    <AuthLayout title="Reset password" subtitle="We will email you a single-use reset link.">
      {mutation.isSuccess ? (
        <div className="space-y-4">
          <InlineAlert tone="success">{mutation.data.message}</InlineAlert>
          <Link to="/login" className="text-sm text-primary hover:underline">
            Back to sign in
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
          <FormField label="Email" error={form.formState.errors.email?.message}>
            <Input type="email" autoComplete="email" autoFocus {...form.register("email")} />
          </FormField>
          <Button type="submit" className="w-full" disabled={mutation.isPending}>
            Send reset link
          </Button>
          <p className="text-center text-sm">
            <Link to="/login" className="text-primary hover:underline">
              Back to sign in
            </Link>
          </p>
        </form>
      )}
    </AuthLayout>
  );
}
