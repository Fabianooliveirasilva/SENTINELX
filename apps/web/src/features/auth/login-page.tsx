import { zodResolver } from "@hookform/resolvers/zod";
import { useMutation } from "@tanstack/react-query";
import { LogIn } from "lucide-react";
import { useForm } from "react-hook-form";
import { Link } from "react-router";
import { z } from "zod";

import { FormField } from "@/components/shared/form-field";
import { ErrorAlert } from "@/components/shared/inline-alert";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

import { login } from "./api";
import { AuthLayout } from "./auth-layout";

const loginSchema = z.object({
  email: z.email("Enter a valid email address."),
  password: z.string().min(1, "Enter your password.").max(128),
});
type LoginValues = z.infer<typeof loginSchema>;

/** Successful login updates the session store; the route guard then redirects. */
export function LoginPage() {
  const form = useForm<LoginValues>({
    resolver: zodResolver(loginSchema),
    defaultValues: { email: "", password: "" },
  });
  const mutation = useMutation({
    mutationFn: (values: LoginValues) => login(values.email, values.password),
  });
  const { errors } = form.formState;

  return (
    <AuthLayout title="Sign in" subtitle="Access the SentinelX security platform.">
      <form
        noValidate
        className="space-y-4"
        onSubmit={form.handleSubmit((values) => {
          mutation.mutate(values);
        })}
      >
        {mutation.isError ? <ErrorAlert error={mutation.error} /> : null}
        <FormField label="Email" error={errors.email?.message}>
          <Input type="email" autoComplete="username" autoFocus {...form.register("email")} />
        </FormField>
        <FormField label="Password" error={errors.password?.message}>
          <Input type="password" autoComplete="current-password" {...form.register("password")} />
        </FormField>
        <Button type="submit" className="w-full" disabled={mutation.isPending}>
          <LogIn aria-hidden="true" />
          {mutation.isPending ? "Signing in…" : "Sign in"}
        </Button>
        <p className="text-center text-sm">
          <Link to="/forgot-password" className="text-primary hover:underline">
            Forgot your password?
          </Link>
        </p>
      </form>
    </AuthLayout>
  );
}
