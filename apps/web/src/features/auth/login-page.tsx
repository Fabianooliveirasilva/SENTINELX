import { zodResolver } from "@hookform/resolvers/zod";
import { useMutation } from "@tanstack/react-query";
import { LogIn } from "lucide-react";
import { useState } from "react";
import { useForm } from "react-hook-form";
import { Link } from "react-router";
import { z } from "zod";

import { FormField } from "@/components/shared/form-field";
import { ErrorAlert } from "@/components/shared/inline-alert";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

import { login, verifyMfa } from "./api";
import { mfaChallengeSchema } from "./schemas";
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
  const [challenge, setChallenge] = useState<string | null>(null);
  const mutation = useMutation({
    mutationFn: async (values: LoginValues) => {
      const result = await login(values.email, values.password);
      const pending = mfaChallengeSchema.safeParse(result);
      if (pending.success) setChallenge(pending.data.challenge_token);
    },
  });
  const { errors } = form.formState;

  if (challenge) {
    return (
      <MfaStep
        challengeToken={challenge}
        onRestart={() => {
          setChallenge(null);
          mutation.reset();
        }}
      />
    );
  }

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

const codeSchema = z.object({ code: z.string().trim().min(6, "Enter the code from your authenticator app.").max(32) });
type CodeValues = z.infer<typeof codeSchema>;

function MfaStep({ challengeToken, onRestart }: { challengeToken: string; onRestart: () => void }) {
  const form = useForm<CodeValues>({ resolver: zodResolver(codeSchema), defaultValues: { code: "" } });
  const mutation = useMutation({ mutationFn: (values: CodeValues) => verifyMfa(challengeToken, values.code) });
  return (
    <AuthLayout title="Verification code" subtitle="Enter the 6-digit code from your authenticator app, or a recovery code.">
      <form
        noValidate
        className="space-y-4"
        onSubmit={form.handleSubmit((values) => {
          mutation.mutate(values);
        })}
      >
        {mutation.isError ? <ErrorAlert error={mutation.error} /> : null}
        <FormField label="Code" error={form.formState.errors.code?.message}>
          <Input inputMode="numeric" autoComplete="one-time-code" autoFocus {...form.register("code")} />
        </FormField>
        <Button type="submit" className="w-full" disabled={mutation.isPending}>
          {mutation.isPending ? "Verifying…" : "Verify"}
        </Button>
        <p className="text-center text-sm">
          <button type="button" className="text-primary hover:underline" onClick={onRestart}>
            Use a different account
          </button>
        </p>
      </form>
    </AuthLayout>
  );
}
