import { zodResolver } from "@hookform/resolvers/zod";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Monitor } from "lucide-react";
import { useForm } from "react-hook-form";
import { z } from "zod";

import { FormField } from "@/components/shared/form-field";
import { ErrorAlert } from "@/components/shared/inline-alert";
import { PageHeader } from "@/components/shared/page-header";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { changePassword, listSessions, revokeSession } from "@/features/auth/api";
import { newPasswordSchema, ROLE_LABELS } from "@/features/auth/schemas";
import { sessionStore } from "@/features/auth/session-store";
import { useSession } from "@/features/auth/use-auth";
import { formatDateTime } from "@/lib/format";

const passwordSchema = z
  .object({
    current: z.string().min(1, "Enter your current password."),
    next: newPasswordSchema,
    confirm: z.string(),
  })
  .refine((v) => v.next === v.confirm, { message: "Passwords do not match.", path: ["confirm"] });
type PasswordValues = z.infer<typeof passwordSchema>;

function ChangePasswordCard() {
  const form = useForm<PasswordValues>({
    resolver: zodResolver(passwordSchema),
    defaultValues: { current: "", next: "", confirm: "" },
  });
  const mutation = useMutation({
    mutationFn: (values: PasswordValues) => changePassword(values.current, values.next),
    // Every session (including this one) is revoked server-side: sign in again.
    onSuccess: () => {
      sessionStore.clear();
    },
  });
  const { errors } = form.formState;
  return (
    <Card>
      <CardHeader>
        <CardTitle>Change password</CardTitle>
        <CardDescription>Changing your password signs you out of every session.</CardDescription>
      </CardHeader>
      <CardContent>
        <form
          noValidate
          className="max-w-sm space-y-4"
          onSubmit={form.handleSubmit((values) => {
            mutation.mutate(values);
          })}
        >
          {mutation.isError ? <ErrorAlert error={mutation.error} /> : null}
          <FormField label="Current password" error={errors.current?.message}>
            <Input type="password" autoComplete="current-password" {...form.register("current")} />
          </FormField>
          <FormField label="New password" error={errors.next?.message} hint="At least 12 characters.">
            <Input type="password" autoComplete="new-password" {...form.register("next")} />
          </FormField>
          <FormField label="Confirm new password" error={errors.confirm?.message}>
            <Input type="password" autoComplete="new-password" {...form.register("confirm")} />
          </FormField>
          <Button type="submit" disabled={mutation.isPending}>
            Update password
          </Button>
        </form>
      </CardContent>
    </Card>
  );
}

function SessionsCard() {
  const queryClient = useQueryClient();
  const sessions = useQuery({ queryKey: ["auth", "sessions"], queryFn: listSessions });
  const revoke = useMutation({
    mutationFn: revokeSession,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["auth", "sessions"] }),
  });
  return (
    <Card>
      <CardHeader>
        <CardTitle>Active sessions</CardTitle>
        <CardDescription>Sign out sessions you do not recognize.</CardDescription>
      </CardHeader>
      <CardContent>
        {revoke.isError ? <ErrorAlert error={revoke.error} /> : null}
        {sessions.isPending ? (
          <Skeleton className="h-16 w-full" />
        ) : sessions.isError ? (
          <ErrorAlert error={sessions.error} />
        ) : (
          <ul className="divide-y divide-border" aria-label="Active sessions">
            {sessions.data.map((session) => (
              <li key={session.id} className="flex items-center justify-between gap-4 py-3">
                <div className="flex min-w-0 items-start gap-3">
                  <Monitor className="mt-0.5 size-4 shrink-0 text-muted-foreground" aria-hidden="true" />
                  <div className="min-w-0">
                    <p className="truncate text-sm">{session.user_agent ?? "Unknown client"}</p>
                    <p className="text-xs text-muted-foreground">
                      {session.ip_address ?? "unknown IP"} · started {formatDateTime(session.started_at)} · last used{" "}
                      {formatDateTime(session.last_used_at)}
                    </p>
                  </div>
                </div>
                {session.current ? (
                  <Badge tone="ok">This device</Badge>
                ) : (
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={revoke.isPending}
                    onClick={() => {
                      revoke.mutate(session.id);
                    }}
                  >
                    Sign out
                  </Button>
                )}
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  );
}

export function AccountPage() {
  const { user } = useSession();
  return (
    <div className="space-y-6">
      <PageHeader title="Account" description="Your profile, password and sessions." />
      <Card>
        <CardHeader>
          <CardTitle>Profile</CardTitle>
        </CardHeader>
        <CardContent>
          <dl className="grid gap-3 text-sm sm:grid-cols-3">
            <div>
              <dt className="text-xs text-muted-foreground">Name</dt>
              <dd>{user?.full_name}</dd>
            </div>
            <div>
              <dt className="text-xs text-muted-foreground">Email</dt>
              <dd>{user?.email}</dd>
            </div>
            <div>
              <dt className="text-xs text-muted-foreground">Role</dt>
              <dd>{user ? ROLE_LABELS[user.role] : null}</dd>
            </div>
          </dl>
        </CardContent>
      </Card>
      <ChangePasswordCard />
      <SessionsCard />
    </div>
  );
}
