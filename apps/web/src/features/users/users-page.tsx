import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { LogOut, Search, Users } from "lucide-react";
import { useState } from "react";

import { EmptyState } from "@/components/shared/empty-state";
import { ErrorAlert } from "@/components/shared/inline-alert";
import { PageHeader } from "@/components/shared/page-header";
import { Pagination } from "@/components/shared/pagination";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input, Select } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { ROLE_LABELS, ROLES, type Role } from "@/features/auth/schemas";
import { useCan, useSession } from "@/features/auth/use-auth";
import { formatDateTime } from "@/lib/format";

import { listRoles, listUsers, revokeUserSessions, updateUser, usersKeys, type User } from "./api";
import { CreateUserDialog } from "./create-user-dialog";

function UserRow({ user, canManage, isSelf }: { user: User; canManage: boolean; isSelf: boolean }) {
  const queryClient = useQueryClient();
  const invalidate = () => queryClient.invalidateQueries({ queryKey: usersKeys.all });
  const update = useMutation({
    mutationFn: (changes: { role?: Role; is_active?: boolean }) => updateUser(user.id, changes),
    onSuccess: invalidate,
  });
  const revoke = useMutation({ mutationFn: () => revokeUserSessions(user.id) });

  return (
    <TR>
      <TD>
        <div className="font-medium">{user.full_name}</div>
        <div className="text-xs text-muted-foreground">{user.email}</div>
        {update.isError ? (
          <div className="mt-2">
            <ErrorAlert error={update.error} />
          </div>
        ) : null}
      </TD>
      <TD>
        {canManage && !isSelf ? (
          <Select
            aria-label={`Role for ${user.email}`}
            value={user.role}
            disabled={update.isPending}
            onChange={(event) => {
              update.mutate({ role: event.target.value as Role });
            }}
            className="w-44"
          >
            {ROLES.map((role) => (
              <option key={role} value={role}>
                {ROLE_LABELS[role]}
              </option>
            ))}
          </Select>
        ) : (
          <span>{ROLE_LABELS[user.role]}</span>
        )}
      </TD>
      <TD>
        <div className="flex flex-wrap gap-1.5">
          <Badge tone={user.is_active ? "ok" : "neutral"}>{user.is_active ? "Active" : "Disabled"}</Badge>
          {user.locked ? <Badge tone="degraded">Locked</Badge> : null}
        </div>
      </TD>
      <TD className="text-xs text-muted-foreground">{formatDateTime(user.last_login_at)}</TD>
      <TD>
        {canManage && !isSelf ? (
          <div className="flex justify-end gap-1">
            <Button
              variant="outline"
              size="sm"
              disabled={update.isPending}
              onClick={() => {
                update.mutate({ is_active: !user.is_active });
              }}
            >
              {user.is_active ? "Disable" : "Enable"}
            </Button>
            <Button
              variant="ghost"
              size="sm"
              disabled={revoke.isPending}
              onClick={() => {
                revoke.mutate();
              }}
              aria-label={`Sign out ${user.email} everywhere`}
              title="Sign out everywhere"
            >
              <LogOut aria-hidden="true" />
              {revoke.isSuccess ? "Signed out" : null}
            </Button>
          </div>
        ) : null}
      </TD>
    </TR>
  );
}

function RolesCard() {
  const roles = useQuery({ queryKey: usersKeys.roles, queryFn: listRoles });
  return (
    <Card>
      <CardHeader>
        <CardTitle>Roles &amp; permissions</CardTitle>
        <CardDescription>Permissions are enforced by the API for every request.</CardDescription>
      </CardHeader>
      <CardContent>
        {roles.isPending ? (
          <Skeleton className="h-24 w-full" />
        ) : roles.isError ? (
          <ErrorAlert error={roles.error} />
        ) : (
          <div className="grid gap-4 md:grid-cols-3">
            {roles.data.map((role) => (
              <div key={role.name} className="rounded-md border border-border p-4">
                <p className="text-sm font-semibold">{ROLE_LABELS[role.name]}</p>
                <p className="mt-1 text-xs text-muted-foreground">{role.description}</p>
                <ul className="mt-3 flex flex-wrap gap-1" aria-label={`${ROLE_LABELS[role.name]} permissions`}>
                  {role.permissions.map((permission) => (
                    <li key={permission}>
                      <Badge>{permission}</Badge>
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

export function UsersPage() {
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState("");
  const [role, setRole] = useState<Role | "">("");
  const canManage = useCan("users:manage");
  const { user: me } = useSession();
  const filters = { page, search: search.trim(), role };
  const users = useQuery({ queryKey: usersKeys.list(filters), queryFn: () => listUsers(filters) });

  return (
    <div className="space-y-6">
      <PageHeader
        title="Users & Roles"
        description="Manage platform accounts and their access level."
        actions={canManage ? <CreateUserDialog /> : null}
      />
      <Card>
        <CardContent className="pt-5">
          <div className="mb-4 flex flex-col gap-2 sm:flex-row">
            <div className="relative flex-1">
              <Search className="pointer-events-none absolute top-2.5 left-3 size-4 text-muted-foreground" aria-hidden="true" />
              <Input
                aria-label="Search users"
                placeholder="Search by name or email"
                className="pl-9"
                value={search}
                onChange={(event) => {
                  setSearch(event.target.value);
                  setPage(1);
                }}
              />
            </div>
            <Select
              aria-label="Filter by role"
              className="sm:w-48"
              value={role}
              onChange={(event) => {
                setRole(event.target.value as Role | "");
                setPage(1);
              }}
            >
              <option value="">All roles</option>
              {ROLES.map((r) => (
                <option key={r} value={r}>
                  {ROLE_LABELS[r]}
                </option>
              ))}
            </Select>
          </div>
          {users.isPending ? (
            <div role="status" aria-label="Loading users" className="space-y-2">
              <Skeleton className="h-10 w-full" />
              <Skeleton className="h-10 w-full" />
            </div>
          ) : users.isError ? (
            <ErrorAlert error={users.error} />
          ) : users.data.items.length === 0 ? (
            <EmptyState icon={Users} title="No users match these filters" />
          ) : (
            <>
              <Table aria-label="Users">
                <THead>
                  <tr>
                    <TH>User</TH>
                    <TH>Role</TH>
                    <TH>Status</TH>
                    <TH>Last sign-in</TH>
                    <TH>
                      <span className="sr-only">Actions</span>
                    </TH>
                  </tr>
                </THead>
                <TBody>
                  {users.data.items.map((user) => (
                    <UserRow key={user.id} user={user} canManage={canManage} isSelf={user.id === me?.id} />
                  ))}
                </TBody>
              </Table>
              <Pagination page={page} pageSize={users.data.page_size} total={users.data.total} onPageChange={setPage} />
            </>
          )}
        </CardContent>
      </Card>
      <RolesCard />
    </div>
  );
}
