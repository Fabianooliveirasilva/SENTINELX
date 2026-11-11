import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, Trash2, UserMinus, UserPlus } from "lucide-react";
import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router";

import { ErrorAlert, InlineAlert } from "@/components/shared/inline-alert";
import { PageHeader } from "@/components/shared/page-header";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogClose, DialogContent, DialogTrigger } from "@/components/ui/dialog";
import { Select } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { ROLE_LABELS } from "@/features/auth/schemas";
import { useCan } from "@/features/auth/use-auth";
import { listUsers } from "@/features/users/api";
import { ApiError } from "@/lib/api-client";
import { formatDateTime } from "@/lib/format";

import {
  addMember,
  deleteProject,
  getProject,
  listMembers,
  projectsKeys,
  removeMember,
  updateProject,
  type Project,
} from "./api";
import { ProjectForm } from "./project-form";
import { ProjectTabs } from "./project-tabs";

function AddMemberForm({ projectId, memberIds }: { projectId: string; memberIds: Set<string> }) {
  const [userId, setUserId] = useState("");
  const queryClient = useQueryClient();
  const users = useQuery({
    queryKey: ["users", "member-candidates"],
    queryFn: () => listUsers({ page: 1 }),
  });
  const mutation = useMutation({
    mutationFn: () => addMember(projectId, userId),
    onSuccess: async () => {
      setUserId("");
      await queryClient.invalidateQueries({ queryKey: projectsKeys.all });
    },
  });
  const candidates = (users.data?.items ?? []).filter((u) => u.is_active && !memberIds.has(u.id));

  return (
    <div className="space-y-2">
      {mutation.isError ? <ErrorAlert error={mutation.error} /> : null}
      <form
        className="flex flex-col gap-2 sm:flex-row"
        onSubmit={(event) => {
          event.preventDefault();
          if (userId) mutation.mutate();
        }}
      >
        <Select
          aria-label="User to add"
          value={userId}
          onChange={(event) => {
            setUserId(event.target.value);
          }}
          className="flex-1"
        >
          <option value="">Select a user…</option>
          {candidates.map((u) => (
            <option key={u.id} value={u.id}>
              {u.full_name} — {u.email} ({ROLE_LABELS[u.role]})
            </option>
          ))}
        </Select>
        <Button type="submit" size="sm" className="h-9" disabled={!userId || mutation.isPending}>
          <UserPlus aria-hidden="true" />
          Add member
        </Button>
      </form>
    </div>
  );
}

function MembersCard({ project, canManage }: { project: Project; canManage: boolean }) {
  const queryClient = useQueryClient();
  const members = useQuery({
    queryKey: projectsKeys.members(project.id),
    queryFn: () => listMembers(project.id),
  });
  const remove = useMutation({
    mutationFn: (userId: string) => removeMember(project.id, userId),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: projectsKeys.all }),
  });

  return (
    <Card>
      <CardHeader>
        <CardTitle>Members</CardTitle>
        <CardDescription>Members can access this project according to their role.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {canManage && members.data ? (
          <AddMemberForm projectId={project.id} memberIds={new Set(members.data.map((m) => m.user_id))} />
        ) : null}
        {remove.isError ? <ErrorAlert error={remove.error} /> : null}
        {members.isPending ? (
          <Skeleton className="h-16 w-full" />
        ) : members.isError ? (
          <ErrorAlert error={members.error} />
        ) : (
          <Table aria-label="Project members">
            <THead>
              <tr>
                <TH>Member</TH>
                <TH>Role</TH>
                <TH>Added</TH>
                <TH>
                  <span className="sr-only">Actions</span>
                </TH>
              </tr>
            </THead>
            <TBody>
              {members.data.map((member) => (
                <TR key={member.user_id}>
                  <TD>
                    <div className="font-medium">{member.full_name}</div>
                    <div className="text-xs text-muted-foreground">{member.email}</div>
                  </TD>
                  <TD>
                    <span className="mr-2">{ROLE_LABELS[member.role]}</span>
                    {member.is_active ? null : <Badge>Disabled</Badge>}
                  </TD>
                  <TD className="text-xs text-muted-foreground">{formatDateTime(member.added_at)}</TD>
                  <TD className="text-right">
                    {canManage ? (
                      <Button
                        variant="ghost"
                        size="sm"
                        aria-label={`Remove ${member.email}`}
                        disabled={remove.isPending}
                        onClick={() => {
                          remove.mutate(member.user_id);
                        }}
                      >
                        <UserMinus aria-hidden="true" />
                      </Button>
                    ) : null}
                  </TD>
                </TR>
              ))}
            </TBody>
          </Table>
        )}
      </CardContent>
    </Card>
  );
}

function DangerZone({ project }: { project: Project }) {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const mutation = useMutation({
    mutationFn: () => deleteProject(project.id),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: projectsKeys.all });
      void navigate("/projects");
    },
  });
  return (
    <Card className="border-status-down/30">
      <CardHeader>
        <CardTitle>Delete project</CardTitle>
        <CardDescription>Removes the project and its memberships. Audit records are preserved.</CardDescription>
      </CardHeader>
      <CardContent>
        <Dialog>
          <DialogTrigger asChild>
            <Button variant="outline" size="sm" className="text-status-down">
              <Trash2 aria-hidden="true" />
              Delete project
            </Button>
          </DialogTrigger>
          <DialogContent title={`Delete “${project.name}”?`} description="This action cannot be undone.">
            {mutation.isError ? <ErrorAlert error={mutation.error} /> : null}
            <div className="flex justify-end gap-2 pt-2">
              <DialogClose asChild>
                <Button variant="ghost">Cancel</Button>
              </DialogClose>
              <Button
                className="bg-status-down text-white hover:bg-status-down/90"
                disabled={mutation.isPending}
                onClick={() => {
                  mutation.mutate();
                }}
              >
                Delete
              </Button>
            </div>
          </DialogContent>
        </Dialog>
      </CardContent>
    </Card>
  );
}

export function ProjectDetailPage() {
  const { projectId = "" } = useParams();
  const canManage = useCan("projects:manage");
  const queryClient = useQueryClient();
  const project = useQuery({ queryKey: projectsKeys.detail(projectId), queryFn: () => getProject(projectId) });
  const update = useMutation({
    mutationFn: (values: { name: string; description: string }) => updateProject(projectId, values),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: projectsKeys.all }),
  });

  const back = (
    <Link to="/projects" className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
      <ArrowLeft className="size-4" aria-hidden="true" />
      Projects
    </Link>
  );

  if (project.isPending) {
    return (
      <div role="status" aria-label="Loading project" className="space-y-4">
        {back}
        <Skeleton className="h-8 w-64" />
        <Skeleton className="h-40 w-full" />
      </div>
    );
  }
  if (project.isError) {
    const notFound = project.error instanceof ApiError && project.error.status === 404;
    return (
      <div className="space-y-4">
        {back}
        {notFound ? <InlineAlert>Project not found or you are not a member.</InlineAlert> : <ErrorAlert error={project.error} />}
      </div>
    );
  }

  const data = project.data;
  return (
    <div className="space-y-6">
      {back}
      <PageHeader title={data.name} description={data.description || "No description."} />
      <ProjectTabs projectId={data.id} />
      {canManage ? (
        <Card>
          <CardHeader>
            <CardTitle>Details</CardTitle>
            <CardDescription>
              Slug <span className="font-mono">{data.slug}</span> · created {formatDateTime(data.created_at)}
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {update.isError ? <ErrorAlert error={update.error} /> : null}
            {update.isSuccess ? <InlineAlert tone="success">Project updated.</InlineAlert> : null}
            <ProjectForm
              key={data.updated_at}
              defaultValues={{ name: data.name, description: data.description }}
              submitLabel="Save changes"
              pending={update.isPending}
              onSubmit={(values) => {
                update.mutate(values);
              }}
            />
          </CardContent>
        </Card>
      ) : null}
      <MembersCard project={data} canManage={canManage} />
      {canManage ? <DangerZone project={data} /> : null}
    </div>
  );
}
