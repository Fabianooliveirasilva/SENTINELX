import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { FolderKanban, FolderPlus, Search } from "lucide-react";
import { useState } from "react";
import { Link, useNavigate } from "react-router";

import { EmptyState } from "@/components/shared/empty-state";
import { ErrorAlert } from "@/components/shared/inline-alert";
import { PageHeader } from "@/components/shared/page-header";
import { Pagination } from "@/components/shared/pagination";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Dialog, DialogContent, DialogTrigger } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { useCan } from "@/features/auth/use-auth";
import { formatDateTime } from "@/lib/format";

import { createProject, listProjects, projectsKeys } from "./api";
import { ProjectForm } from "./project-form";

function CreateProjectDialog() {
  const [open, setOpen] = useState(false);
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const mutation = useMutation({
    mutationFn: createProject,
    onSuccess: async (project) => {
      await queryClient.invalidateQueries({ queryKey: projectsKeys.all });
      setOpen(false);
      void navigate(`/projects/${project.id}`);
    },
  });
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button size="sm">
          <FolderPlus aria-hidden="true" />
          New project
        </Button>
      </DialogTrigger>
      <DialogContent title="Create project" description="Projects isolate assets, scans and findings per engagement.">
        {mutation.isError ? (
          <div className="mb-4">
            <ErrorAlert error={mutation.error} />
          </div>
        ) : null}
        <ProjectForm
          defaultValues={{ name: "", description: "" }}
          submitLabel={mutation.isPending ? "Creating…" : "Create project"}
          pending={mutation.isPending}
          onSubmit={(values) => {
            mutation.mutate(values);
          }}
        />
      </DialogContent>
    </Dialog>
  );
}

export function ProjectsPage() {
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState("");
  const canManage = useCan("projects:manage");
  const projects = useQuery({
    queryKey: projectsKeys.list(page, search.trim()),
    queryFn: () => listProjects(page, search.trim()),
  });

  return (
    <div className="space-y-6">
      <PageHeader
        title="Projects"
        description="Each project is an isolated workspace. You only see projects you are a member of."
        actions={canManage ? <CreateProjectDialog /> : null}
      />
      <Card>
        <CardContent className="pt-5">
          <div className="relative mb-4">
            <Search className="pointer-events-none absolute top-2.5 left-3 size-4 text-muted-foreground" aria-hidden="true" />
            <Input
              aria-label="Search projects"
              placeholder="Search projects"
              className="pl-9"
              value={search}
              onChange={(event) => {
                setSearch(event.target.value);
                setPage(1);
              }}
            />
          </div>
          {projects.isPending ? (
            <div role="status" aria-label="Loading projects" className="space-y-2">
              <Skeleton className="h-10 w-full" />
              <Skeleton className="h-10 w-full" />
            </div>
          ) : projects.isError ? (
            <ErrorAlert error={projects.error} />
          ) : projects.data.items.length === 0 ? (
            <EmptyState icon={FolderKanban} title="No projects yet">
              {canManage ? "Create a project to start registering authorized assets." : "Ask an administrator to add you to a project."}
            </EmptyState>
          ) : (
            <>
              <Table aria-label="Projects">
                <THead>
                  <tr>
                    <TH>Project</TH>
                    <TH>Members</TH>
                    <TH>Created</TH>
                  </tr>
                </THead>
                <TBody>
                  {projects.data.items.map((project) => (
                    <TR key={project.id}>
                      <TD>
                        <Link to={`/projects/${project.id}`} className="font-medium text-primary hover:underline">
                          {project.name}
                        </Link>
                        <div className="font-mono text-xs text-muted-foreground">{project.slug}</div>
                      </TD>
                      <TD>{project.member_count}</TD>
                      <TD className="text-xs text-muted-foreground">{formatDateTime(project.created_at)}</TD>
                    </TR>
                  ))}
                </TBody>
              </Table>
              <Pagination page={page} pageSize={projects.data.page_size} total={projects.data.total} onPageChange={setPage} />
            </>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
