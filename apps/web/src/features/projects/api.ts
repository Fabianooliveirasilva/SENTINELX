import { z } from "zod";

import { roleSchema } from "@/features/auth/schemas";
import { apiRequest, noContent, pageSchema } from "@/lib/api-client";

export const projectSchema = z.object({
  id: z.uuid(),
  name: z.string(),
  slug: z.string(),
  description: z.string(),
  created_at: z.string(),
  updated_at: z.string(),
  member_count: z.number().int().nonnegative(),
});
export type Project = z.infer<typeof projectSchema>;

export const memberSchema = z.object({
  user_id: z.uuid(),
  email: z.string(),
  full_name: z.string(),
  role: roleSchema,
  is_active: z.boolean(),
  added_at: z.string(),
});
export type Member = z.infer<typeof memberSchema>;

export const projectsKeys = {
  all: ["projects"] as const,
  list: (page: number, search: string) => ["projects", "list", page, search] as const,
  detail: (id: string) => ["projects", "detail", id] as const,
  members: (id: string) => ["projects", "members", id] as const,
};

export function listProjects(page: number, search: string) {
  return apiRequest("/projects", pageSchema(projectSchema), {
    query: { page, page_size: 25, search },
  });
}

export function getProject(id: string) {
  return apiRequest(`/projects/${id}`, projectSchema);
}

export function createProject(body: { name: string; description: string }) {
  return apiRequest("/projects", projectSchema, { method: "POST", body });
}

export function updateProject(id: string, body: { name?: string; description?: string }) {
  return apiRequest(`/projects/${id}`, projectSchema, { method: "PATCH", body });
}

export function deleteProject(id: string) {
  return apiRequest(`/projects/${id}`, noContent, { method: "DELETE" });
}

export function listMembers(id: string) {
  return apiRequest(`/projects/${id}/members`, z.array(memberSchema));
}

export function addMember(id: string, userId: string) {
  return apiRequest(`/projects/${id}/members`, memberSchema, {
    method: "POST",
    body: { user_id: userId },
  });
}

export function removeMember(id: string, userId: string) {
  return apiRequest(`/projects/${id}/members/${userId}`, noContent, { method: "DELETE" });
}
