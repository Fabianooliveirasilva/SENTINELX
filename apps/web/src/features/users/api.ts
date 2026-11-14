import { z } from "zod";

import { roleSchema, type Role } from "@/features/auth/schemas";
import { apiRequest, noContent, pageSchema } from "@/lib/api-client";

export const userSchema = z.object({
  id: z.uuid(),
  email: z.string(),
  full_name: z.string(),
  role: roleSchema,
  is_active: z.boolean(),
  created_at: z.string(),
  last_login_at: z.string().nullable(),
  locked: z.boolean(),
});
export type User = z.infer<typeof userSchema>;

export const roleInfoSchema = z.object({
  name: roleSchema,
  description: z.string(),
  permissions: z.array(z.string()),
});
export type RoleInfo = z.infer<typeof roleInfoSchema>;

export interface UserFilters {
  page: number;
  search?: string;
  role?: Role | "";
}

export const usersKeys = {
  all: ["users"] as const,
  list: (filters: UserFilters) => ["users", "list", filters] as const,
  roles: ["roles"] as const,
};

export function listUsers(filters: UserFilters) {
  return apiRequest("/users", pageSchema(userSchema), {
    query: { page: filters.page, page_size: 25, search: filters.search, role: filters.role },
  });
}

export interface NewUser {
  email: string;
  full_name: string;
  password: string;
  role: Role;
}

export function createUser(user: NewUser) {
  return apiRequest("/users", userSchema, { method: "POST", body: user });
}

export function updateUser(id: string, changes: { role?: Role; is_active?: boolean }) {
  return apiRequest(`/users/${id}`, userSchema, { method: "PATCH", body: changes });
}

export function resetUserMfa(id: string) {
  return apiRequest(`/users/${id}/mfa/reset`, noContent, { method: "POST" });
}

export function revokeUserSessions(id: string) {
  return apiRequest(`/users/${id}/revoke-sessions`, noContent, { method: "POST" });
}

export function listRoles() {
  return apiRequest("/roles", z.array(roleInfoSchema));
}
