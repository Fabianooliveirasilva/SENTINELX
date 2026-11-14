import { z } from "zod";

export const ROLES = ["admin", "security_analyst", "viewer"] as const;
export const roleSchema = z.enum(ROLES);
export type Role = z.infer<typeof roleSchema>;

export const ROLE_LABELS: Record<Role, string> = {
  admin: "Admin",
  security_analyst: "Security Analyst",
  viewer: "Viewer",
};

export const currentUserSchema = z.object({
  id: z.uuid(),
  email: z.string(),
  full_name: z.string(),
  role: roleSchema,
  permissions: z.array(z.string()),
});
export type CurrentUser = z.infer<typeof currentUserSchema>;

export const tokenResponseSchema = z.object({
  access_token: z.string().min(1),
  token_type: z.literal("bearer"),
  expires_in: z.number().int().positive(),
  user: currentUserSchema,
});
export type TokenResponse = z.infer<typeof tokenResponseSchema>;

export const sessionSchema = z.object({
  id: z.uuid(),
  started_at: z.string(),
  last_used_at: z.string(),
  expires_at: z.string(),
  user_agent: z.string().nullable(),
  ip_address: z.string().nullable(),
  current: z.boolean(),
});
export type Session = z.infer<typeof sessionSchema>;

export const messageSchema = z.object({ message: z.string() });

export const MIN_PASSWORD_LENGTH = 12;
export const MAX_PASSWORD_LENGTH = 128;

export const newPasswordSchema = z
  .string()
  .min(MIN_PASSWORD_LENGTH, `Use at least ${MIN_PASSWORD_LENGTH} characters.`)
  .max(MAX_PASSWORD_LENGTH, `Use at most ${MAX_PASSWORD_LENGTH} characters.`);

export type Permission =
  | "users:read"
  | "users:manage"
  | "roles:read"
  | "projects:read"
  | "projects:manage"
  | "audit:read"
  | "settings:manage"
  | "assets:read"
  | "assets:write"
  | "scans:read"
  | "scans:execute"
  | "findings:read"
  | "findings:write"
  | "intelligence:read"
  | "events:read"
  | "alerts:manage"
  | "ai:use"
  | "reports:read"
  | "reports:generate";

export const mfaChallengeSchema = z.object({
  mfa_required: z.literal(true),
  challenge_token: z.string(),
  expires_in: z.number().int(),
});
export type MfaChallenge = z.infer<typeof mfaChallengeSchema>;
export const loginResponseSchema = z.union([mfaChallengeSchema, tokenResponseSchema]);

export const mfaStatusSchema = z.object({
  enabled: z.boolean(),
  pending_enrollment: z.boolean(),
  recovery_codes_remaining: z.number().int(),
});
export const mfaEnrollmentSchema = z.object({ secret: z.string(), otpauth_uri: z.string() });
export const mfaRecoveryCodesSchema = z.object({ recovery_codes: z.array(z.string()) });
