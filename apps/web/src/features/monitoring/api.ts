import { z } from "zod";

import { SEVERITIES, type Severity } from "@/features/findings/api";
import { apiRequest, noContent, pageSchema } from "@/lib/api-client";

const id = z.uuid();
const nullableId = id.nullable();

export const eventSchema = z.object({
  id,
  project_id: id,
  event_type: z.string(),
  severity: z.enum(SEVERITIES),
  title: z.string(),
  asset_id: nullableId,
  finding_id: nullableId,
  scan_job_id: nullableId,
  details: z.record(z.string(), z.unknown()),
  actor_email: z.string().nullable(),
  occurred_at: z.string(),
});
export type SecurityEvent = z.infer<typeof eventSchema>;

export const eventTypeSchema = z.object({ type: z.string(), description: z.string() });
export type EventTypeInfo = z.infer<typeof eventTypeSchema>;

export const eventSummarySchema = z.object({
  since: z.string(),
  total: z.number().int(),
  by_severity: z.record(z.string(), z.number().int()),
});

export const CHANNEL_KINDS = ["email", "webhook"] as const;
export type ChannelKind = (typeof CHANNEL_KINDS)[number];

export const channelSchema = z.object({
  id,
  project_id: id,
  name: z.string(),
  kind: z.enum(CHANNEL_KINDS),
  enabled: z.boolean(),
  recipients: z.array(z.string()).nullable(),
  url: z.string().nullable(),
  has_secret: z.boolean(),
  created_at: z.string(),
  updated_at: z.string(),
});
export type Channel = z.infer<typeof channelSchema>;
export const channelWithSecretSchema = channelSchema.extend({ signing_secret: z.string().nullable() });

export const ruleSchema = z.object({
  id,
  project_id: id,
  name: z.string(),
  enabled: z.boolean(),
  event_types: z.array(z.string()),
  min_severity: z.enum(SEVERITIES),
  asset_id: nullableId,
  quiet_period_minutes: z.number().int(),
  channels: z.array(z.object({ id, name: z.string(), kind: z.enum(CHANNEL_KINDS), enabled: z.boolean() })),
  created_at: z.string(),
  updated_at: z.string(),
});
export type AlertRule = z.infer<typeof ruleSchema>;

export const DELIVERY_STATUSES = ["pending", "sent", "failed", "suppressed"] as const;
export type DeliveryStatus = (typeof DELIVERY_STATUSES)[number];

export const deliverySchema = z.object({
  id,
  status: z.enum(DELIVERY_STATUSES),
  attempts: z.number().int(),
  last_error: z.string().nullable(),
  response_status: z.number().int().nullable(),
  next_attempt_at: z.string(),
  sent_at: z.string().nullable(),
  created_at: z.string(),
  rule_id: nullableId,
  channel_id: id,
  channel_name: z.string(),
  channel_kind: z.enum(CHANNEL_KINDS),
  event_id: id,
  event_type: z.string(),
  event_title: z.string(),
  event_severity: z.enum(SEVERITIES),
});
export type Delivery = z.infer<typeof deliverySchema>;

export const scheduleSchema = z.object({
  id,
  project_id: id,
  asset_id: id,
  scanner: z.string(),
  profile: z.string(),
  interval_hours: z.number().int(),
  enabled: z.boolean(),
  next_run_at: z.string(),
  last_run_at: z.string().nullable(),
  last_status: z.string().nullable(),
  last_message: z.string().nullable(),
  last_scan_job_id: nullableId,
  owner_id: nullableId,
  created_at: z.string(),
  updated_at: z.string(),
});
export type Schedule = z.infer<typeof scheduleSchema>;

export interface EventFilters {
  page: number;
  eventType: string;
  minSeverity: Severity | "";
  assetId: string;
  days: number;
}

export const monitoringKeys = {
  types: ["events", "types"] as const,
  events: (projectId: string, filters: EventFilters) => ["events", projectId, "list", filters] as const,
  summary: (projectId: string) => ["events", projectId, "summary"] as const,
  channels: (projectId: string) => ["alerts", projectId, "channels"] as const,
  rules: (projectId: string) => ["alerts", projectId, "rules"] as const,
  deliveries: (projectId: string, page: number) => ["alerts", projectId, "deliveries", page] as const,
  alerts: (projectId: string) => ["alerts", projectId] as const,
  schedules: (projectId: string) => ["schedules", projectId] as const,
};

const project = (projectId: string) => `/projects/${projectId}`;

export function listEventTypes() {
  return apiRequest("/events/types", z.array(eventTypeSchema));
}

export function listEvents(projectId: string, filters: EventFilters) {
  const since = filters.days > 0 ? new Date(Date.now() - filters.days * 86_400_000).toISOString() : undefined;
  return apiRequest(`${project(projectId)}/events`, pageSchema(eventSchema), {
    query: {
      page: filters.page,
      page_size: 50,
      event_type: filters.eventType,
      min_severity: filters.minSeverity,
      asset_id: filters.assetId,
      since,
    },
  });
}

export function eventSummary(projectId: string) {
  return apiRequest(`${project(projectId)}/events/summary`, eventSummarySchema, { query: { days: 7 } });
}

export function listChannels(projectId: string) {
  return apiRequest(`${project(projectId)}/notification-channels`, z.array(channelSchema));
}

export interface ChannelInput {
  name: string;
  kind: ChannelKind;
  recipients?: string[];
  url?: string;
}

export function createChannel(projectId: string, body: ChannelInput) {
  return apiRequest(`${project(projectId)}/notification-channels`, channelWithSecretSchema, { method: "POST", body });
}

export function updateChannel(projectId: string, channelId: string, body: Partial<ChannelInput> & { enabled?: boolean }) {
  return apiRequest(`${project(projectId)}/notification-channels/${channelId}`, channelSchema, { method: "PATCH", body });
}

export function rotateSecret(projectId: string, channelId: string) {
  return apiRequest(`${project(projectId)}/notification-channels/${channelId}/rotate-secret`, channelWithSecretSchema, {
    method: "POST",
  });
}

export function testChannel(projectId: string, channelId: string) {
  return apiRequest(
    `${project(projectId)}/notification-channels/${channelId}/test`,
    z.object({ notification_id: id, status: z.string() }),
    { method: "POST" },
  );
}

export function deleteChannel(projectId: string, channelId: string) {
  return apiRequest(`${project(projectId)}/notification-channels/${channelId}`, noContent, { method: "DELETE" });
}

export function listRules(projectId: string) {
  return apiRequest(`${project(projectId)}/alert-rules`, z.array(ruleSchema));
}

export interface RuleInput {
  name: string;
  event_types: string[];
  min_severity: Severity;
  asset_id: string | null;
  quiet_period_minutes: number;
  channel_ids: string[];
  enabled?: boolean;
}

export function createRule(projectId: string, body: RuleInput) {
  return apiRequest(`${project(projectId)}/alert-rules`, ruleSchema, { method: "POST", body });
}

export function updateRule(projectId: string, ruleId: string, body: Partial<RuleInput>) {
  return apiRequest(`${project(projectId)}/alert-rules/${ruleId}`, ruleSchema, { method: "PATCH", body });
}

export function deleteRule(projectId: string, ruleId: string) {
  return apiRequest(`${project(projectId)}/alert-rules/${ruleId}`, noContent, { method: "DELETE" });
}

export function listDeliveries(projectId: string, page: number) {
  return apiRequest(`${project(projectId)}/notifications`, pageSchema(deliverySchema), {
    query: { page, page_size: 25 },
  });
}

export function listSchedules(projectId: string) {
  return apiRequest(`${project(projectId)}/scan-schedules`, pageSchema(scheduleSchema), { query: { page_size: 100 } });
}

export interface ScheduleInput {
  asset_id: string;
  scanner: string;
  profile: string;
  interval_hours: number;
  first_run_at?: string;
}

export function createSchedule(projectId: string, body: ScheduleInput) {
  return apiRequest(`${project(projectId)}/scan-schedules`, scheduleSchema, { method: "POST", body });
}

export function updateSchedule(projectId: string, scheduleId: string, body: { enabled?: boolean; interval_hours?: number }) {
  return apiRequest(`${project(projectId)}/scan-schedules/${scheduleId}`, scheduleSchema, { method: "PATCH", body });
}

export function deleteSchedule(projectId: string, scheduleId: string) {
  return apiRequest(`${project(projectId)}/scan-schedules/${scheduleId}`, noContent, { method: "DELETE" });
}

/** "finding.created" -> "Finding created" */
export function eventLabel(type: string): string {
  const text = type.replace(".", " ").replaceAll("_", " ");
  return text.charAt(0).toUpperCase() + text.slice(1);
}
