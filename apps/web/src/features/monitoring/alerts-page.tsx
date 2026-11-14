import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { BellRing, Plus, Send } from "lucide-react";
import { useState } from "react";
import { useParams } from "react-router";

import { EmptyState } from "@/components/shared/empty-state";
import { FormField } from "@/components/shared/form-field";
import { ErrorAlert, InlineAlert } from "@/components/shared/inline-alert";
import { PageHeader } from "@/components/shared/page-header";
import { Pagination } from "@/components/shared/pagination";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, DialogTrigger } from "@/components/ui/dialog";
import { Input, Select, Textarea } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { useCan } from "@/features/auth/use-auth";
import { SEVERITIES, type Severity } from "@/features/findings/api";
import { SeverityBadge } from "@/features/findings/severity";
import { ProjectTabs } from "@/features/projects/project-tabs";
import { formatDateTime } from "@/lib/format";

import {
  createChannel,
  createRule,
  deleteChannel,
  deleteRule,
  eventLabel,
  listChannels,
  listDeliveries,
  listEventTypes,
  listRules,
  monitoringKeys,
  rotateSecret,
  testChannel,
  updateChannel,
  updateRule,
  type Channel,
  type ChannelKind,
  type DeliveryStatus,
} from "./api";

const DELIVERY_TONE: Record<DeliveryStatus, "ok" | "degraded" | "down" | "neutral"> = {
  sent: "ok",
  pending: "degraded",
  failed: "down",
  suppressed: "neutral",
};

function useInvalidateAlerts(projectId: string) {
  const queryClient = useQueryClient();
  return () => queryClient.invalidateQueries({ queryKey: monitoringKeys.alerts(projectId) });
}

// --------------------------------------------------------------------- secret reveal

function SecretNotice({ secret, onClose }: { secret: string; onClose: () => void }) {
  return (
    <Dialog
      open
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
    >
      <DialogContent
        title="Webhook signing secret"
        description="Copy it now: it is stored encrypted and will not be shown again. Verify the X-SentinelX-Signature header with it."
      >
        <div className="space-y-4">
          <code className="block rounded-md border border-border bg-muted p-3 font-mono text-sm break-all select-all">
            {secret}
          </code>
          <p className="text-xs text-muted-foreground">
            Signature: <span className="font-mono">t=&lt;unix&gt;,v1=HMAC-SHA256(secret, "&lt;t&gt;." + body)</span>
          </p>
          <div className="flex justify-end">
            <Button onClick={onClose}>I have stored it</Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

// --------------------------------------------------------------------- channels

function NewChannelDialog({ projectId, onSecret }: { projectId: string; onSecret: (secret: string) => void }) {
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [kind, setKind] = useState<ChannelKind>("email");
  const [recipients, setRecipients] = useState("");
  const [url, setUrl] = useState("");
  const invalidate = useInvalidateAlerts(projectId);
  const mutation = useMutation({
    mutationFn: () =>
      createChannel(projectId, {
        name,
        kind,
        ...(kind === "email"
          ? { recipients: recipients.split(/[\s,;]+/).filter(Boolean) }
          : { url: url.trim() }),
      }),
    onSuccess: async (channel) => {
      await invalidate();
      setOpen(false);
      if (channel.signing_secret) onSecret(channel.signing_secret);
    },
  });
  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        setOpen(next);
        if (!next) {
          setName("");
          setRecipients("");
          setUrl("");
          mutation.reset();
        }
      }}
    >
      <DialogTrigger asChild>
        <Button size="sm" variant="outline">
          <Plus aria-hidden="true" />
          New channel
        </Button>
      </DialogTrigger>
      <DialogContent
        title="New notification channel"
        description="Webhooks must use https and resolve to public addresses (or networks an administrator allowed); every delivery is signed."
      >
        <form
          noValidate
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault();
            mutation.mutate();
          }}
        >
          {mutation.isError ? <ErrorAlert error={mutation.error} /> : null}
          <FormField label="Name">
            <Input
              value={name}
              maxLength={100}
              onChange={(e) => {
                setName(e.target.value);
              }}
            />
          </FormField>
          <FormField label="Type">
            <Select
              value={kind}
              onChange={(e) => {
                setKind(e.target.value as ChannelKind);
              }}
            >
              <option value="email">E-mail</option>
              <option value="webhook">Webhook (signed JSON POST)</option>
            </Select>
          </FormField>
          {kind === "email" ? (
            <FormField label="Recipients" hint="Separate addresses with commas or new lines (up to 20).">
              <Textarea
                rows={3}
                value={recipients}
                onChange={(e) => {
                  setRecipients(e.target.value);
                }}
              />
            </FormField>
          ) : (
            <FormField label="URL">
              <Input
                type="url"
                placeholder="https://hooks.example.com/sentinelx"
                value={url}
                onChange={(e) => {
                  setUrl(e.target.value);
                }}
              />
            </FormField>
          )}
          <div className="flex justify-end">
            <Button type="submit" disabled={!name.trim() || mutation.isPending}>
              {mutation.isPending ? "Saving…" : "Create channel"}
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function ChannelRow({
  projectId,
  channel,
  onSecret,
  onNotice,
}: {
  projectId: string;
  channel: Channel;
  onSecret: (secret: string) => void;
  onNotice: (text: string) => void;
}) {
  const invalidate = useInvalidateAlerts(projectId);
  const toggle = useMutation({
    mutationFn: () => updateChannel(projectId, channel.id, { enabled: !channel.enabled }),
    onSuccess: invalidate,
  });
  const test = useMutation({
    mutationFn: () => testChannel(projectId, channel.id),
    onSuccess: async () => {
      await invalidate();
      onNotice(`Test notification queued for ${channel.name}. Check the delivery log.`);
    },
  });
  const rotate = useMutation({
    mutationFn: () => rotateSecret(projectId, channel.id),
    onSuccess: (result) => {
      if (result.signing_secret) onSecret(result.signing_secret);
    },
  });
  const remove = useMutation({ mutationFn: () => deleteChannel(projectId, channel.id), onSuccess: invalidate });
  const error = toggle.error ?? test.error ?? rotate.error ?? remove.error;
  return (
    <TR>
      <TD className="font-medium">{channel.name}</TD>
      <TD className="text-sm">{channel.kind}</TD>
      <TD className="max-w-xs truncate font-mono text-xs" title={channel.url ?? channel.recipients?.join(", ")}>
        {channel.kind === "email" ? channel.recipients?.join(", ") : channel.url}
        {error ? <ErrorAlert error={error} /> : null}
      </TD>
      <TD>
        <Badge tone={channel.enabled ? "ok" : "neutral"}>{channel.enabled ? "enabled" : "disabled"}</Badge>
      </TD>
      <TD>
        <div className="flex flex-wrap justify-end gap-1">
          <Button size="sm" variant="ghost" disabled={!channel.enabled || test.isPending} onClick={() => { test.mutate(); }}>
            <Send aria-hidden="true" />
            Test
          </Button>
          {channel.kind === "webhook" ? (
            <Button
              size="sm"
              variant="ghost"
              disabled={rotate.isPending}
              onClick={() => {
                if (window.confirm("Rotate the signing secret? The receiver must be updated with the new one.")) {
                  rotate.mutate();
                }
              }}
            >
              Rotate secret
            </Button>
          ) : null}
          <Button size="sm" variant="ghost" disabled={toggle.isPending} onClick={() => { toggle.mutate(); }}>
            {channel.enabled ? "Disable" : "Enable"}
          </Button>
          <Button
            size="sm"
            variant="ghost"
            disabled={remove.isPending}
            onClick={() => {
              if (window.confirm(`Delete channel ${channel.name}? Rules using it stop notifying it.`)) remove.mutate();
            }}
          >
            Delete
          </Button>
        </div>
      </TD>
    </TR>
  );
}

function ChannelsCard({ projectId }: { projectId: string }) {
  const [secret, setSecret] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const channels = useQuery({ queryKey: monitoringKeys.channels(projectId), queryFn: () => listChannels(projectId) });
  return (
    <Card>
      <CardHeader className="flex flex-row items-start justify-between gap-4">
        <div>
          <CardTitle>Notification channels</CardTitle>
          <CardDescription>Where alerts are delivered.</CardDescription>
        </div>
        <NewChannelDialog projectId={projectId} onSecret={setSecret} />
      </CardHeader>
      <CardContent className="space-y-3">
        {notice ? <InlineAlert tone="success">{notice}</InlineAlert> : null}
        {channels.isPending ? (
          <Skeleton className="h-10 w-full" />
        ) : channels.isError ? (
          <ErrorAlert error={channels.error} />
        ) : channels.data.length === 0 ? (
          <EmptyState icon={BellRing} title="No channels yet">
            Add an e-mail list or a webhook, then point alert rules at it.
          </EmptyState>
        ) : (
          <Table aria-label="Notification channels">
            <THead>
              <tr>
                <TH>Name</TH>
                <TH>Type</TH>
                <TH>Destination</TH>
                <TH>State</TH>
                <TH className="text-right">Actions</TH>
              </tr>
            </THead>
            <TBody>
              {channels.data.map((channel) => (
                <ChannelRow
                  key={channel.id}
                  projectId={projectId}
                  channel={channel}
                  onSecret={setSecret}
                  onNotice={setNotice}
                />
              ))}
            </TBody>
          </Table>
        )}
      </CardContent>
      {secret ? (
        <SecretNotice
          secret={secret}
          onClose={() => {
            setSecret(null);
          }}
        />
      ) : null}
    </Card>
  );
}

// --------------------------------------------------------------------- rules

function NewRuleDialog({ projectId, channels }: { projectId: string; channels: Channel[] }) {
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [eventTypes, setEventTypes] = useState<string[]>([]);
  const [minSeverity, setMinSeverity] = useState<Severity>("high");
  const [quiet, setQuiet] = useState(60);
  const [channelIds, setChannelIds] = useState<string[]>([]);
  const types = useQuery({ queryKey: monitoringKeys.types, queryFn: listEventTypes, staleTime: Infinity, enabled: open });
  const invalidate = useInvalidateAlerts(projectId);
  const mutation = useMutation({
    mutationFn: () =>
      createRule(projectId, {
        name,
        event_types: eventTypes,
        min_severity: minSeverity,
        asset_id: null,
        quiet_period_minutes: quiet,
        channel_ids: channelIds,
      }),
    onSuccess: async () => {
      await invalidate();
      setOpen(false);
    },
  });
  const toggle = (list: string[], value: string) =>
    list.includes(value) ? list.filter((v) => v !== value) : [...list, value];

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        setOpen(next);
        if (!next) {
          setName("");
          setEventTypes([]);
          setChannelIds([]);
          mutation.reset();
        }
      }}
    >
      <DialogTrigger asChild>
        <Button size="sm" disabled={channels.length === 0}>
          <Plus aria-hidden="true" />
          New rule
        </Button>
      </DialogTrigger>
      <DialogContent
        title="New alert rule"
        description="Matching events notify the selected channels. Repeats of the same event within the quiet period are recorded but not sent."
        className="max-w-2xl"
      >
        <form
          noValidate
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault();
            mutation.mutate();
          }}
        >
          {mutation.isError ? <ErrorAlert error={mutation.error} /> : null}
          <FormField label="Name">
            <Input
              value={name}
              maxLength={100}
              onChange={(e) => {
                setName(e.target.value);
              }}
            />
          </FormField>
          <div className="grid gap-4 sm:grid-cols-2">
            <FormField label="Minimum severity">
              <Select
                value={minSeverity}
                onChange={(e) => {
                  setMinSeverity(e.target.value as Severity);
                }}
              >
                {SEVERITIES.map((s) => (
                  <option key={s} value={s}>
                    {s}
                  </option>
                ))}
              </Select>
            </FormField>
            <FormField label="Quiet period (minutes)" hint="0 sends every occurrence.">
              <Input
                type="number"
                min={0}
                max={10080}
                value={quiet}
                onChange={(e) => {
                  setQuiet(Number(e.target.value));
                }}
              />
            </FormField>
          </div>
          <fieldset>
            <legend className="mb-1 text-sm font-medium">Event types</legend>
            <p className="mb-2 text-xs text-muted-foreground">Leave all unchecked to match every event type.</p>
            <div className="grid max-h-48 gap-1 overflow-y-auto rounded-md border border-border p-2 sm:grid-cols-2">
              {(types.data ?? []).map((t) => (
                <label key={t.type} className="flex items-start gap-2 text-sm" title={t.description}>
                  <input
                    type="checkbox"
                    className="mt-0.5"
                    checked={eventTypes.includes(t.type)}
                    onChange={() => {
                      setEventTypes(toggle(eventTypes, t.type));
                    }}
                  />
                  {eventLabel(t.type)}
                </label>
              ))}
            </div>
          </fieldset>
          <fieldset>
            <legend className="mb-1 text-sm font-medium">Channels</legend>
            <div className="flex flex-wrap gap-3">
              {channels.map((c) => (
                <label key={c.id} className="flex items-center gap-2 text-sm">
                  <input
                    type="checkbox"
                    checked={channelIds.includes(c.id)}
                    onChange={() => {
                      setChannelIds(toggle(channelIds, c.id));
                    }}
                  />
                  {c.name} <span className="text-xs text-muted-foreground">({c.kind})</span>
                </label>
              ))}
            </div>
          </fieldset>
          <div className="flex justify-end">
            <Button type="submit" disabled={!name.trim() || channelIds.length === 0 || mutation.isPending}>
              {mutation.isPending ? "Saving…" : "Create rule"}
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function RulesCard({ projectId, canManage }: { projectId: string; canManage: boolean }) {
  const rules = useQuery({ queryKey: monitoringKeys.rules(projectId), queryFn: () => listRules(projectId) });
  const channels = useQuery({
    queryKey: monitoringKeys.channels(projectId),
    queryFn: () => listChannels(projectId),
    enabled: canManage,
  });
  const invalidate = useInvalidateAlerts(projectId);
  const toggle = useMutation({
    mutationFn: (rule: { id: string; enabled: boolean }) => updateRule(projectId, rule.id, { enabled: !rule.enabled }),
    onSuccess: invalidate,
  });
  const remove = useMutation({ mutationFn: (id: string) => deleteRule(projectId, id), onSuccess: invalidate });

  return (
    <Card>
      <CardHeader className="flex flex-row items-start justify-between gap-4">
        <div>
          <CardTitle>Alert rules</CardTitle>
          <CardDescription>Which events notify whom.</CardDescription>
        </div>
        {canManage ? <NewRuleDialog projectId={projectId} channels={channels.data ?? []} /> : null}
      </CardHeader>
      <CardContent className="space-y-3">
        {toggle.isError ? <ErrorAlert error={toggle.error} /> : null}
        {remove.isError ? <ErrorAlert error={remove.error} /> : null}
        {rules.isPending ? (
          <Skeleton className="h-10 w-full" />
        ) : rules.isError ? (
          <ErrorAlert error={rules.error} />
        ) : rules.data.length === 0 ? (
          <EmptyState icon={BellRing} title="No alert rules">
            {canManage ? "Create a channel first, then a rule that routes events to it." : null}
          </EmptyState>
        ) : (
          <Table aria-label="Alert rules">
            <THead>
              <tr>
                <TH>Name</TH>
                <TH>Events</TH>
                <TH>Severity</TH>
                <TH>Quiet</TH>
                <TH>Channels</TH>
                <TH>State</TH>
                {canManage ? <TH className="text-right">Actions</TH> : null}
              </tr>
            </THead>
            <TBody>
              {rules.data.map((rule) => (
                <TR key={rule.id}>
                  <TD className="font-medium">{rule.name}</TD>
                  <TD className="max-w-xs text-xs">
                    {rule.event_types.length === 0 ? "All events" : rule.event_types.map(eventLabel).join(", ")}
                  </TD>
                  <TD>
                    <span className="flex items-center gap-1 text-xs">
                      <SeverityBadge severity={rule.min_severity} />+
                    </span>
                  </TD>
                  <TD className="text-sm tabular-nums">{rule.quiet_period_minutes} min</TD>
                  <TD className="text-xs">{rule.channels.map((c) => c.name).join(", ")}</TD>
                  <TD>
                    <Badge tone={rule.enabled ? "ok" : "neutral"}>{rule.enabled ? "enabled" : "disabled"}</Badge>
                  </TD>
                  {canManage ? (
                    <TD>
                      <div className="flex justify-end gap-1">
                        <Button size="sm" variant="ghost" onClick={() => { toggle.mutate(rule); }}>
                          {rule.enabled ? "Disable" : "Enable"}
                        </Button>
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => {
                            if (window.confirm(`Delete rule ${rule.name}?`)) remove.mutate(rule.id);
                          }}
                        >
                          Delete
                        </Button>
                      </div>
                    </TD>
                  ) : null}
                </TR>
              ))}
            </TBody>
          </Table>
        )}
      </CardContent>
    </Card>
  );
}

// --------------------------------------------------------------------- deliveries

function DeliveriesCard({ projectId }: { projectId: string }) {
  const [page, setPage] = useState(1);
  const deliveries = useQuery({
    queryKey: monitoringKeys.deliveries(projectId, page),
    queryFn: () => listDeliveries(projectId, page),
    refetchInterval: (query) => (query.state.data?.items.some((d) => d.status === "pending") ? 10_000 : false),
  });
  return (
    <Card>
      <CardHeader>
        <CardTitle>Delivery log</CardTitle>
        <CardDescription>Every notification attempt, including suppressed repeats.</CardDescription>
      </CardHeader>
      <CardContent>
        {deliveries.isPending ? (
          <Skeleton className="h-10 w-full" />
        ) : deliveries.isError ? (
          <ErrorAlert error={deliveries.error} />
        ) : deliveries.data.items.length === 0 ? (
          <EmptyState icon={Send} title="Nothing delivered yet" />
        ) : (
          <>
            <Table aria-label="Notification deliveries">
              <THead>
                <tr>
                  <TH>Queued</TH>
                  <TH>Event</TH>
                  <TH>Channel</TH>
                  <TH>Status</TH>
                  <TH>Attempts</TH>
                  <TH>Last error</TH>
                </tr>
              </THead>
              <TBody>
                {deliveries.data.items.map((d) => (
                  <TR key={d.id}>
                    <TD className="text-xs text-muted-foreground">{formatDateTime(d.created_at)}</TD>
                    <TD className="max-w-xs">
                      <span className="flex items-center gap-2">
                        <SeverityBadge severity={d.event_severity} />
                        <span className="truncate text-sm" title={d.event_title}>
                          {d.event_title}
                        </span>
                      </span>
                    </TD>
                    <TD className="text-sm">{d.channel_name}</TD>
                    <TD>
                      <Badge tone={DELIVERY_TONE[d.status]}>{d.status}</Badge>
                    </TD>
                    <TD className="text-sm tabular-nums">{d.attempts}</TD>
                    <TD className="max-w-xs truncate text-xs text-muted-foreground" title={d.last_error ?? ""}>
                      {d.last_error ?? "—"}
                    </TD>
                  </TR>
                ))}
              </TBody>
            </Table>
            <Pagination
              page={page}
              pageSize={deliveries.data.page_size}
              total={deliveries.data.total}
              onPageChange={setPage}
            />
          </>
        )}
      </CardContent>
    </Card>
  );
}

export function AlertsPage() {
  const { projectId = "" } = useParams();
  const canManage = useCan("alerts:manage");
  return (
    <div className="space-y-6">
      <PageHeader
        title="Alerts"
        description="Route security events to e-mail and signed webhooks, with severity floors and quiet periods."
      />
      <ProjectTabs projectId={projectId} />
      <RulesCard projectId={projectId} canManage={canManage} />
      {canManage ? (
        <>
          <ChannelsCard projectId={projectId} />
          <DeliveriesCard projectId={projectId} />
        </>
      ) : null}
    </div>
  );
}
