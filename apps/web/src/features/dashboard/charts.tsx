import type { ReactNode } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  Line,
  Rectangle,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
  type BarShapeProps,
  type TooltipContentProps,
  type TooltipValueType,
} from "recharts";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { SEVERITIES, type Severity } from "@/features/findings/api";

import { AXIS_TEXT, GRID, REMEDIATION_COLORS, SCAN_STATUS_COLORS, SERIES_PRIMARY, SEVERITY_COLORS } from "./colors";
import { shortDay, type Dashboard } from "./api";

const AXIS = { stroke: GRID, tick: { fill: AXIS_TEXT, fontSize: 11 }, tickLine: false } as const;
const SURFACE = "#0c141e";
const ORDER: readonly Severity[] = SEVERITIES;

const capitalize = (value: string) => value.charAt(0).toUpperCase() + value.slice(1);

/** Chart card: title, one-line takeaway, the plot, and a data table for screen readers and print. */
export function ChartCard({
  title,
  description,
  summary,
  table,
  children,
}: {
  title: string;
  description: string;
  summary: string;
  table: { headers: string[]; rows: (string | number)[][] };
  children: ReactNode;
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>{title}</CardTitle>
        <CardDescription>{description}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        <figure className="m-0">
          <div role="img" aria-label={`${title}: ${summary}`} className="h-56 w-full">
            {children}
          </div>
          <figcaption className="sr-only">{summary}</figcaption>
        </figure>
        <details className="text-xs text-muted-foreground">
          <summary className="cursor-pointer select-none hover:text-foreground">Show data table</summary>
          <table className="mt-2 w-full text-left" aria-label={`${title} data`}>
            <thead>
              <tr>
                {table.headers.map((h) => (
                  <th key={h} scope="col" className="py-1 pr-3 font-medium">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {table.rows.map((row, r) => (
                <tr key={r} className="border-t border-border">
                  {row.map((cell, c) => (
                    <td key={c} className="py-1 pr-3 tabular-nums">
                      {cell}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </details>
      </CardContent>
    </Card>
  );
}

function ChartTooltip({ active, payload, label }: TooltipContentProps<TooltipValueType, string | number>) {
  if (!active || payload.length === 0) return null;
  return (
    <div className="rounded-md border border-border bg-surface-raised px-3 py-2 text-xs shadow-lg">
      <p className="mb-1 font-medium text-foreground">{String(label)}</p>
      <ul className="space-y-0.5">
        {payload.map((entry) => (
          <li key={String(entry.dataKey)} className="flex items-center gap-2 text-muted-foreground">
            <span aria-hidden="true" className="size-2 rounded-full" style={{ background: entry.color }} />
            <span>{entry.name}</span>
            <span className="ml-auto pl-3 font-medium text-foreground tabular-nums">{String(entry.value)}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

const legend = (value: string) => <span className="text-xs text-muted-foreground">{value}</span>;

export function RiskDistributionChart({ data }: { data: Dashboard["risk_distribution"] }) {
  const rows = ORDER.map((band) => ({ band, label: capitalize(band), count: data[band] }));
  const total = rows.reduce((sum, r) => sum + r.count, 0);
  return (
    <ChartCard
      title="Risk distribution"
      description="Active findings by risk band."
      summary={rows.map((r) => `${r.label} ${String(r.count)}`).join(", ")}
      table={{ headers: ["Risk band", "Active findings"], rows: rows.map((r) => [r.label, r.count]) }}
    >
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={rows} layout="vertical" margin={{ top: 4, right: 32, bottom: 4, left: 8 }} barCategoryGap="28%">
          <CartesianGrid horizontal={false} stroke={GRID} />
          <XAxis type="number" allowDecimals={false} {...AXIS} domain={[0, total === 0 ? 1 : "auto"]} />
          <YAxis type="category" dataKey="label" width={64} {...AXIS} axisLine={false} />
          <Tooltip cursor={{ fill: "rgba(255,255,255,0.04)" }} content={ChartTooltip} />
          <Bar
            dataKey="count"
            name="Active findings"
            radius={[0, 4, 4, 0]}
            maxBarSize={18}
            label={{ position: "right", fill: AXIS_TEXT, fontSize: 11 }}
            isAnimationActive={false}
            // Colour comes from each bar's own band (replaces the deprecated <Cell>).
            shape={(props: BarShapeProps) => (
              <Rectangle {...props} fill={SEVERITY_COLORS[(props.payload as { band: Severity }).band]} />
            )}
          />
        </BarChart>
      </ResponsiveContainer>
    </ChartCard>
  );
}

export function PostureTrendChart({ data }: { data: Dashboard["posture_trend"] }) {
  const rows = data.map((d) => ({ ...d, label: shortDay(d.day) }));
  const last = rows.at(-1);
  return (
    <ChartCard
      title="Posture trend"
      description="Daily project risk posture (worst project), last 30 days. Lower is better."
      summary={
        last ? `${String(rows.length)} daily points, latest ${String(last.score)} of 100` : "No daily snapshots yet"
      }
      table={{ headers: ["Day", "Posture score"], rows: rows.map((r) => [r.day, r.score]) }}
    >
      {rows.length < 2 ? (
        <p className="flex h-full items-center justify-center text-sm text-muted-foreground">
          The trend appears after two daily snapshots.
        </p>
      ) : (
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={rows} margin={{ top: 8, right: 16, bottom: 4, left: -16 }}>
            <CartesianGrid vertical={false} stroke={GRID} />
            <XAxis dataKey="label" {...AXIS} minTickGap={24} />
            <YAxis domain={[0, 100]} ticks={[0, 25, 50, 75, 100]} {...AXIS} axisLine={false} />
            <Tooltip cursor={{ stroke: AXIS_TEXT, strokeDasharray: "3 3" }} content={ChartTooltip} />
            <Line
              type="monotone"
              dataKey="score"
              name="Posture score"
              stroke={SERIES_PRIMARY}
              strokeWidth={2}
              dot={false}
              activeDot={{ r: 5, stroke: SURFACE, strokeWidth: 2 }}
              isAnimationActive={false}
            />
          </LineChart>
        </ResponsiveContainer>
      )}
    </ChartCard>
  );
}

export function ScanActivityChart({ data }: { data: Dashboard["scan_activity"] }) {
  const rows = data.map((d) => ({ ...d, label: shortDay(d.day) }));
  const totals = rows.reduce(
    (acc, r) => ({ completed: acc.completed + r.completed, failed: acc.failed + r.failed, cancelled: acc.cancelled + r.cancelled }),
    { completed: 0, failed: 0, cancelled: 0 },
  );
  const series = [
    { key: "completed", name: "Completed" },
    { key: "failed", name: "Failed" },
    { key: "cancelled", name: "Cancelled" },
  ] as const;
  return (
    <ChartCard
      title="Scan activity"
      description="Scans per day by outcome, last 14 days."
      summary={`${String(totals.completed)} completed, ${String(totals.failed)} failed, ${String(totals.cancelled)} cancelled`}
      table={{
        headers: ["Day", "Completed", "Failed", "Cancelled"],
        rows: rows.map((r) => [r.day, r.completed, r.failed, r.cancelled]),
      }}
    >
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={rows} margin={{ top: 8, right: 8, bottom: 4, left: -16 }} barCategoryGap="30%">
          <CartesianGrid vertical={false} stroke={GRID} />
          <XAxis dataKey="label" {...AXIS} minTickGap={16} />
          <YAxis allowDecimals={false} {...AXIS} axisLine={false} />
          <Tooltip cursor={{ fill: "rgba(255,255,255,0.04)" }} content={ChartTooltip} />
          <Legend formatter={legend} iconType="circle" iconSize={8} />
          {series.map((s, index) => (
            <Bar
              key={s.key}
              dataKey={s.key}
              name={s.name}
              stackId="scans"
              fill={SCAN_STATUS_COLORS[s.key]}
              stroke={SURFACE}
              strokeWidth={2}
              maxBarSize={18}
              radius={index === series.length - 1 ? [4, 4, 0, 0] : 0}
              isAnimationActive={false}
            />
          ))}
        </BarChart>
      </ResponsiveContainer>
    </ChartCard>
  );
}

export function RemediationChart({ data }: { data: Dashboard["remediation"] }) {
  const rows = data.weekly.map((w) => ({ ...w, label: `Wk ${shortDay(w.week)}` }));
  const opened = rows.reduce((s, r) => s + r.opened, 0);
  const resolved = rows.reduce((s, r) => s + r.resolved, 0);
  return (
    <ChartCard
      title="Remediation progress"
      description="Findings first seen vs. resolved per week, last 8 weeks."
      summary={`${String(opened)} opened and ${String(resolved)} resolved over 8 weeks`}
      table={{ headers: ["Week of", "Opened", "Resolved"], rows: rows.map((r) => [r.week, r.opened, r.resolved]) }}
    >
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={rows} margin={{ top: 8, right: 8, bottom: 4, left: -16 }} barGap={2} barCategoryGap="28%">
          <CartesianGrid vertical={false} stroke={GRID} />
          <XAxis dataKey="label" {...AXIS} minTickGap={12} />
          <YAxis allowDecimals={false} {...AXIS} axisLine={false} />
          <Tooltip cursor={{ fill: "rgba(255,255,255,0.04)" }} content={ChartTooltip} />
          <Legend formatter={legend} iconType="circle" iconSize={8} />
          <Bar dataKey="opened" name="Opened" fill={REMEDIATION_COLORS.opened} radius={[4, 4, 0, 0]} maxBarSize={14} isAnimationActive={false} />
          <Bar dataKey="resolved" name="Resolved" fill={REMEDIATION_COLORS.resolved} radius={[4, 4, 0, 0]} maxBarSize={14} isAnimationActive={false} />
        </BarChart>
      </ResponsiveContainer>
    </ChartCard>
  );
}

export function ExposureChart({ data }: { data: Dashboard["assets_by_exposure"] }) {
  const rows = ["external", "internal", "unknown"].map((key) => ({
    key,
    label: capitalize(key),
    count: data[key] ?? 0,
  }));
  return (
    <ChartCard
      title="Asset exposure"
      description="Active assets by network exposure."
      summary={rows.map((r) => `${r.label} ${String(r.count)}`).join(", ")}
      table={{ headers: ["Exposure", "Assets"], rows: rows.map((r) => [r.label, r.count]) }}
    >
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={rows} layout="vertical" margin={{ top: 4, right: 32, bottom: 4, left: 8 }} barCategoryGap="34%">
          <CartesianGrid horizontal={false} stroke={GRID} />
          <XAxis type="number" allowDecimals={false} {...AXIS} />
          <YAxis type="category" dataKey="label" width={64} {...AXIS} axisLine={false} />
          <Tooltip cursor={{ fill: "rgba(255,255,255,0.04)" }} content={ChartTooltip} />
          <Bar
            dataKey="count"
            name="Assets"
            fill={SERIES_PRIMARY}
            radius={[0, 4, 4, 0]}
            maxBarSize={18}
            label={{ position: "right", fill: AXIS_TEXT, fontSize: 11 }}
            isAnimationActive={false}
          />
        </BarChart>
      </ResponsiveContainer>
    </ChartCard>
  );
}
