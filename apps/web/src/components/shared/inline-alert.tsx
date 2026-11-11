import { AlertTriangle, CheckCircle2 } from "lucide-react";
import type { ReactNode } from "react";

import { ApiError } from "@/lib/api-client";
import { cn } from "@/lib/utils";

export function InlineAlert({
  tone = "error",
  children,
}: {
  tone?: "error" | "success";
  children: ReactNode;
}) {
  const Icon = tone === "error" ? AlertTriangle : CheckCircle2;
  return (
    <div
      role={tone === "error" ? "alert" : "status"}
      className={cn(
        "flex items-start gap-2 rounded-md border px-3 py-2 text-sm",
        tone === "error"
          ? "border-status-down/30 bg-status-down/10 text-status-down"
          : "border-status-ok/30 bg-status-ok/10 text-status-ok",
      )}
    >
      <Icon className="mt-0.5 size-4 shrink-0" aria-hidden="true" />
      <div>{children}</div>
    </div>
  );
}

export function ErrorAlert({ error }: { error: unknown }) {
  if (!error) return null;
  const message = error instanceof Error ? error.message : "Something went wrong.";
  const requestId = error instanceof ApiError ? error.requestId : null;
  return (
    <InlineAlert>
      {message}
      {requestId ? (
        <span className="mt-0.5 block font-mono text-[11px] opacity-80">Request ID: {requestId}</span>
      ) : null}
    </InlineAlert>
  );
}
