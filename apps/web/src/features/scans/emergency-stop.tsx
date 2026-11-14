import { useMutation, useQueryClient } from "@tanstack/react-query";
import { OctagonX } from "lucide-react";
import { useState } from "react";

import { FormField } from "@/components/shared/form-field";
import { ErrorAlert } from "@/components/shared/inline-alert";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogTrigger } from "@/components/ui/dialog";
import { Textarea } from "@/components/ui/input";
import { formatDateTime } from "@/lib/format";

import { emergencyStop, resumeScanning, scansKeys, type ScanControls } from "./api";

export function HaltedBanner({ controls }: { controls: ScanControls }) {
  return (
    <div role="alert" className="rounded-md border border-status-down/30 bg-status-down/10 px-4 py-3 text-sm text-status-down">
      <p className="font-medium">Scanning is halted platform-wide (emergency stop).</p>
      <p className="mt-1">
        {controls.reason ?? "No reason recorded."} — {controls.updated_by ?? "unknown"}, {formatDateTime(controls.updated_at)}
      </p>
    </div>
  );
}

export function EmergencyControls({ controls }: { controls: ScanControls }) {
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState("");
  const queryClient = useQueryClient();
  const refresh = async () => {
    await queryClient.invalidateQueries({ queryKey: scansKeys.controls });
    await queryClient.invalidateQueries({ queryKey: ["scans"] });
  };
  const stop = useMutation({
    mutationFn: () => emergencyStop(reason),
    onSuccess: async () => {
      setOpen(false);
      setReason("");
      await refresh();
    },
  });
  const resume = useMutation({ mutationFn: resumeScanning, onSuccess: refresh });

  if (controls.halted) {
    return (
      <>
        {resume.isError ? <ErrorAlert error={resume.error} /> : null}
        <Button
          size="sm"
          variant="outline"
          disabled={resume.isPending}
          onClick={() => {
            resume.mutate();
          }}
        >
          Resume scanning
        </Button>
      </>
    );
  }
  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        setOpen(next);
        if (!next) stop.reset();
      }}
    >
      <DialogTrigger asChild>
        <Button size="sm" variant="outline" className="border-status-down/40 text-status-down">
          <OctagonX aria-hidden="true" />
          Emergency stop
        </Button>
      </DialogTrigger>
      <DialogContent
        title="Emergency stop"
        description="Cancels every pending, queued and running scan on the platform and blocks new scans until an administrator resumes scanning."
      >
        <form
          noValidate
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault();
            stop.mutate();
          }}
        >
          {stop.isError ? <ErrorAlert error={stop.error} /> : null}
          <FormField label="Reason" hint="Recorded in the audit log.">
            <Textarea
              value={reason}
              maxLength={500}
              onChange={(e) => {
                setReason(e.target.value);
              }}
            />
          </FormField>
          <div className="flex justify-end">
            <Button type="submit" disabled={reason.trim().length < 3 || stop.isPending}>
              {stop.isPending ? "Stopping…" : "Stop all scans"}
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}
