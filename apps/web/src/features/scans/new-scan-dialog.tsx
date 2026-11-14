import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Radar } from "lucide-react";
import { useState } from "react";
import { useNavigate } from "react-router";

import { FormField } from "@/components/shared/form-field";
import { ErrorAlert, InlineAlert } from "@/components/shared/inline-alert";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogTrigger } from "@/components/ui/dialog";
import { Select } from "@/components/ui/input";
import { listAssets, type Asset } from "@/features/assets/api";

import { listScanners, requestScan, scansKeys, type ScannerInfo } from "./api";

function eligible(asset: Asset, scanner: ScannerInfo): boolean {
  return asset.eligibility[scanner.technique] && scanner.supported_asset_types.includes(asset.type);
}

export function NewScanDialog({ projectId, disabled }: { projectId: string; disabled?: boolean }) {
  const [open, setOpen] = useState(false);
  const [assetId, setAssetId] = useState("");
  const [scannerName, setScannerName] = useState("");
  const [profile, setProfile] = useState("");
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const scanners = useQuery({ queryKey: scansKeys.scanners, queryFn: listScanners, enabled: open, staleTime: Infinity });
  const assets = useQuery({
    queryKey: ["assets", projectId, "scan-targets"],
    queryFn: () => listAssets(projectId, { page: 1, type: "", status: "active", search: "" }),
    enabled: open,
  });
  const asset = assets.data?.items.find((a) => a.id === assetId);
  const available = (scanners.data ?? []).filter((s) => (asset ? eligible(asset, s) : false));
  const scanner = available.find((s) => s.name === scannerName);
  const profiles = scanner && asset ? scanner.profiles.filter((p) => asset.eligibility[p.technique]) : [];

  const mutation = useMutation({
    mutationFn: () => requestScan(projectId, { asset_id: assetId, scanner: scannerName, profile }),
    onSuccess: async (job) => {
      await queryClient.invalidateQueries({ queryKey: scansKeys.all(projectId) });
      setOpen(false);
      void navigate(`/projects/${projectId}/scans/${job.id}`);
    },
  });

  const reset = () => {
    setAssetId("");
    setScannerName("");
    setProfile("");
    mutation.reset();
  };

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        setOpen(next);
        if (!next) reset();
      }}
    >
      <DialogTrigger asChild>
        <Button size="sm" disabled={disabled}>
          <Radar aria-hidden="true" />
          New scan
        </Button>
      </DialogTrigger>
      <DialogContent
        title="New scan"
        description="Only assets with a current authorization are listed. Scope is checked again, with fresh DNS, right before the scan runs."
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
          {scanners.isError ? <ErrorAlert error={scanners.error} /> : null}
          {assets.isError ? <ErrorAlert error={assets.error} /> : null}
          <FormField label="Asset">
            <Select
              value={assetId}
              onChange={(e) => {
                setAssetId(e.target.value);
                setScannerName("");
                setProfile("");
              }}
            >
              <option value="">Select an asset…</option>
              {(assets.data?.items ?? [])
                .filter((a) => a.eligibility.passive)
                .map((a) => (
                  <option key={a.id} value={a.id}>
                    {a.value}
                  </option>
                ))}
            </Select>
          </FormField>
          {asset && available.length === 0 ? (
            <InlineAlert>No scanner is permitted for this asset under its current authorizations.</InlineAlert>
          ) : null}
          <FormField label="Scanner" hint={scanner?.description}>
            <Select
              value={scannerName}
              disabled={!asset}
              onChange={(e) => {
                const next = available.find((s) => s.name === e.target.value);
                setScannerName(e.target.value);
                setProfile(next?.default_profile ?? "");
              }}
            >
              <option value="">Select a scanner…</option>
              {available.map((s) => (
                <option key={s.name} value={s.name}>
                  {s.name} ({s.technique})
                </option>
              ))}
            </Select>
          </FormField>
          <FormField label="Profile" hint={scanner?.profiles.find((p) => p.name === profile)?.description}>
            <Select
              value={profile}
              disabled={!scanner}
              onChange={(e) => {
                setProfile(e.target.value);
              }}
            >
              {profiles.map((p) => (
                <option key={p.name} value={p.name}>
                  {p.name}
                  {p.technique === scanner?.technique ? "" : ` (${p.technique})`}
                </option>
              ))}
            </Select>
          </FormField>
          <div className="flex justify-end">
            <Button type="submit" disabled={!scanner || !profile || mutation.isPending}>
              {mutation.isPending ? "Queuing…" : "Start scan"}
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}
