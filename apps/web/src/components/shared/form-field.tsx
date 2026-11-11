import { cloneElement, useId, type ReactElement, type ReactNode } from "react";

import { Label } from "@/components/ui/input";

interface ControlProps {
  id?: string;
  "aria-invalid"?: boolean;
  "aria-describedby"?: string;
}

interface FormFieldProps {
  label: string;
  error?: string | undefined;
  hint?: ReactNode;
  children: ReactElement<ControlProps>;
}

/** Associates a label, hint and validation message with a single form control. */
export function FormField({ label, error, hint, children }: FormFieldProps) {
  const id = useId();
  const messageId = `${id}-message`;
  const controlProps: ControlProps = { id };
  if (error) controlProps["aria-invalid"] = true;
  if (error || hint) controlProps["aria-describedby"] = messageId;
  return (
    <div className="space-y-1.5">
      <Label htmlFor={id}>{label}</Label>
      {cloneElement(children, controlProps)}
      {error ? (
        <p id={messageId} className="text-xs text-status-down">
          {error}
        </p>
      ) : hint ? (
        <p id={messageId} className="text-xs text-muted-foreground">
          {hint}
        </p>
      ) : null}
    </div>
  );
}
