import { Link } from "react-router";

import { Button } from "@/components/ui/button";

export function NotFoundPage() {
  return (
    <div className="flex flex-col items-start gap-4 py-16">
      <p className="font-mono text-xs uppercase tracking-widest text-muted-foreground">404</p>
      <h1 className="text-xl font-semibold">Page not found</h1>
      <p className="text-sm text-muted-foreground">The requested page does not exist.</p>
      <Button asChild variant="outline" size="sm">
        <Link to="/">Back to System Status</Link>
      </Button>
    </div>
  );
}
