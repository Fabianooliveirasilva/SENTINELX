import { ChevronLeft, ChevronRight } from "lucide-react";

import { Button } from "@/components/ui/button";

interface PaginationProps {
  page: number;
  pageSize: number;
  total: number;
  onPageChange: (page: number) => void;
}

export function Pagination({ page, pageSize, total, onPageChange }: PaginationProps) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  const first = total === 0 ? 0 : (page - 1) * pageSize + 1;
  const last = Math.min(total, page * pageSize);
  return (
    <nav aria-label="Pagination" className="flex items-center justify-between gap-4 pt-4">
      <p className="text-xs text-muted-foreground">
        {first}–{last} of {total}
      </p>
      <div className="flex items-center gap-1">
        <Button
          variant="ghost"
          size="sm"
          onClick={() => {
            onPageChange(page - 1);
          }}
          disabled={page <= 1}
          aria-label="Previous page"
        >
          <ChevronLeft aria-hidden="true" />
        </Button>
        <span className="font-mono text-xs text-muted-foreground">
          {page} / {pages}
        </span>
        <Button
          variant="ghost"
          size="sm"
          onClick={() => {
            onPageChange(page + 1);
          }}
          disabled={page >= pages}
          aria-label="Next page"
        >
          <ChevronRight aria-hidden="true" />
        </Button>
      </div>
    </nav>
  );
}
