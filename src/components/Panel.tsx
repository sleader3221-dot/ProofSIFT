import { cn } from "@/lib/utils";
import type { ReactNode } from "react";

export function Panel({
  title,
  subtitle,
  children,
  className,
  action,
  accent,
}: {
  title?: string;
  subtitle?: string;
  children: ReactNode;
  className?: string;
  action?: ReactNode;
  accent?: "confirmed" | "inferred" | "blocked";
}) {
  const accentBar =
    accent === "confirmed"
      ? "bg-confirmed"
      : accent === "inferred"
        ? "bg-inferred"
        : accent === "blocked"
          ? "bg-blocked"
          : "bg-border";
  return (
    <section
      className={cn(
        "relative overflow-hidden rounded-lg border border-border bg-card/60 backdrop-blur",
        className,
      )}
    >
      <div className={cn("absolute left-0 top-0 h-full w-[2px]", accentBar)} />
      {(title || action) && (
        <header className="flex items-center justify-between border-b border-border/60 px-4 py-2.5">
          <div>
            {title && (
              <h3 className="font-mono text-[11px] uppercase tracking-[0.22em] text-muted-foreground">
                {title}
              </h3>
            )}
            {subtitle && <p className="mt-0.5 text-sm font-medium text-foreground">{subtitle}</p>}
          </div>
          {action}
        </header>
      )}
      <div className="p-4">{children}</div>
    </section>
  );
}
