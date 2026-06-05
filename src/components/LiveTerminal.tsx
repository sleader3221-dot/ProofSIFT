import { useEffect, useRef, useState } from "react";
import { Play, Square } from "lucide-react";
import { terminalScript } from "@/lib/proofsift-data";
import { cn } from "@/lib/utils";

const toneClass = {
  ok: "text-confirmed",
  warn: "text-inferred",
  err: "text-blocked",
  info: "text-cyan-300",
  dim: "text-muted-foreground",
} as const;

export function LiveTerminal() {
  const [lines, setLines] = useState<typeof terminalScript>([]);
  const [running, setRunning] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!running) return;
    let i = 0;
    setLines([]);
    const id = setInterval(() => {
      const nextLine = terminalScript[i];
      if (!nextLine) {
        clearInterval(id);
        setRunning(false);
        return;
      }

      setLines((prev) => [...prev, nextLine]);
      i += 1;
      if (i >= terminalScript.length) {
        clearInterval(id);
        setRunning(false);
      }
    }, 220);
    return () => clearInterval(id);
  }, [running]);

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: "smooth" });
  }, [lines]);

  return (
    <div className="rounded-lg border border-border bg-[var(--terminal-bg)] shadow-2xl">
      <div className="flex items-center justify-between border-b border-border/60 px-3 py-2">
        <div className="flex items-center gap-2">
          <span className="h-2.5 w-2.5 rounded-full bg-blocked" />
          <span className="h-2.5 w-2.5 rounded-full bg-inferred" />
          <span className="h-2.5 w-2.5 rounded-full bg-confirmed" />
          <span className="ml-3 font-mono text-[11px] uppercase tracking-widest text-muted-foreground">
            proofsift@cyber-ops ~ /case/proofsift-demo-001
          </span>
        </div>
        <button
          onClick={() => setRunning((r) => !r)}
          className={cn(
            "inline-flex items-center gap-1.5 rounded-md border px-3 py-1 font-mono text-[11px] uppercase tracking-widest transition",
            running
              ? "border-blocked/50 bg-blocked/10 text-blocked"
              : "border-confirmed/50 bg-confirmed/10 text-confirmed hover:bg-confirmed/20",
          )}
        >
          {running ? (
            <>
              <Square className="h-3 w-3" /> running
            </>
          ) : (
            <>
              <Play className="h-3 w-3" /> run live case
            </>
          )}
        </button>
      </div>
      <div
        ref={scrollRef}
        className="h-[420px] overflow-auto px-4 py-3 font-mono text-[12.5px] leading-relaxed"
      >
        {lines.length === 0 && !running && (
          <p className="text-muted-foreground">
            $ click <span className="text-confirmed">"run live case"</span> to stream the
            self-correcting investigator…
          </p>
        )}
        {lines.filter(Boolean).map((l, idx) => (
          <div key={idx} className={cn("whitespace-pre", toneClass[l.tone ?? "dim"])}>
            {l.text || "\u00a0"}
          </div>
        ))}
        {running && (
          <span className="inline-block h-3 w-2 bg-confirmed align-middle animate-blink" />
        )}
      </div>
    </div>
  );
}
