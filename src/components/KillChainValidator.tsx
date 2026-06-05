import { useEffect, useState } from "react";
import { AlertTriangle, CheckCircle2, RadioTower, ShieldCheck } from "lucide-react";
import { Panel } from "@/components/Panel";
import { cn } from "@/lib/utils";

const phases = [
  { id: "initial", label: "Initial Access", status: "observed", detail: "phishing vector unknown" },
  { id: "execution", label: "Execution", status: "gap", detail: "missing predecessor" },
  { id: "persistence", label: "Persistence", status: "active", detail: "HKCU\\Run\\Updater" },
  { id: "c2", label: "C2", status: "active", detail: "203.0.113.50:443" },
] as const;

type ValidatorStage = "gap" | "resolving" | "complete";

function formatClock(date: Date) {
  return date.toISOString().replace(/\.\d{3}Z$/, "Z");
}

export function KillChainValidator() {
  const [stage, setStage] = useState<ValidatorStage>("gap");
  const [updatedAt, setUpdatedAt] = useState<string>("");

  useEffect(() => {
    const stages: ValidatorStage[] = ["gap", "resolving", "complete"];
    let index = 0;
    const applyStage = () => {
      setStage(stages[index % stages.length]);
      setUpdatedAt(formatClock(new Date()));
      index += 1;
    };

    applyStage();
    const id = window.setInterval(applyStage, 2400);
    return () => {
      window.clearInterval(id);
    };
  }, []);

  const resolved = stage === "complete";

  return (
    <Panel
      title="kill chain validator"
      subtitle="MITRE sequence critic simulation"
      accent={resolved ? "confirmed" : "inferred"}
    >
      <div className="grid gap-3 md:grid-cols-4">
        {phases.map((phase, index) => {
          const isExecution = phase.id === "execution";
          const active =
            phase.status === "active" ||
            phase.status === "observed" ||
            (isExecution && stage !== "gap");
          const gap = isExecution && stage === "gap";
          return (
            <div
              key={phase.id}
              className={cn(
                "relative overflow-hidden rounded-lg border bg-background/50 p-3 transition duration-500",
                active &&
                  "border-confirmed/60 bg-confirmed/10 shadow-[0_0_28px_-18px_var(--confirmed)]",
                gap && "glow-blocked animate-pulse-blocked border-blocked/70 bg-blocked/10",
              )}
            >
              <div className="flex items-center justify-between">
                <span className="font-mono text-[10px] uppercase tracking-[0.22em] text-muted-foreground">
                  #{index + 1}
                </span>
                {gap ? (
                  <AlertTriangle className="h-4 w-4 text-blocked" />
                ) : (
                  <CheckCircle2 className="h-4 w-4 text-confirmed" />
                )}
              </div>
              <div
                className={cn(
                  "mt-3 text-sm font-semibold",
                  gap ? "text-blocked" : active ? "text-confirmed" : "text-foreground",
                )}
              >
                {phase.label}
              </div>
              <div className="mt-1 font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
                {phase.detail}
              </div>
              <div
                className={cn(
                  "mt-3 h-1 rounded-full",
                  gap ? "bg-blocked" : active ? "bg-confirmed" : "bg-muted",
                )}
              />
            </div>
          );
        })}
      </div>

      <div className="mt-4 rounded-md border border-border bg-[var(--terminal-bg)] p-3 font-mono text-xs">
        <div className="flex items-start gap-2">
          {resolved ? (
            <ShieldCheck className="mt-0.5 h-4 w-4 text-confirmed" />
          ) : (
            <RadioTower className="mt-0.5 h-4 w-4 text-inferred" />
          )}
          <div>
            <div className={resolved ? "text-confirmed" : "text-inferred"}>
              {resolved
                ? "CRITIC RESOLUTION COMPLETE"
                : stage === "resolving"
                  ? "CRITIC COLLECTING EXECUTION PROOF"
                  : "CRITIC ALERT: PRECEDING REQUIREMENT GAP"}
            </div>
            <div className="mt-1 text-muted-foreground">
              {resolved
                ? "Execution proof found via disk_prefetch + windows_process_creation. Persistence and C2 are now sequence-valid."
                : stage === "resolving"
                  ? "Disk prefetch and process-creation evidence are being promoted into the sequence gate."
                  : "C2 and Persistence are active, but Execution is flashing until corroborating evidence closes the sequence gap."}
            </div>
            {updatedAt && (
              <div className="mt-2 text-[10px] uppercase tracking-widest text-muted-foreground">
                live update {updatedAt}
              </div>
            )}
          </div>
        </div>
      </div>
    </Panel>
  );
}
