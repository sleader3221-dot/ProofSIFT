import { createFileRoute } from "@tanstack/react-router";
import { Panel } from "@/components/Panel";
import {
  tacticOrder,
  observedTactics,
  sequenceRecommendations,
  techniqueToTactic,
} from "@/lib/proofsift-data";
import { CheckCircle2, Circle, AlertTriangle } from "lucide-react";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/mitre")({
  head: () => ({ meta: [{ title: "MITRE ATT&CK Sequence · ProofSIFT" }] }),
  component: MitrePage,
});

function MitrePage() {
  return (
    <div className="space-y-6 p-6">
      <div>
        <div className="font-mono text-[11px] uppercase tracking-[0.25em] text-confirmed">
          // MitreSequenceValidator
        </div>
        <h1 className="mt-1 text-3xl font-semibold tracking-tight">ATT&CK Behavioral Sequence</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          12-tactic kill chain. PRECEDING_REQUIREMENTS gate every high-impact tactic — a missing
          predecessor triggers a<span className="text-inferred"> SequenceRecommendation</span> with
          concrete tools and forensic paths.
        </p>
      </div>

      <Panel
        title="kill chain"
        subtitle="Tactics observed in case proofsift-demo-001"
        accent="confirmed"
      >
        <ol className="grid gap-2 md:grid-cols-2 xl:grid-cols-3">
          {tacticOrder.map((t, i) => {
            const o = observedTactics[t];
            return (
              <li
                key={t}
                className={cn(
                  "flex items-start gap-3 rounded-md border bg-background/40 p-3 transition",
                  o.detected ? "border-confirmed/50" : "border-border",
                )}
              >
                {o.detected ? (
                  <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-confirmed" />
                ) : (
                  <Circle className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground/60" />
                )}
                <div className="min-w-0 flex-1">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-sm font-medium text-foreground">{t}</span>
                    <span className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
                      #{i + 1}
                    </span>
                  </div>
                  <div className="mt-1 flex flex-wrap gap-1 font-mono text-[10px] text-muted-foreground">
                    {o.via.length === 0 ? (
                      <span>—</span>
                    ) : (
                      o.via.map((s) => (
                        <span
                          key={s}
                          className="rounded border border-border/60 bg-muted/30 px-1.5 py-0.5 text-confirmed/90"
                        >
                          {s}
                        </span>
                      ))
                    )}
                  </div>
                </div>
              </li>
            );
          })}
        </ol>
      </Panel>

      <div className="grid gap-6 lg:grid-cols-[1.2fr_1fr]">
        <Panel
          title="sequence recommendations"
          subtitle="Gaps detected by critic — and how they were resolved"
          accent="inferred"
        >
          {sequenceRecommendations.map((r) => (
            <div key={r.id} className="rounded-md border border-inferred/40 bg-inferred/5 p-4">
              <div className="flex items-start gap-2">
                <AlertTriangle className="mt-0.5 h-4 w-4 text-inferred" />
                <div className="min-w-0 flex-1">
                  <div className="font-mono text-[11px] uppercase tracking-widest text-inferred">
                    {r.gap_type}
                  </div>
                  <p className="mt-1 text-sm text-foreground">{r.reason}</p>
                  <div className="mt-3 grid gap-3 sm:grid-cols-2">
                    <div>
                      <div className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
                        recommended tools
                      </div>
                      <ul className="mt-1 space-y-0.5 font-mono text-[11px] text-confirmed">
                        {r.recommended_tools.map((t) => (
                          <li key={t}>$ {t}</li>
                        ))}
                      </ul>
                    </div>
                    <div>
                      <div className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
                        recommended paths
                      </div>
                      <ul className="mt-1 space-y-0.5 font-mono text-[11px] text-foreground/80">
                        {r.recommended_paths.map((p) => (
                          <li key={p} className="truncate">
                            {p}
                          </li>
                        ))}
                      </ul>
                    </div>
                  </div>
                  <div className="mt-3 flex items-center gap-2 font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
                    <span>target → {r.target_claim_id}</span>
                    <span>priority {r.priority}</span>
                    {r.resolved && (
                      <span className="rounded border border-confirmed/40 bg-confirmed/10 px-1.5 py-0.5 text-confirmed">
                        resolved iter 2
                      </span>
                    )}
                  </div>
                </div>
              </div>
            </div>
          ))}
        </Panel>

        <Panel title="technique → tactic map" subtitle="TACTIC_BY_TECHNIQUE" accent="confirmed">
          <div className="overflow-hidden rounded-md border border-border">
            <table className="w-full text-sm">
              <thead className="bg-muted/40 font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
                <tr>
                  <th className="px-3 py-2 text-left">technique</th>
                  <th className="px-3 py-2 text-left">tactic</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(techniqueToTactic).map(([k, v]) => (
                  <tr key={k} className="border-t border-border/60">
                    <td className="px-3 py-2 font-mono text-xs text-confirmed">{k}</td>
                    <td className="px-3 py-2 text-foreground">{v}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      </div>
    </div>
  );
}
