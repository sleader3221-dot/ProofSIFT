import { createFileRoute } from "@tanstack/react-router";
import { Panel } from "@/components/Panel";
import { benchmark } from "@/lib/proofsift-data";
import { Check, X } from "lucide-react";

export const Route = createFileRoute("/benchmark")({
  head: () => ({ meta: [{ title: "Accuracy Benchmark · ProofSIFT" }] }),
  component: BenchmarkPage,
});

const matrix = `======================================================================
          PROOFSIFT ACCURACY BENCHMARK HARNESS
======================================================================
 FORENSIC DETECTION RESULTS:
   Forensic True Positives Caught : 2 / 2  (100.0%)
   False Positive Claims Raised   : 0      (0.00%)
   Hallucinated Items Intercepted : 14     (Enforced via Critic)
   Anti-Forensics Anomalies Found : 2 / 2  (100.0%)
   Clock-Drift Adjustments Applied: 1 / 1  (120s Normalized)
   Evidence Spoliation Attempts   : 0 Writes Allowed (2 Blocked by Policy)
 SYSTEM METRICS:
   Total Execution Runtime        : 0.15 seconds
   Final Benchmark Accuracy Score : 100.0%  [PERFECT MATURATION]
======================================================================`;

function Stat({
  label,
  value,
  sub,
  accent = "confirmed",
}: {
  label: string;
  value: string;
  sub?: string;
  accent?: "confirmed" | "inferred" | "blocked";
}) {
  const color =
    accent === "blocked"
      ? "text-blocked"
      : accent === "inferred"
        ? "text-inferred"
        : "text-confirmed";
  return (
    <div className="rounded-lg border border-border bg-card/60 p-4">
      <div className="font-mono text-[10px] uppercase tracking-[0.22em] text-muted-foreground">
        {label}
      </div>
      <div className={`mt-2 font-mono text-3xl font-semibold ${color}`}>{value}</div>
      {sub && <div className="mt-1 text-[11px] text-muted-foreground">{sub}</div>}
    </div>
  );
}

function BenchmarkPage() {
  return (
    <div className="space-y-6 p-6">
      <div>
        <div className="font-mono text-[11px] uppercase tracking-[0.25em] text-confirmed">
          // validation suite
        </div>
        <h1 className="mt-1 text-3xl font-semibold tracking-tight">ProofSIFT Accuracy Benchmark</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Ground-truth scoring against the demo case — precision, recall, and integrity guarantees.
        </p>
      </div>

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <Stat
          label="True Positives"
          value={`${benchmark.truePositives.pct}%`}
          sub={`${benchmark.truePositives.value} / ${benchmark.truePositives.total}`}
        />
        <Stat
          label="False Positives"
          value={`${benchmark.falsePositives.pct}%`}
          sub={`${benchmark.falsePositives.value} / ${benchmark.falsePositives.total}`}
        />
        <Stat
          label="Hallucinations Intercepted"
          value={String(benchmark.hallucinationsIntercepted)}
          sub="enforced via Critic"
          accent="inferred"
        />
        <Stat
          label="Spoliation Writes"
          value={`${benchmark.spoliationBlocked.allowed} / ${benchmark.spoliationBlocked.blocked + benchmark.spoliationBlocked.allowed}`}
          sub={`${benchmark.spoliationBlocked.blocked} blocked by policy`}
          accent="blocked"
        />
      </div>

      <Panel title="benchmark matrix" subtitle="Raw harness output" accent="confirmed">
        <pre className="overflow-x-auto rounded-md border border-border bg-[var(--terminal-bg)] p-4 font-mono text-[12.5px] leading-relaxed text-confirmed">
          {matrix}
        </pre>
      </Panel>

      <div className="grid gap-6 lg:grid-cols-[1.4fr_1fr]">
        <Panel title="expected vs. detected" subtitle="6 / 6 targets hit" accent="confirmed">
          <div className="overflow-hidden rounded-md border border-border">
            <table className="w-full text-sm">
              <thead className="bg-muted/40 font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
                <tr>
                  <th className="px-3 py-2 text-left">target</th>
                  <th className="px-3 py-2 text-left">expected</th>
                  <th className="px-3 py-2 text-left">actual</th>
                  <th className="px-3 py-2 text-center">hit</th>
                </tr>
              </thead>
              <tbody>
                {benchmark.expectedTargets.map((t) => (
                  <tr key={t.name} className="border-t border-border/60">
                    <td className="px-3 py-2 text-foreground">{t.name}</td>
                    <td className="px-3 py-2 font-mono text-xs text-muted-foreground">
                      {t.expected}
                    </td>
                    <td className="px-3 py-2 font-mono text-xs text-confirmed">{t.actual}</td>
                    <td className="px-3 py-2 text-center">
                      {t.hit ? (
                        <Check className="mx-auto h-4 w-4 text-confirmed" />
                      ) : (
                        <X className="mx-auto h-4 w-4 text-blocked" />
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>

        <Panel title="missed targets" accent="blocked">
          {benchmark.missedTargets.length === 0 ? (
            <div className="rounded-md border border-confirmed/40 bg-confirmed/5 p-4 text-center">
              <div className="font-mono text-2xl font-semibold text-confirmed">0</div>
              <div className="mt-1 text-xs uppercase tracking-widest text-muted-foreground">
                missed targets
              </div>
              <div className="mt-3 font-mono text-[11px] text-confirmed">
                [ PERFECT MATURATION ]
              </div>
            </div>
          ) : null}
          <div className="mt-4 space-y-2 font-mono text-xs">
            <div className="flex items-center justify-between">
              <span className="text-muted-foreground">runtime</span>
              <span className="text-foreground">{benchmark.runtimeSeconds}s</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-muted-foreground">final score</span>
              <span className="text-confirmed">{benchmark.finalScore.toFixed(1)}%</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-muted-foreground">drift normalized</span>
              <span className="text-inferred">{benchmark.clockDrifts.label}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-muted-foreground">anomalies caught</span>
              <span className="text-inferred">
                {benchmark.antiForensicsFound.value} / {benchmark.antiForensicsFound.total}
              </span>
            </div>
          </div>
        </Panel>
      </div>
    </div>
  );
}
