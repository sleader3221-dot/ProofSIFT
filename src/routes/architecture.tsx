import { createFileRoute } from "@tanstack/react-router";
import { Panel } from "@/components/Panel";
import {
  pipelinePhases,
  iterations,
  outputArtifacts,
  integrityChecks,
  clockDriftDetail,
  antiForensicsAnomalies,
  antiForensicsThresholds,
} from "@/lib/proofsift-data";
import { ArrowRight, FileCode, Database, FileText, FileJson, CheckCircle2 } from "lucide-react";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/architecture")({
  head: () => ({ meta: [{ title: "Architecture · ProofSIFT" }] }),
  component: ArchitecturePage,
});

const outputIcon = (kind: string) =>
  kind === "sqlite"
    ? Database
    : kind === "jsonl" || kind === "json"
      ? FileJson
      : kind === "html"
        ? FileCode
        : FileText;

function ArchitecturePage() {
  return (
    <div className="space-y-6 p-6">
      <div>
        <div className="font-mono text-[11px] uppercase tracking-[0.25em] text-confirmed">
          // SelfCorrectingInvestigator
        </div>
        <h1 className="mt-1 text-3xl font-semibold tracking-tight">
          Architecture & Iteration Timeline
        </h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Deterministic Plan → Collect → Hypothesize → Verify → Correct → Report loop, capped at 3
          iterations, instrumented at every step.
        </p>
      </div>

      <Panel
        title="pipeline phases"
        subtitle="Each phase emits typed artifacts into the evidence graph"
        accent="confirmed"
      >
        <div className="flex flex-wrap items-center gap-2">
          {pipelinePhases.map((p, i) => (
            <div key={p} className="flex items-center gap-2">
              <div className="rounded-md border border-confirmed/40 bg-confirmed/10 px-3 py-1.5 font-mono text-xs uppercase tracking-widest text-confirmed">
                {i + 1}. {p}
              </div>
              {i < pipelinePhases.length - 1 && (
                <ArrowRight className="h-3.5 w-3.5 text-muted-foreground" />
              )}
            </div>
          ))}
        </div>
      </Panel>

      <Panel title="iteration timeline" subtitle="max_iterations = 3" accent="confirmed">
        <ol className="space-y-3">
          {iterations.map((it) => (
            <li
              key={it.n}
              className="grid gap-3 rounded-md border border-border bg-background/40 p-4 md:grid-cols-[80px_1fr]"
            >
              <div>
                <div className="font-mono text-3xl font-semibold text-confirmed">{it.n}</div>
                <div className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
                  iteration
                </div>
              </div>
              <div className="space-y-2">
                <div className="text-sm font-semibold text-foreground">{it.title}</div>
                <div className="flex flex-wrap gap-1">
                  {it.tools.map((t) => (
                    <span
                      key={t}
                      className="rounded border border-border/60 bg-muted/30 px-1.5 py-0.5 font-mono text-[10px] text-confirmed"
                    >
                      {t}
                    </span>
                  ))}
                </div>
                <div className="grid gap-2 sm:grid-cols-3">
                  <div>
                    <div className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
                      output
                    </div>
                    <div className="text-xs text-foreground">{it.output}</div>
                  </div>
                  <div>
                    <div className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
                      critic
                    </div>
                    <div className="text-xs text-inferred">{it.critic}</div>
                  </div>
                  <div>
                    <div className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
                      correction
                    </div>
                    <div className="text-xs text-confirmed">{it.correction}</div>
                  </div>
                </div>
              </div>
            </li>
          ))}
        </ol>
      </Panel>

      <div className="grid gap-6 lg:grid-cols-2">
        <Panel title="clock drift normalization" subtitle="ClockDriftNormalizer" accent="inferred">
          <div className="mb-3 grid grid-cols-2 gap-3 font-mono text-[11px]">
            <div className="rounded border border-border bg-background/40 p-2">
              <div className="uppercase tracking-widest text-muted-foreground">reference</div>
              <div className="text-confirmed">
                {clockDriftDetail.reference.source}.{clockDriftDetail.reference.timestamp_field}
              </div>
            </div>
            <div className="rounded border border-border bg-background/40 p-2">
              <div className="uppercase tracking-widest text-muted-foreground">candidate</div>
              <div className="text-inferred">
                {clockDriftDetail.candidate.source}.{clockDriftDetail.candidate.timestamp_field}
              </div>
            </div>
            <div className="rounded border border-border bg-background/40 p-2">
              <div className="uppercase tracking-widest text-muted-foreground">delta</div>
              <div className="text-inferred">+{clockDriftDetail.delta_seconds}s</div>
            </div>
            <div className="rounded border border-border bg-background/40 p-2">
              <div className="uppercase tracking-widest text-muted-foreground">max_abs_delta</div>
              <div className="text-foreground">{clockDriftDetail.max_abs_delta_seconds}s</div>
            </div>
          </div>
          <div className="overflow-hidden rounded-md border border-border">
            <table className="w-full text-xs">
              <thead className="bg-muted/40 font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
                <tr>
                  <th className="px-3 py-2 text-left">source</th>
                  <th className="px-3 py-2 text-left">observed_utc</th>
                  <th className="px-3 py-2 text-left">normalized_utc</th>
                  <th className="px-3 py-2 text-right">drift</th>
                </tr>
              </thead>
              <tbody>
                {clockDriftDetail.observations.map((o, i) => (
                  <tr key={i} className="border-t border-border/60 font-mono">
                    <td className="px-3 py-1.5 text-confirmed">{o.source}</td>
                    <td className="px-3 py-1.5 text-muted-foreground">{o.observed_utc}</td>
                    <td className="px-3 py-1.5 text-foreground">{o.normalized_utc}</td>
                    <td
                      className={cn(
                        "px-3 py-1.5 text-right",
                        o.drift_seconds === 0 ? "text-muted-foreground" : "text-inferred",
                      )}
                    >
                      {o.drift_seconds}s
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>

        <Panel title="anti-forensics anomalies" subtitle="AntiForensicsDetector" accent="inferred">
          <div className="mb-3 flex flex-wrap gap-2 font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
            <span className="rounded border border-border bg-muted/30 px-2 py-0.5">
              creation→exec skew ≤ {antiForensicsThresholds.max_creation_to_execution_skew_seconds}s
            </span>
            <span className="rounded border border-border bg-muted/30 px-2 py-0.5">
              mft→usn skew ≤ {antiForensicsThresholds.max_mft_to_usn_skew_seconds}s
            </span>
          </div>
          <ul className="space-y-2">
            {antiForensicsAnomalies.map((a) => (
              <li key={a.id} className="rounded-md border border-inferred/40 bg-inferred/5 p-3">
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono text-[11px] text-inferred">{a.anomaly_type}</span>
                  <span className="rounded border border-inferred/40 bg-inferred/10 px-1.5 py-0.5 font-mono text-[10px] text-inferred">
                    ×{a.multiplier}
                  </span>
                </div>
                <div className="mt-1 text-xs text-foreground">{a.details}</div>
                <div className="mt-1 font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
                  target {a.target} · severity {a.severity}
                </div>
              </li>
            ))}
          </ul>
        </Panel>
      </div>

      <div className="grid gap-6 lg:grid-cols-[1.2fr_1fr]">
        <Panel
          title="output artifacts"
          subtitle="Every run is fully reproducible from outputs/"
          accent="confirmed"
        >
          <ul className="space-y-2">
            {outputArtifacts.map((o) => {
              const Icon = outputIcon(o.kind);
              return (
                <li
                  key={o.file}
                  className="flex items-start gap-3 rounded-md border border-border bg-background/40 p-3"
                >
                  <Icon className="mt-0.5 h-4 w-4 shrink-0 text-confirmed" />
                  <div className="min-w-0 flex-1">
                    <div className="font-mono text-xs text-foreground">{o.file}</div>
                    <div className="text-xs text-muted-foreground">{o.desc}</div>
                  </div>
                  <span className="rounded border border-border bg-muted/30 px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
                    {o.kind}
                  </span>
                </li>
              );
            })}
          </ul>
        </Panel>

        <Panel
          title="evidence integrity"
          subtitle="SafePathPolicy + SHA-256 chain"
          accent="blocked"
        >
          <ul className="space-y-2">
            {integrityChecks.map((c) => (
              <li
                key={c.check}
                className="flex items-start gap-3 rounded-md border border-confirmed/30 bg-confirmed/5 p-2.5"
              >
                <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-confirmed" />
                <div className="min-w-0 flex-1">
                  <div className="text-xs text-foreground">{c.check}</div>
                  <div className="font-mono text-[10px] uppercase tracking-widest text-confirmed">
                    {c.result}
                  </div>
                </div>
              </li>
            ))}
          </ul>
        </Panel>
      </div>
    </div>
  );
}
