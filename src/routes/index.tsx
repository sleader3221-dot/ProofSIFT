import { useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { Panel } from "@/components/Panel";
import { LiveTerminal } from "@/components/LiveTerminal";
import { KillChainValidator } from "@/components/KillChainValidator";
import { TemporalTimelineNormalizer } from "@/components/TemporalTimelineNormalizer";
import { metrics } from "@/lib/proofsift-data";
import {
  AlertTriangle,
  Database,
  FileSearch,
  GitBranch,
  Clock,
  ShieldAlert,
  ShieldCheck,
  Zap,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/")({
  head: () => ({ meta: [{ title: "Dashboard · ProofSIFT" }] }),
  component: Dashboard,
});

function Metric({
  icon: Icon,
  label,
  value,
  sub,
  accent,
}: {
  icon: LucideIcon;
  label: string;
  value: string | number;
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
    <div className="group relative overflow-hidden rounded-lg border border-border bg-card/60 p-4 backdrop-blur transition hover:border-confirmed/40">
      <div className="flex items-center justify-between">
        <span className="font-mono text-[10px] uppercase tracking-[0.22em] text-muted-foreground">
          {label}
        </span>
        <Icon className={cn("h-4 w-4", color)} />
      </div>
      <div className={cn("mt-3 font-mono text-3xl font-semibold tracking-tight", color)}>
        {value}
      </div>
      {sub && <div className="mt-1 text-[11px] text-muted-foreground">{sub}</div>}
    </div>
  );
}

function Dashboard() {
  const [breach, setBreach] = useState(false);

  return (
    <div className="space-y-6 p-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <div className="font-mono text-[11px] uppercase tracking-[0.25em] text-confirmed">
            // case triage
          </div>
          <h1 className="mt-1 text-3xl font-semibold tracking-tight text-foreground">
            Autonomous DFIR Engine
          </h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Plan → Collect → Hypothesize → Verify → Correct → Report. Every confirmed claim is
            provable.
          </p>
        </div>
        <button
          onClick={() => {
            setBreach(true);
            setTimeout(() => setBreach(false), 6000);
          }}
          className="inline-flex items-center gap-2 rounded-md border border-blocked/60 bg-blocked/10 px-4 py-2 font-mono text-xs uppercase tracking-widest text-blocked transition hover:bg-blocked/20"
        >
          <Zap className="h-3.5 w-3.5" /> Simulate attack on evidence
        </button>
      </div>

      {breach && (
        <div className="glow-blocked animate-pulse-blocked rounded-lg border border-blocked bg-blocked/10 p-4">
          <div className="flex items-start gap-3">
            <ShieldAlert className="mt-0.5 h-5 w-5 text-blocked" />
            <div className="font-mono text-sm">
              <div className="text-blocked font-semibold tracking-wide">
                CRITICAL: UNSANCTIONED WRITE ATTEMPT DETECTED ON CORE FILE SYSTEM.
              </div>
              <div className="mt-1 text-foreground/80">
                SafePathPolicy intercepted and dropped transaction. Evidence integrity remains{" "}
                <span className="text-confirmed">100% SECURE</span>.
              </div>
            </div>
          </div>
        </div>
      )}

      <div className="grid grid-cols-2 gap-4 md:grid-cols-3 xl:grid-cols-6">
        <Metric
          icon={Database}
          label="Ingested Artifacts"
          value={metrics.ingestedArtifacts.toLocaleString()}
          sub="SHA-256 verified"
          accent="confirmed"
        />
        <Metric
          icon={FileSearch}
          label="Generated Claims"
          value={metrics.generatedClaims}
          sub="4 confirmed · 1 inferred · 1 ctx"
          accent="confirmed"
        />
        <Metric
          icon={GitBranch}
          label="Self-Corrections"
          value={metrics.selfCorrections}
          sub="critic interventions"
          accent="inferred"
        />
        <Metric
          icon={Clock}
          label="Clock Drift Adj."
          value={metrics.clockDrifts}
          sub={`${metrics.clockDriftOffset} offset normalized`}
          accent="inferred"
        />
        <Metric
          icon={AlertTriangle}
          label="Anti-Forensics"
          value={metrics.antiForensics}
          sub="timestomping detected"
          accent="inferred"
        />
        <Metric
          icon={ShieldCheck}
          label="Spoliation Blocked"
          value={metrics.spoliationBlocked}
          sub="enforced via SafePathPolicy"
          accent="blocked"
        />
      </div>

      <div className="grid gap-6 xl:grid-cols-[1fr_1.15fr]">
        <KillChainValidator />
        <TemporalTimelineNormalizer />
      </div>

      <div className="grid gap-6 xl:grid-cols-[1.6fr_1fr]">
        <Panel
          title="live case run terminal"
          subtitle="Self-correcting investigator stream"
          accent="confirmed"
        >
          <LiveTerminal />
        </Panel>
        <div className="space-y-6">
          <Panel title="case state" subtitle="proofsift-demo-001" accent="confirmed">
            <dl className="space-y-2 font-mono text-xs">
              {[
                ["max iterations", "3"],
                ["max corrections", "23"],
                ["policy", "SafePathPolicy (read-only)"],
                ["evidence graph", "outputs/evidence_graph.sqlite"],
                ["audit log", "outputs/audit.jsonl"],
                ["benchmark", "100.0% PERFECT MATURATION"],
              ].map(([k, v]) => (
                <div
                  key={k}
                  className="flex items-center justify-between border-b border-border/40 pb-1.5"
                >
                  <dt className="uppercase tracking-widest text-muted-foreground">{k}</dt>
                  <dd className="text-foreground">{v}</dd>
                </div>
              ))}
            </dl>
          </Panel>
          <Panel title="threat surface" accent="blocked">
            <ul className="space-y-2 text-sm">
              <li className="flex items-center justify-between">
                <span className="text-muted-foreground">C2 endpoint</span>
                <span className="font-mono text-blocked">203.0.113.50:443</span>
              </li>
              <li className="flex items-center justify-between">
                <span className="text-muted-foreground">Suspect endpoint</span>
                <span className="font-mono text-inferred">198.51.100.24:443</span>
              </li>
              <li className="flex items-center justify-between">
                <span className="text-muted-foreground">Persistence</span>
                <span className="font-mono text-blocked">HKCU\Run\Updater</span>
              </li>
              <li className="flex items-center justify-between">
                <span className="text-muted-foreground">Injected page</span>
                <span className="font-mono text-blocked">PID 1888 · RWX</span>
              </li>
            </ul>
          </Panel>
        </div>
      </div>
    </div>
  );
}
