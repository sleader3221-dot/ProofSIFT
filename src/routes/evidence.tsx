import { useMemo, useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { Panel } from "@/components/Panel";
import { claims, tableData, type Claim } from "@/lib/proofsift-data";
import { cn } from "@/lib/utils";
import { ArrowRight, Database, Filter, Network } from "lucide-react";

export const Route = createFileRoute("/evidence")({
  head: () => ({ meta: [{ title: "Evidence Graph · ProofSIFT" }] }),
  component: EvidencePage,
});

const tabs = ["tool_runs", "artifacts", "claims", "clock_drifts", "anomalies"] as const;

function statusClass(s: Claim["status"]) {
  if (s.startsWith("CONFIRMED")) return "border-confirmed/50 bg-confirmed/10 text-confirmed";
  if (s.startsWith("INFERRED")) return "border-inferred/50 bg-inferred/10 text-inferred";
  if (s === "CONTEXT") return "border-border bg-muted/40 text-muted-foreground";
  return "border-blocked/50 bg-blocked/10 text-blocked";
}

function statusStroke(s: Claim["status"]) {
  if (s.startsWith("CONFIRMED")) return "var(--confirmed)";
  if (s.startsWith("INFERRED")) return "var(--inferred)";
  if (s === "CONTEXT") return "var(--muted-foreground)";
  return "var(--blocked)";
}

// ---------------- Evidence Graph (SVG) ----------------
function EvidenceGraph({ selected, onSelect }: { selected: Claim; onSelect: (c: Claim) => void }) {
  // Collect unique sources (left column) in stable order of first appearance.
  const sources = useMemo(() => {
    const order: string[] = [];
    claims.forEach((c) =>
      c.evidence.forEach((e) => {
        if (!order.includes(e.source)) order.push(e.source);
      }),
    );
    return order;
  }, []);

  const W = 760;
  const PAD_Y = 24;
  const ROW_H = 34;
  const LEFT_X = 24;
  const RIGHT_X = W - 24;
  const SRC_W = 190;
  const CLAIM_W = 290;
  const height = Math.max(sources.length, claims.length) * ROW_H + PAD_Y * 2;

  const srcY = (i: number) => PAD_Y + i * ROW_H + 14;
  const claimY = (i: number) => PAD_Y + i * ROW_H + 14;

  const activeSources = new Set(selected.evidence.map((e) => e.source));

  return (
    <div className="overflow-x-auto rounded-md border border-border bg-background/40">
      <svg viewBox={`0 0 ${W} ${height}`} className="block w-full" style={{ minWidth: 680 }}>
        <defs>
          <pattern id="grid" width="20" height="20" patternUnits="userSpaceOnUse">
            <path
              d="M 20 0 L 0 0 0 20"
              fill="none"
              stroke="var(--border)"
              strokeOpacity="0.25"
              strokeWidth="0.5"
            />
          </pattern>
        </defs>
        <rect width={W} height={height} fill="url(#grid)" />

        {/* Edges: source -> claim. Draw inactive first, then active on top. */}
        {[false, true].map((activePass) =>
          claims.flatMap((c, ci) =>
            c.evidence.map((e, ei) => {
              const si = sources.indexOf(e.source);
              if (si < 0) return null;
              const isActiveClaim = c.id === selected.id;
              if (activePass !== isActiveClaim) return null;
              const x1 = LEFT_X + SRC_W;
              const y1 = srcY(si);
              const x2 = RIGHT_X - CLAIM_W;
              const y2 = claimY(ci);
              const mx = (x1 + x2) / 2;
              const d = `M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`;
              const stroke = isActiveClaim ? statusStroke(c.status) : "var(--border)";
              return (
                <path
                  key={`${c.id}-${ei}-${activePass}`}
                  d={d}
                  fill="none"
                  stroke={stroke}
                  strokeOpacity={isActiveClaim ? 0.9 : 0.18}
                  strokeWidth={isActiveClaim ? 1.6 : 1}
                />
              );
            }),
          ),
        )}

        {/* Source nodes */}
        {sources.map((s, i) => {
          const active = activeSources.has(s);
          return (
            <g key={s} transform={`translate(${LEFT_X},${srcY(i) - 12})`}>
              <rect
                width={SRC_W}
                height={24}
                rx={4}
                fill={
                  active ? "color-mix(in oklab, var(--confirmed) 12%, transparent)" : "var(--card)"
                }
                stroke={active ? "var(--confirmed)" : "var(--border)"}
                strokeOpacity={active ? 0.9 : 0.6}
              />
              <text
                x={10}
                y={16}
                fontFamily="ui-monospace, monospace"
                fontSize={11}
                fill={active ? "var(--confirmed)" : "var(--muted-foreground)"}
              >
                {s}
              </text>
            </g>
          );
        })}

        {/* Claim nodes */}
        {claims.map((c, i) => {
          const isActive = c.id === selected.id;
          const stroke = statusStroke(c.status);
          return (
            <g
              key={c.id}
              transform={`translate(${RIGHT_X - CLAIM_W},${claimY(i) - 12})`}
              onClick={() => onSelect(c)}
              style={{ cursor: "pointer" }}
            >
              <rect
                width={CLAIM_W}
                height={24}
                rx={4}
                fill={
                  isActive ? "color-mix(in oklab, " + stroke + " 16%, transparent)" : "var(--card)"
                }
                stroke={stroke}
                strokeOpacity={isActive ? 1 : 0.45}
                strokeWidth={isActive ? 1.5 : 1}
              />
              <text
                x={10}
                y={16}
                fontFamily="ui-monospace, monospace"
                fontSize={11}
                fill="var(--foreground)"
              >
                {c.id.slice(0, 14)}… · conf {c.confidence.toFixed(2)}
              </text>
            </g>
          );
        })}

        {/* Column headers */}
        <text
          x={LEFT_X}
          y={14}
          fontFamily="ui-monospace, monospace"
          fontSize={9}
          fill="var(--muted-foreground)"
          letterSpacing="2"
        >
          TOOL SOURCES
        </text>
        <text
          x={RIGHT_X - CLAIM_W}
          y={14}
          fontFamily="ui-monospace, monospace"
          fontSize={9}
          fill="var(--muted-foreground)"
          letterSpacing="2"
        >
          CLAIMS
        </text>
      </svg>
    </div>
  );
}

function EvidencePage() {
  const [activeTab, setActiveTab] = useState<(typeof tabs)[number]>("tool_runs");
  const [selected, setSelected] = useState<Claim>(claims[0]);
  const [scopeToClaim, setScopeToClaim] = useState(true);

  const activeSources = useMemo(() => new Set(selected.evidence.map((e) => e.source)), [selected]);
  const allRows = tableData[activeTab];

  // Scope DB viewer rows to the selected claim's corroboration chain.
  const rows = useMemo(() => {
    if (!scopeToClaim) return allRows;
    switch (activeTab) {
      case "tool_runs":
        return allRows.filter((r) => activeSources.has(String(r.tool)));
      case "artifacts":
        return allRows.filter((r) => activeSources.has(String(r.source)));
      case "claims":
        return allRows.filter((r) => r.id === selected.id);
      case "clock_drifts":
        return allRows.filter(
          (r) => activeSources.has(String(r.source_a)) || activeSources.has(String(r.source_b)),
        );
      case "anomalies":
        // Anomalies are tied to evil.exe — surface them whenever the selected claim references it.
        return selected.title.toLowerCase().includes("evil.exe") ||
          selected.evidence.some((e) => e.detail.toLowerCase().includes("evil.exe"))
          ? allRows
          : [];
      default:
        return allRows;
    }
  }, [scopeToClaim, activeTab, allRows, activeSources, selected]);

  const cols = (
    rows[0] ? Object.keys(rows[0]) : allRows[0] ? Object.keys(allRows[0]) : []
  ) as string[];

  return (
    <div className="space-y-6 p-6">
      <div>
        <div className="font-mono text-[11px] uppercase tracking-[0.25em] text-confirmed">
          // evidence graph browser
        </div>
        <h1 className="mt-1 text-3xl font-semibold tracking-tight">SQLite Provenance Store</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Every artifact, tool run, and claim is traceable to a parser command and an evidence hash.
          Click any node or row to isolate its corroboration chain.
        </p>
      </div>

      <Panel
        title="evidence graph"
        subtitle="tool sources → claims (interactive)"
        accent="confirmed"
        action={
          <div className="flex items-center gap-2 font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
            <Network className="h-3.5 w-3.5" />
            {selected.evidence.length} edges · {activeSources.size} sources
          </div>
        }
      >
        <EvidenceGraph selected={selected} onSelect={setSelected} />
      </Panel>

      <div className="grid gap-6 xl:grid-cols-[1.1fr_1fr]">
        <Panel
          title="claim investigator"
          subtitle="Select a claim to isolate its corroboration chain"
          accent="confirmed"
        >
          <ul className="space-y-2">
            {claims.map((c) => (
              <li key={c.id}>
                <button
                  onClick={() => setSelected(c)}
                  className={cn(
                    "group flex w-full items-start gap-3 rounded-md border bg-background/40 p-3 text-left transition hover:border-confirmed/40",
                    selected.id === c.id ? "border-confirmed/60 bg-confirmed/5" : "border-border",
                  )}
                >
                  <span
                    className={cn(
                      "inline-flex shrink-0 items-center rounded border px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-widest",
                      statusClass(c.status),
                    )}
                  >
                    {c.status}
                  </span>
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-sm text-foreground">{c.title}</div>
                    <div className="mt-0.5 flex flex-wrap items-center gap-x-3 gap-y-0.5 font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
                      <span>{c.id}</span>
                      <span className="text-confirmed">conf {c.confidence.toFixed(2)}</span>
                      {c.mitre.map((m) => (
                        <span key={m}>{m}</span>
                      ))}
                    </div>
                  </div>
                  <ArrowRight className="mt-1 h-3.5 w-3.5 text-muted-foreground transition group-hover:translate-x-0.5 group-hover:text-confirmed" />
                </button>
              </li>
            ))}
          </ul>
        </Panel>

        <Panel
          title="corroboration chain"
          subtitle={selected.title}
          accent={
            selected.status.startsWith("CONFIRMED")
              ? "confirmed"
              : selected.status.startsWith("INFERRED")
                ? "inferred"
                : undefined
          }
        >
          <div className="mb-4 flex flex-wrap items-center gap-2">
            <span
              className={cn(
                "rounded border px-2 py-0.5 font-mono text-[10px] uppercase tracking-widest",
                statusClass(selected.status),
              )}
            >
              {selected.status}
            </span>
            <span className="font-mono text-[11px] text-muted-foreground">
              confidence {selected.confidence.toFixed(2)}
            </span>
            <span className="font-mono text-[11px] text-muted-foreground">
              severity {selected.severity}
            </span>
            {selected.mitre.map((m) => (
              <span
                key={m}
                className="rounded border border-border bg-muted/30 px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground"
              >
                {m}
              </span>
            ))}
          </div>
          {selected.note && (
            <div
              className={cn(
                "mb-4 rounded-md border p-3 text-xs",
                selected.status.startsWith("INFERRED")
                  ? "border-inferred/50 bg-inferred/10 text-inferred"
                  : "border-border bg-muted/30 text-muted-foreground",
              )}
            >
              {selected.note}
            </div>
          )}
          <div className="overflow-hidden rounded-md border border-border">
            <table className="w-full text-sm">
              <thead className="bg-muted/40 font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
                <tr>
                  <th className="px-3 py-2 text-left">#</th>
                  <th className="px-3 py-2 text-left">source</th>
                  <th className="px-3 py-2 text-left">artifact detail</th>
                </tr>
              </thead>
              <tbody>
                {selected.evidence.map((e, i) => (
                  <tr key={i} className="border-t border-border/60">
                    <td className="px-3 py-2 font-mono text-[11px] text-muted-foreground">
                      {i + 1}
                    </td>
                    <td className="px-3 py-2 font-mono text-xs text-confirmed">{e.source}</td>
                    <td className="px-3 py-2 text-foreground">{e.detail}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      </div>

      <Panel
        title="database viewer"
        subtitle="evidence_graph.sqlite"
        accent="confirmed"
        action={
          <div className="flex items-center gap-3">
            <button
              onClick={() => setScopeToClaim((v) => !v)}
              className={cn(
                "inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 font-mono text-[10px] uppercase tracking-widest transition",
                scopeToClaim
                  ? "border-confirmed/60 bg-confirmed/10 text-confirmed"
                  : "border-border text-muted-foreground hover:text-foreground",
              )}
            >
              <Filter className="h-3 w-3" />
              {scopeToClaim ? "scoped to claim" : "all rows"}
            </button>
            <Database className="h-4 w-4 text-muted-foreground" />
          </div>
        }
      >
        <div className="mb-3 flex flex-wrap gap-1.5">
          {tabs.map((t) => (
            <button
              key={t}
              onClick={() => setActiveTab(t)}
              className={cn(
                "rounded-md border px-3 py-1 font-mono text-[11px] uppercase tracking-widest transition",
                activeTab === t
                  ? "border-confirmed bg-confirmed/10 text-confirmed"
                  : "border-border text-muted-foreground hover:text-foreground",
              )}
            >
              {t}
            </button>
          ))}
        </div>
        <div className="overflow-x-auto rounded-md border border-border">
          <table className="w-full text-sm">
            <thead className="bg-muted/40 font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
              <tr>
                {cols.map((c) => (
                  <th key={c} className="px-3 py-2 text-left">
                    {c}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.length === 0 ? (
                <tr>
                  <td
                    colSpan={cols.length || 1}
                    className="px-3 py-6 text-center font-mono text-xs text-muted-foreground"
                  >
                    no rows in <span className="text-foreground">{activeTab}</span> intersect the
                    selected claim's chain — toggle "all rows" to view the full table
                  </td>
                </tr>
              ) : (
                rows.map((r, i) => (
                  <tr key={i} className="border-t border-border/60 transition hover:bg-confirmed/5">
                    {cols.map((c) => (
                      <td key={c} className="px-3 py-2 font-mono text-xs text-foreground/90">
                        {String(r[c] ?? "—")}
                      </td>
                    ))}
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
        <div className="mt-2 font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
          {rows.length} / {allRows.length} rows · table{" "}
          <span className="text-confirmed">{activeTab}</span>
        </div>
      </Panel>
    </div>
  );
}
