import { useMemo, useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { Panel } from "@/components/Panel";
import { auditLog, type AuditEvent } from "@/lib/proofsift-data";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/audit")({
  head: () => ({ meta: [{ title: "Audit Log Stream · ProofSIFT" }] }),
  component: AuditPage,
});

const actorClass: Record<AuditEvent["actor"], string> = {
  agent: "text-confirmed border-confirmed/40 bg-confirmed/5",
  tool: "text-foreground border-border bg-muted/30",
  anti_forensics: "text-inferred border-inferred/40 bg-inferred/5",
  mitre_sequence: "text-inferred border-inferred/40 bg-inferred/5",
  clock_drift: "text-inferred border-inferred/40 bg-inferred/5",
  policy: "text-blocked border-blocked/40 bg-blocked/5",
  bmc_solver: "text-blocked border-blocked/40 bg-blocked/5",
  z3_solver: "text-blocked border-blocked/40 bg-blocked/5",
  mft_entropy: "text-inferred border-inferred/40 bg-inferred/5",
  tool_authorization: "text-confirmed border-confirmed/40 bg-confirmed/5",
  knowledge_graph: "text-confirmed border-confirmed/40 bg-confirmed/5",
  advanced_collector: "text-foreground border-border bg-muted/30",
  provenance: "text-confirmed border-confirmed/40 bg-confirmed/5",
  remediation: "text-inferred border-inferred/40 bg-inferred/5",
};

const actors: AuditEvent["actor"][] = [
  "agent",
  "tool",
  "anti_forensics",
  "mitre_sequence",
  "clock_drift",
  "policy",
  "bmc_solver",
  "z3_solver",
  "mft_entropy",
  "tool_authorization",
  "knowledge_graph",
  "advanced_collector",
  "provenance",
  "remediation",
];

function AuditPage() {
  const [filter, setFilter] = useState<Set<AuditEvent["actor"]>>(new Set(actors));
  const [q, setQ] = useState("");

  const filtered = useMemo(() => {
    return auditLog.filter(
      (e) =>
        filter.has(e.actor) &&
        (q === "" ||
          e.action.toLowerCase().includes(q.toLowerCase()) ||
          JSON.stringify(e.details ?? {})
            .toLowerCase()
            .includes(q.toLowerCase()) ||
          e.event_id.includes(q)),
    );
  }, [filter, q]);

  return (
    <div className="space-y-6 p-6">
      <div>
        <div className="font-mono text-[11px] uppercase tracking-[0.25em] text-confirmed">
          // outputs/execution_log.jsonl
        </div>
        <h1 className="mt-1 text-3xl font-semibold tracking-tight">Append-Only Audit Stream</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Every claim mutation, tool invocation, critic alert, and policy decision is persisted as
          an immutable JSONL event.
        </p>
      </div>

      <Panel title="filters" accent="confirmed">
        <div className="flex flex-wrap items-center gap-2">
          {actors.map((a) => {
            const on = filter.has(a);
            return (
              <button
                key={a}
                onClick={() => {
                  const next = new Set(filter);
                  if (on) {
                    next.delete(a);
                  } else {
                    next.add(a);
                  }
                  setFilter(next);
                }}
                className={cn(
                  "rounded-md border px-2.5 py-1 font-mono text-[10px] uppercase tracking-widest transition",
                  on
                    ? actorClass[a]
                    : "border-border text-muted-foreground opacity-50 hover:opacity-100",
                )}
              >
                {a}
              </button>
            );
          })}
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="grep actions, details, event_id…"
            className="ml-auto w-72 rounded-md border border-border bg-background/60 px-3 py-1.5 font-mono text-xs text-foreground placeholder:text-muted-foreground focus:border-confirmed focus:outline-none"
          />
        </div>
      </Panel>

      <Panel
        title="stream"
        subtitle={`${filtered.length} / ${auditLog.length} events`}
        accent="confirmed"
      >
        <div className="overflow-hidden rounded-md border border-border bg-[var(--terminal-bg)]">
          <table className="w-full font-mono text-[12px]">
            <thead className="bg-muted/30 text-[10px] uppercase tracking-widest text-muted-foreground">
              <tr>
                <th className="px-3 py-2 text-left">t</th>
                <th className="px-3 py-2 text-left">event_id</th>
                <th className="px-3 py-2 text-left">actor</th>
                <th className="px-3 py-2 text-left">action</th>
                <th className="px-3 py-2 text-left">details</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((e) => (
                <tr key={e.event_id} className="border-t border-border/40 hover:bg-confirmed/5">
                  <td className="px-3 py-1.5 text-muted-foreground">{e.timestamp_utc}</td>
                  <td className="px-3 py-1.5 text-confirmed/80">{e.event_id}</td>
                  <td className="px-3 py-1.5">
                    <span
                      className={cn(
                        "rounded border px-1.5 py-0.5 text-[10px] uppercase tracking-widest",
                        actorClass[e.actor],
                      )}
                    >
                      {e.actor}
                    </span>
                  </td>
                  <td className="px-3 py-1.5 text-foreground">{e.action}</td>
                  <td className="px-3 py-1.5 text-muted-foreground">
                    {e.details ? JSON.stringify(e.details) : "—"}
                  </td>
                </tr>
              ))}
              {filtered.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-3 py-8 text-center text-muted-foreground">
                    no events match the filter
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </Panel>
    </div>
  );
}
