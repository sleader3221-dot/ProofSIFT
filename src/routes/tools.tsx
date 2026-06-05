import { useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { Panel } from "@/components/Panel";
import { ProofsiftCliConsole } from "@/components/ProofsiftCliConsole";
import { toolCatalog, cliCommands, configKnobs } from "@/lib/proofsift-data";
import { cn } from "@/lib/utils";
import {
  Cpu,
  HardDrive,
  Database,
  Calendar,
  FileText,
  Search,
  ShieldCheck,
  Copy,
  Check,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";

export const Route = createFileRoute("/tools")({
  head: () => ({ meta: [{ title: "Tools & CLI · ProofSIFT" }] }),
  component: ToolsPage,
});

const categoryIcon: Record<string, LucideIcon> = {
  memory: Cpu,
  disk: HardDrive,
  registry: Database,
  timeline: Calendar,
  logs: FileText,
  ioc: Search,
  guardrail: ShieldCheck,
};
const categoryAccent: Record<string, string> = {
  memory: "text-confirmed",
  disk: "text-confirmed",
  registry: "text-inferred",
  timeline: "text-foreground",
  logs: "text-foreground",
  ioc: "text-inferred",
  guardrail: "text-blocked",
};

function CopyBtn({ text }: { text: string }) {
  const [status, setStatus] = useState<"idle" | "copied" | "failed">("idle");

  async function handleCopy() {
    try {
      if (!navigator.clipboard) throw new Error("Clipboard API unavailable");
      await navigator.clipboard.writeText(text);
      setStatus("copied");
    } catch {
      setStatus("failed");
    } finally {
      window.setTimeout(() => setStatus("idle"), 1400);
    }
  }

  return (
    <button
      onClick={handleCopy}
      className="inline-flex items-center gap-1 rounded border border-border bg-background/50 px-2 py-1 font-mono text-[10px] uppercase tracking-widest text-muted-foreground transition hover:text-confirmed"
    >
      {status === "copied" ? (
        <>
          <Check className="h-3 w-3 text-confirmed" /> copied
        </>
      ) : status === "failed" ? (
        <>
          <Copy className="h-3 w-3 text-blocked" /> failed
        </>
      ) : (
        <>
          <Copy className="h-3 w-3" /> copy
        </>
      )}
    </button>
  );
}

function ToolsPage() {
  return (
    <div className="space-y-6 p-6">
      <div>
        <div className="font-mono text-[11px] uppercase tracking-[0.25em] text-confirmed">
          // ToolRunner.catalog()
        </div>
        <h1 className="mt-1 text-3xl font-semibold tracking-tight">16 Typed Forensic Tools</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          The agent never invokes raw shell. Every tool is a typed facade with guardrails — on SIFT
          they wrap Volatility, EvtxECmd, MFTECmd, AmcacheParser, RegRipper, and YARA.
        </p>
      </div>

      <Panel
        title="tool catalog"
        subtitle={`${toolCatalog.length} tools across 7 categories`}
        accent="confirmed"
      >
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {toolCatalog.map((t) => {
            const Icon = categoryIcon[t.category];
            return (
              <div
                key={t.name}
                className="rounded-md border border-border bg-background/40 p-3 transition hover:border-confirmed/40"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Icon className={cn("h-4 w-4", categoryAccent[t.category])} />
                    <span className="font-mono text-sm text-foreground">{t.name}</span>
                  </div>
                  <span className="rounded border border-border bg-muted/30 px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
                    {t.category}
                  </span>
                </div>
                <p className="mt-2 text-xs text-muted-foreground">{t.guardrail}</p>
                <div className="mt-2 grid grid-cols-2 gap-2 font-mono text-[10px] text-muted-foreground">
                  <div>
                    <span className="uppercase tracking-widest">input</span>
                    <div className="text-foreground/90">{t.input}</div>
                  </div>
                  <div>
                    <span className="uppercase tracking-widest">artifact</span>
                    <div className="text-confirmed">{t.artifactKind}</div>
                  </div>
                </div>
                {t.siftWrap && (
                  <div className="mt-2 font-mono text-[10px] text-inferred">
                    SIFT → {t.siftWrap}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </Panel>

      <div className="grid gap-6 lg:grid-cols-[1.3fr_1fr]">
        <Panel title="CLI reference" subtitle="src/proofsift/cli.py" accent="confirmed">
          <div className="space-y-3">
            {cliCommands.map((c) => (
              <div
                key={c.cmd}
                className="rounded-md border border-border bg-[var(--terminal-bg)] p-3"
              >
                <div className="flex items-center justify-between gap-2">
                  <pre className="overflow-x-auto font-mono text-[12.5px] text-confirmed">
                    $ {c.cmd}
                  </pre>
                  <CopyBtn text={c.cmd} />
                </div>
                <p className="mt-1.5 text-xs text-muted-foreground">{c.desc}</p>
              </div>
            ))}
          </div>
        </Panel>

        <Panel title="configuration knobs" subtitle="CaseConfig + case.json" accent="confirmed">
          <div className="overflow-hidden rounded-md border border-border">
            <table className="w-full text-sm">
              <tbody>
                {configKnobs.map((k) => (
                  <tr key={k.key} className="border-t border-border/60 first:border-t-0">
                    <td className="px-3 py-2 font-mono text-[11px] uppercase tracking-widest text-muted-foreground">
                      {k.key}
                    </td>
                    <td className="px-3 py-2 font-mono text-xs text-confirmed">{k.value}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      </div>

      <Panel
        title="live protected CLI"
        subtitle="Browser command console with whitelisted ProofSIFT handlers"
        accent="confirmed"
      >
        <ProofsiftCliConsole />
      </Panel>
    </div>
  );
}
