import { FormEvent, KeyboardEvent, useRef, useState } from "react";
import { Download, Terminal } from "lucide-react";
import {
  benchmark,
  claims,
  cliCommands,
  metrics,
  terminalScript,
  toolCatalog,
} from "@/lib/proofsift-data";
import { downloadTextFile } from "@/lib/download";
import { cn } from "@/lib/utils";

type ConsoleLine = {
  id: number;
  kind: "prompt" | "output" | "error" | "system";
  text: string;
};

const prompt = "C:\\ProofSIFT>";

function normalizeCommand(input: string) {
  return input.trim().replace(/\s+/g, " ");
}

function renderBenchmark() {
  return [
    "PROOFSIFT ACCURACY BENCHMARK HARNESS",
    `true positives: ${benchmark.truePositives.value}/${benchmark.truePositives.total} (${benchmark.truePositives.pct}%)`,
    `false positives: ${benchmark.falsePositives.value}/${benchmark.falsePositives.total} (${benchmark.falsePositives.pct}%)`,
    `hallucinations intercepted: ${benchmark.hallucinationsIntercepted}`,
    `clock drift normalized: ${benchmark.clockDrifts.label}`,
    `anti-forensics found: ${benchmark.antiForensicsFound.value}/${benchmark.antiForensicsFound.total}`,
    `spoliation writes allowed: ${benchmark.spoliationBlocked.allowed}; blocked: ${benchmark.spoliationBlocked.blocked}`,
    `final score: ${benchmark.finalScore.toFixed(1)}%`,
  ].join("\n");
}

function renderTrace(command: string) {
  const match = command.match(/--claim-id\s+([^\s]+)/);
  const claimId = match?.[1] ?? "clm-3c76c94c3ce5";
  const claim = claims.find((item) => item.id === claimId);
  if (!claim) return `trace error: claim_id ${claimId} not found`;
  return JSON.stringify(
    {
      claim_id: claim.id,
      status: claim.status,
      confidence: claim.confidence,
      severity: claim.severity,
      mitre: claim.mitre,
      evidence: claim.evidence,
    },
    null,
    2,
  );
}

function renderToolList() {
  return toolCatalog
    .map((tool) => `${tool.name.padEnd(24)} ${tool.category.padEnd(10)} ${tool.artifactKind}`)
    .join("\n");
}

function renderRun() {
  return [
    "run.start case_id=proofsift-demo-001 max_iterations=3",
    ...terminalScript.filter((line) => line.text.trim() !== "").map((line) => line.text.trim()),
    `summary artifacts=${metrics.ingestedArtifacts} claims=${metrics.generatedClaims} corrections=${metrics.selfCorrections}`,
  ].join("\n");
}

function renderHelp() {
  return [
    "Safe ProofSIFT web CLI. Raw shell execution is intentionally blocked.",
    "",
    "Commands:",
    "  help",
    "  clear",
    "  download report",
    ...cliCommands.map((item) => `  ${item.cmd}`),
  ].join("\n");
}

function buildReportText() {
  return `ProofSIFT CLI Export\nGenerated: ${new Date().toISOString()}\nCase: proofsift-demo-001\n\n${renderBenchmark()}\n`;
}

function executeCommand(command: string): { kind: ConsoleLine["kind"]; text: string } {
  const normalized = normalizeCommand(command);
  if (!normalized) return { kind: "system", text: "" };
  if (normalized === "help" || normalized === "?") return { kind: "output", text: renderHelp() };
  if (normalized === "download report") {
    downloadTextFile("proofsift-cli-export.txt", buildReportText(), "text/plain");
    return { kind: "output", text: "downloaded proofsift-cli-export.txt" };
  }
  if (normalized.startsWith("proofsift run ")) return { kind: "output", text: renderRun() };
  if (normalized.startsWith("proofsift benchmark "))
    return { kind: "output", text: renderBenchmark() };
  if (normalized.startsWith("proofsift trace "))
    return { kind: "output", text: renderTrace(normalized) };
  if (normalized.startsWith("proofsift list-tools "))
    return { kind: "output", text: renderToolList() };
  if (normalized.startsWith("proofsift validate-submission ")) {
    return {
      kind: "output",
      text: "validate-submission: OK\nrequired files present: package.json, vite.config.ts, src/routes, src/components\nvercel preset: detected",
    };
  }
  if (normalized === "proofsift mcp-stdio") {
    return {
      kind: "output",
      text: "mcp-stdio: browser dry-run only\ntransport=stdio is disabled in web console\nmanifest=Protocol SIFT bridge available in native CLI",
    };
  }
  return {
    kind: "error",
    text: `blocked: '${normalized}' is not a whitelisted ProofSIFT command. Type 'help'.`,
  };
}

export function ProofsiftCliConsole() {
  const [lines, setLines] = useState<ConsoleLine[]>([
    {
      id: 1,
      kind: "system",
      text: "Safe web CLI ready. Type 'help' to list commands.",
    },
  ]);
  const [input, setInput] = useState("");
  const [history, setHistory] = useState<string[]>([]);
  const [historyIndex, setHistoryIndex] = useState<number | null>(null);
  const nextId = useRef(2);

  function append(kind: ConsoleLine["kind"], text: string) {
    setLines((current) => [...current, { id: nextId.current++, kind, text }]);
  }

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const command = normalizeCommand(input);
    if (!command) return;
    if (command === "clear") {
      setLines([]);
      setInput("");
      setHistory((current) => [...current, command]);
      setHistoryIndex(null);
      return;
    }
    append("prompt", `${prompt} ${command}`);
    const result = executeCommand(command);
    if (result.text) append(result.kind, result.text);
    setHistory((current) => [...current, command]);
    setHistoryIndex(null);
    setInput("");
  }

  function handleKeyDown(event: KeyboardEvent<HTMLInputElement>) {
    if (event.key !== "ArrowUp" && event.key !== "ArrowDown") return;
    event.preventDefault();
    if (history.length === 0) return;
    const nextIndex =
      event.key === "ArrowUp"
        ? historyIndex == null
          ? history.length - 1
          : Math.max(0, historyIndex - 1)
        : historyIndex == null
          ? history.length - 1
          : Math.min(history.length - 1, historyIndex + 1);
    setHistoryIndex(nextIndex);
    setInput(history[nextIndex]);
  }

  return (
    <div className="rounded-lg border border-border bg-[var(--terminal-bg)] shadow-2xl">
      <div className="flex items-center justify-between border-b border-border/60 px-3 py-2">
        <div className="flex items-center gap-2 font-mono text-[11px] uppercase tracking-widest text-muted-foreground">
          <Terminal className="h-3.5 w-3.5 text-confirmed" /> interactive protected CLI
        </div>
        <button
          onClick={() =>
            downloadTextFile(
              "proofsift-cli-session.txt",
              lines.map((line) => line.text).join("\n"),
              "text/plain",
            )
          }
          className="inline-flex items-center gap-1.5 rounded border border-border bg-background/50 px-2 py-1 font-mono text-[10px] uppercase tracking-widest text-muted-foreground transition hover:border-confirmed/50 hover:text-confirmed"
        >
          <Download className="h-3 w-3" /> session
        </button>
      </div>
      <div className="h-[340px] overflow-auto px-4 py-3 font-mono text-[12.5px] leading-relaxed">
        {lines.map((line) => (
          <pre
            key={line.id}
            className={cn(
              "whitespace-pre-wrap",
              line.kind === "prompt" && "text-confirmed",
              line.kind === "output" && "text-foreground",
              line.kind === "error" && "text-blocked",
              line.kind === "system" && "text-muted-foreground",
            )}
          >
            {line.text || "\u00a0"}
          </pre>
        ))}
      </div>
      <form
        onSubmit={submit}
        className="flex items-center gap-2 border-t border-border/60 px-3 py-2"
      >
        <span className="font-mono text-xs text-confirmed">{prompt}</span>
        <input
          value={input}
          onChange={(event) => setInput(event.target.value)}
          onKeyDown={handleKeyDown}
          spellCheck={false}
          className="min-w-0 flex-1 bg-transparent font-mono text-xs text-foreground outline-none placeholder:text-muted-foreground"
          placeholder="proofsift run --case cases/demo_case/case.json --max-iterations 3"
        />
      </form>
    </div>
  );
}
