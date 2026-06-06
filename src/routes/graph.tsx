import { useEffect, useMemo, useRef, useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { drag } from "d3-drag";
import {
  forceCenter,
  forceCollide,
  forceLink,
  forceManyBody,
  forceSimulation,
  type SimulationLinkDatum,
  type SimulationNodeDatum,
} from "d3-force";
import { select } from "d3-selection";
import { Database, Download, FileCode, Fingerprint, Network, ShieldAlert } from "lucide-react";
import { Panel } from "@/components/Panel";
import { cn } from "@/lib/utils";
import { downloadTextFile } from "@/lib/download";

export const Route = createFileRoute("/graph")({
  head: () => ({ meta: [{ title: "Force Graph · ProofSIFT" }] }),
  component: GraphPage,
});

type NodeKind = "process" | "network" | "registry" | "prefetch";

type EvidenceNode = SimulationNodeDatum & {
  id: string;
  label: string;
  kind: NodeKind;
  radius: number;
  artifact: Record<string, unknown>;
};

type EvidenceLink = SimulationLinkDatum<EvidenceNode> & {
  source: string | EvidenceNode;
  target: string | EvidenceNode;
  relation: string;
};

const kindClass: Record<NodeKind, string> = {
  process: "text-blocked border-blocked/50 bg-blocked/10",
  network: "text-confirmed border-confirmed/50 bg-confirmed/10",
  registry: "text-inferred border-inferred/50 bg-inferred/10",
  prefetch: "text-foreground border-border bg-muted/30",
};

function nodeFill(kind: NodeKind) {
  if (kind === "process") return "var(--blocked)";
  if (kind === "network") return "var(--confirmed)";
  if (kind === "registry") return "var(--inferred)";
  return "var(--foreground)";
}

function nodeIcon(kind: NodeKind) {
  if (kind === "process") return ShieldAlert;
  if (kind === "network") return Network;
  if (kind === "registry") return Database;
  return FileCode;
}

function ForceGraph({ onSelect }: { onSelect: (node: EvidenceNode) => void }) {
  const svgRef = useRef<SVGSVGElement>(null);

  const { nodes, links } = useMemo(() => {
    const graphNodes: EvidenceNode[] = [
      {
        id: "evil.exe",
        label: "evil.exe",
        kind: "process",
        radius: 31,
        artifact: {
          artifact_id: "proc-1888",
          type: "process",
          image: "C:\\Users\\Public\\evil.exe",
          pid: 1888,
          sha256: "9f3c2b01...b201",
          status: "CONFIRMED_CRITICAL",
        },
      },
      {
        id: "203.0.113.50",
        label: "203.0.113.50",
        kind: "network",
        radius: 24,
        artifact: {
          artifact_id: "net-203-443",
          type: "network_connection",
          remote_ip: "203.0.113.50",
          remote_port: 443,
          owner_pid: 1888,
          source: "memory_netscan",
        },
      },
      {
        id: "HKCU\\Run",
        label: "HKCU\\Run",
        kind: "registry",
        radius: 24,
        artifact: {
          artifact_id: "reg-updater",
          type: "registry_persistence",
          hive: "HKCU",
          key: "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
          value: "Updater",
          data: "C:\\Users\\Public\\evil.exe",
        },
      },
      {
        id: "EVIL.EXE-9A8B7C6D.pf",
        label: "EVIL.EXE-9A8B7C6D.pf",
        kind: "prefetch",
        radius: 23,
        artifact: {
          artifact_id: "pf-evil-9a8b7c6d",
          type: "prefetch_execution",
          file: "EVIL.EXE-9A8B7C6D.pf",
          execution_count: 3,
          source: "disk_prefetch",
          verifier_role: "Execution predecessor proof",
        },
      },
    ];

    const graphLinks: EvidenceLink[] = [
      { source: "evil.exe", target: "203.0.113.50", relation: "beaconed_to" },
      { source: "evil.exe", target: "HKCU\\Run", relation: "persisted_by" },
      { source: "evil.exe", target: "EVIL.EXE-9A8B7C6D.pf", relation: "executed_as" },
    ];

    return { nodes: graphNodes, links: graphLinks };
  }, []);

  useEffect(() => {
    const svg = select(svgRef.current);
    svg.selectAll("*").remove();

    const width = 920;
    const height = 520;
    const linkLayer = svg.append("g");
    const nodeLayer = svg.append("g");

    const simulation = forceSimulation<EvidenceNode>(nodes)
      .force(
        "link",
        forceLink<EvidenceNode, EvidenceLink>(links)
          .id((node) => node.id)
          .distance(180)
          .strength(0.95),
      )
      .force("charge", forceManyBody().strength(-520))
      .force(
        "collide",
        forceCollide<EvidenceNode>().radius((node) => node.radius + 18),
      )
      .force("center", forceCenter(width / 2, height / 2));

    const link = linkLayer
      .selectAll<SVGLineElement, EvidenceLink>("line")
      .data(links)
      .join("line")
      .attr("stroke", "var(--border)")
      .attr("stroke-width", 1.5)
      .attr("stroke-opacity", 0.8);

    const relation = linkLayer
      .selectAll<SVGTextElement, EvidenceLink>("text")
      .data(links)
      .join("text")
      .attr("fill", "var(--muted-foreground)")
      .attr("font-family", "ui-monospace, monospace")
      .attr("font-size", 10)
      .attr("text-anchor", "middle")
      .text((item) => item.relation);

    const node = nodeLayer
      .selectAll<SVGGElement, EvidenceNode>("g")
      .data(nodes)
      .join("g")
      .attr("cursor", "grab")
      .on("click", (_, item) => onSelect(item));

    node
      .append("circle")
      .attr("r", (item) => item.radius)
      .attr("fill", (item) => nodeFill(item.kind))
      .attr("fill-opacity", (item) => (item.kind === "process" ? 0.95 : 0.35))
      .attr("stroke", (item) => nodeFill(item.kind))
      .attr("stroke-width", 2.5)
      .attr(
        "filter",
        "drop-shadow(0 0 12px color-mix(in oklab, var(--confirmed) 30%, transparent))",
      );

    node
      .append("text")
      .attr("y", (item) => item.radius + 18)
      .attr("text-anchor", "middle")
      .attr("fill", "var(--foreground)")
      .attr("font-family", "ui-monospace, monospace")
      .attr("font-size", 11)
      .text((item) => item.label);

    const dragBehavior = drag<SVGGElement, EvidenceNode>()
      .on("start", (event, item) => {
        if (!event.active) simulation.alphaTarget(0.3).restart();
        item.fx = item.x;
        item.fy = item.y;
      })
      .on("drag", (event, item) => {
        item.fx = event.x;
        item.fy = event.y;
      })
      .on("end", (event, item) => {
        if (!event.active) simulation.alphaTarget(0);
        item.fx = null;
        item.fy = null;
      });

    node.call(dragBehavior);

    simulation.on("tick", () => {
      link
        .attr("x1", (item) => (item.source as EvidenceNode).x ?? 0)
        .attr("y1", (item) => (item.source as EvidenceNode).y ?? 0)
        .attr("x2", (item) => (item.target as EvidenceNode).x ?? 0)
        .attr("y2", (item) => (item.target as EvidenceNode).y ?? 0);

      relation
        .attr(
          "x",
          (item) =>
            (((item.source as EvidenceNode).x ?? 0) + ((item.target as EvidenceNode).x ?? 0)) / 2,
        )
        .attr(
          "y",
          (item) =>
            (((item.source as EvidenceNode).y ?? 0) + ((item.target as EvidenceNode).y ?? 0)) / 2 -
            6,
        );

      node.attr("transform", (item) => `translate(${item.x ?? 0},${item.y ?? 0})`);
    });

    onSelect(nodes[0]);
    return () => {
      simulation.stop();
    };
  }, [links, nodes, onSelect]);

  return (
    <div className="overflow-hidden rounded-lg border border-border bg-background/40 scan-grid">
      <svg
        ref={svgRef}
        viewBox="0 0 920 520"
        className="block h-[520px] w-full min-w-[720px]"
        role="img"
        aria-label="Force directed evidence graph"
      />
    </div>
  );
}

const graphExport = {
  case_id: "proofsift-demo-001",
  generated_by: "ProofSIFT demo force graph",
  nodes: [
    {
      id: "evil.exe",
      kind: "process",
      artifact_id: "proc-1888",
      sha256: "9f3c2b01...b201",
      status: "CONFIRMED_CRITICAL",
    },
    {
      id: "203.0.113.50",
      kind: "network",
      artifact_id: "net-203-443",
      source: "memory_netscan",
      remote_port: 443,
    },
    {
      id: "HKCU\\Run",
      kind: "registry",
      artifact_id: "reg-updater",
      value: "Updater",
      data: "C:\\Users\\Public\\evil.exe",
    },
    {
      id: "EVIL.EXE-9A8B7C6D.pf",
      kind: "prefetch",
      artifact_id: "pf-evil-9a8b7c6d",
      execution_count: 3,
    },
  ],
  edges: [
    { source: "evil.exe", target: "203.0.113.50", relation: "beaconed_to" },
    { source: "evil.exe", target: "HKCU\\Run", relation: "persisted_by" },
    { source: "evil.exe", target: "EVIL.EXE-9A8B7C6D.pf", relation: "executed_as" },
  ],
};

function downloadJson(filename: string, payload: unknown) {
  downloadTextFile(filename, `${JSON.stringify(payload, null, 2)}\n`, "application/json");
}

function GraphPage() {
  const [selected, setSelected] = useState<EvidenceNode | null>(null);
  const Icon = selected ? nodeIcon(selected.kind) : Fingerprint;

  return (
    <div className="space-y-6 p-6">
      <div>
        <div className="font-mono text-[11px] uppercase tracking-[0.25em] text-confirmed">
          // force-directed evidence graph
        </div>
        <h1 className="mt-1 text-3xl font-semibold tracking-tight">
          Interactive Node-and-Edge Proof Network
        </h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Drag nodes to inspect the relationship between execution, persistence, prefetch, and C2
          artifacts. Click a node to inspect its JSON.
        </p>
      </div>

      <div className="grid gap-6 xl:grid-cols-[1.5fr_0.8fr]">
        <Panel
          title="live graph canvas"
          subtitle="D3 force simulation · draggable artifacts"
          accent="confirmed"
          action={
            <button
              onClick={() => downloadJson("proofsift-demo-001-force-graph.json", graphExport)}
              className="inline-flex items-center gap-2 rounded-md border border-confirmed/50 bg-confirmed/10 px-3 py-1.5 font-mono text-[10px] uppercase tracking-widest text-confirmed transition hover:bg-confirmed/20"
            >
              <Download className="h-3 w-3" /> graph json
            </button>
          }
        >
          <ForceGraph onSelect={setSelected} />
          <div className="mt-3 flex flex-wrap gap-2">
            {(["process", "network", "registry", "prefetch"] as NodeKind[]).map((kind) => {
              const LegendIcon = nodeIcon(kind);
              return (
                <span
                  key={kind}
                  className={cn(
                    "inline-flex items-center gap-1.5 rounded border px-2 py-1 font-mono text-[10px] uppercase tracking-widest",
                    kindClass[kind],
                  )}
                >
                  <LegendIcon className="h-3 w-3" /> {kind}
                </span>
              );
            })}
          </div>
        </Panel>

        <Panel
          title="artifact inspector"
          subtitle={selected?.label ?? "select a node"}
          accent={selected?.kind === "process" ? "blocked" : "confirmed"}
        >
          {selected ? (
            <div className="space-y-4">
              <div
                className={cn(
                  "inline-flex items-center gap-2 rounded border px-2.5 py-1.5 font-mono text-[10px] uppercase tracking-widest",
                  kindClass[selected.kind],
                )}
              >
                <Icon className="h-3.5 w-3.5" /> {selected.kind}
              </div>
              <button
                onClick={() =>
                  downloadJson(
                    `proofsift-demo-001-${selected.id.replace(/[^a-z0-9.-]+/gi, "-")}.json`,
                    selected.artifact,
                  )
                }
                className="inline-flex items-center gap-2 rounded-md border border-border bg-background/50 px-3 py-1.5 font-mono text-[10px] uppercase tracking-widest text-muted-foreground transition hover:border-confirmed/50 hover:text-confirmed"
              >
                <Download className="h-3 w-3" /> selected artifact json
              </button>
              <pre className="max-h-[440px] overflow-auto rounded-md border border-border bg-[var(--terminal-bg)] p-4 font-mono text-xs leading-relaxed text-foreground">
                {JSON.stringify(selected.artifact, null, 2)}
              </pre>
            </div>
          ) : (
            <div className="rounded-md border border-border bg-muted/20 p-4 text-sm text-muted-foreground">
              Click any graph node to inspect its artifact payload.
            </div>
          )}
        </Panel>
      </div>
    </div>
  );
}
