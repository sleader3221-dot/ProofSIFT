import React, { memo, useCallback, useMemo, useState } from 'react';
import {
  Background,
  BaseEdge,
  Controls,
  EdgeLabelRenderer,
  Handle,
  MarkerType,
  MiniMap,
  Panel,
  Position,
  ReactFlow,
  ReactFlowProvider,
  getSmoothStepPath,
  useReactFlow,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import {
  Activity,
  Bot,
  BrainCircuit,
  Braces,
  Clock,
  Database,
  FileCheck2,
  FileJson,
  FileSearch,
  GitBranch,
  HardDrive,
  LockKeyhole,
  MemoryStick,
  Network,
  Radar,
  Route,
  ScrollText,
  ShieldAlert,
  ShieldCheck,
  Terminal,
} from 'lucide-react';

const palette = {
  blue: '#38bdf8',
  amber: '#f59e0b',
  red: '#ff334e',
  teal: '#2dd4bf',
  indigo: '#818cf8',
  violet: '#a78bfa',
  green: '#22c55e',
  slate950: '#020617',
  slate900: '#0f172a',
  slate800: '#1e293b',
  slate500: '#64748b',
  slate300: '#cbd5e1',
};

const toneMap = {
  blue: palette.blue,
  amber: palette.amber,
  red: palette.red,
  teal: palette.teal,
  indigo: palette.indigo,
  violet: palette.violet,
  green: palette.green,
  slate: palette.slate500,
};

const nodeDefaults = {
  minWidth: 250,
  minHeight: 142,
};

const chipSets = {
  capabilityMatrix: [
    'pslist',
    'psscan',
    'netscan',
    'malfind',
    'Prefetch',
    'Amcache',
    'Shimcache',
    'MFT',
    'USN',
    'EVTX',
    '4688',
    'PowerShell',
    'YARA',
    'SHA-256',
    'SafePathPolicy',
    'Clock drift',
    'Timestomp',
    'MITRE chain',
    'Confidence scoring',
    'Benchmark',
    'Spoliation tests',
    'JSONL traces',
    'SQLite graph',
    'Report links',
  ],
};

function nodeHandleStyle(accent) {
  return {
    width: 10,
    height: 10,
    background: accent,
    borderColor: palette.slate950,
    boxShadow: `0 0 12px ${accent}99`,
  };
}

const ArchitectureNode = memo(function ArchitectureNode({ data, selected }) {
  const Icon = data.icon ?? Braces;
  const accent = data.accent ?? palette.blue;

  return (
    <div
      className={`proof-node ${selected ? 'proof-node--selected' : ''}`}
      style={{
        '--node-accent': accent,
        '--node-background':
          data.background ??
          'linear-gradient(180deg, rgba(15,23,42,0.98), rgba(9,9,11,0.98))',
        minWidth: data.minWidth ?? nodeDefaults.minWidth,
        minHeight: data.minHeight ?? nodeDefaults.minHeight,
      }}
    >
      {data.handles !== false && (
        <>
          <Handle type="target" position={Position.Left} style={nodeHandleStyle(accent)} />
          <Handle type="source" position={Position.Right} style={nodeHandleStyle(accent)} />
        </>
      )}

      <div className="proof-node__header">
        <div className="proof-node__icon" aria-hidden="true">
          <Icon size={21} strokeWidth={2.25} />
        </div>
        <div className="proof-node__copy">
          {data.kicker && <div className="proof-node__kicker">{data.kicker}</div>}
          <div className="proof-node__title">{data.label}</div>
        </div>
      </div>

      {data.description && <div className="proof-node__description">{data.description}</div>}

      {data.metrics?.length > 0 && (
        <div className="proof-node__metrics">
          {data.metrics.map((metric) => (
            <div className="proof-node__metric" key={`${data.label}-${metric.value}`}>
              <span>{metric.value}</span>
              <small>{metric.label}</small>
            </div>
          ))}
        </div>
      )}

      {data.badges?.length > 0 && (
        <div className="proof-node__badges">
          {data.badges.map((badge) => (
            <span className="proof-node__badge" key={badge}>
              {badge}
            </span>
          ))}
        </div>
      )}
    </div>
  );
});

const BoundaryNode = memo(function BoundaryNode({ data, selected }) {
  return (
    <div className={`boundary-node ${selected ? 'boundary-node--selected' : ''}`}>
      <Handle type="target" position={Position.Left} style={nodeHandleStyle(palette.red)} />
      <Handle type="source" position={Position.Right} style={nodeHandleStyle(palette.red)} />

      <div className="boundary-node__header">
        <div className="boundary-node__icon" aria-hidden="true">
          <LockKeyhole size={26} />
        </div>
        <div>
          <div className="boundary-node__kicker">Structural Chokepoint</div>
          <div className="boundary-node__title">{data.label}</div>
        </div>
      </div>

      <div className="boundary-node__body">
        Type-safe JSON-RPC calls cross here. The LLM receives no raw shell executor,
        and writes to registered evidence roots are denied before tools run.
      </div>

      <div className="boundary-node__callout">Click to verify zero-spoliation enforcement</div>
    </div>
  );
});

const GroupFrame = memo(function GroupFrame({ data, selected }) {
  const accent = data.accent ?? palette.teal;

  return (
    <div
      className={`proof-group ${selected ? 'proof-group--selected' : ''}`}
      style={{
        '--group-accent': accent,
        '--group-background': data.background ?? 'rgba(15,23,42,0.42)',
        '--group-border-style': data.borderStyle ?? 'solid',
      }}
    >
      <div className="proof-group__label">
        <span className="proof-group__icon">{data.icon}</span>
        <span>{data.label}</span>
      </div>
      {data.caption && <div className="proof-group__caption">{data.caption}</div>}
    </div>
  );
});

const CapabilityMatrixNode = memo(function CapabilityMatrixNode({ data, selected }) {
  return (
    <div className={`capability-node ${selected ? 'capability-node--selected' : ''}`}>
      <Handle type="target" position={Position.Left} style={nodeHandleStyle(palette.violet)} />
      <div className="capability-node__header">
        <FileCheck2 size={20} />
        <div>
          <div className="capability-node__kicker">{data.kicker}</div>
          <div className="capability-node__title">{data.label}</div>
        </div>
      </div>
      <div className="capability-node__chips">
        {data.capabilities.map((capability) => (
          <span key={capability}>{capability}</span>
        ))}
      </div>
    </div>
  );
});

function TrustEdge({
  id,
  sourceX,
  sourceY,
  targetX,
  targetY,
  sourcePosition,
  targetPosition,
  markerEnd,
  style,
  data,
}) {
  const [edgePath, labelX, labelY] = getSmoothStepPath({
    sourceX,
    sourceY,
    sourcePosition,
    targetX,
    targetY,
    targetPosition,
    borderRadius: data?.borderRadius ?? 24,
  });
  const tone = toneMap[data?.tone] ?? palette.blue;

  return (
    <>
      <BaseEdge
        id={id}
        path={edgePath}
        markerEnd={markerEnd}
        style={style}
        className={data?.animated ? 'trust-edge-path trust-edge-path--animated' : 'trust-edge-path'}
      />
      {data?.label && (
        <EdgeLabelRenderer>
          <div
            className="trust-edge-label"
            style={{
              '--edge-tone': tone,
              transform: `translate(-50%, -50%) translate(${labelX}px, ${labelY}px)`,
            }}
          >
            {data.label}
          </div>
        </EdgeLabelRenderer>
      )}
    </>
  );
}

const nodeTypes = {
  architecture: ArchitectureNode,
  boundary: BoundaryNode,
  capabilityMatrix: CapabilityMatrixNode,
  groupFrame: GroupFrame,
};

const edgeTypes = {
  trust: TrustEdge,
};

function marker(color) {
  return {
    type: MarkerType.ArrowClosed,
    width: 18,
    height: 18,
    color,
  };
}

function makeEdge(id, source, target, tone, label, options = {}) {
  const color = toneMap[tone] ?? palette.blue;

  return {
    id,
    source,
    target,
    type: 'trust',
    markerEnd: marker(color),
    zIndex: options.zIndex ?? 3,
    data: {
      tone,
      label,
      animated: options.animated ?? true,
      borderRadius: options.borderRadius,
    },
    style: {
      stroke: color,
      strokeWidth: options.strokeWidth ?? 2.8,
      strokeDasharray: options.dashed === false ? 'none' : options.dash ?? '10 7',
      filter: `drop-shadow(0 0 6px ${color}88)`,
    },
  };
}

function buildNodes() {
  return [
    {
      id: 'prompt-layer',
      type: 'groupFrame',
      position: { x: 320, y: 70 },
      style: { width: 760, height: 720 },
      selectable: false,
      draggable: false,
      data: {
        label: 'Prompt-Based Isolation Layer',
        caption:
          'Volatile reasoning can plan, critique, and request tools, but cannot mutate evidence or invoke shell access.',
        accent: palette.amber,
        borderStyle: 'dashed',
        background: 'rgba(120, 53, 15, 0.16)',
        icon: <BrainCircuit size={15} />,
      },
    },
    {
      id: 'sift-zone',
      type: 'groupFrame',
      position: { x: 1470, y: 70 },
      style: { width: 850, height: 720 },
      selectable: false,
      draggable: false,
      data: {
        label: 'Strict Architectural Guardrails (Zero Spoliation)',
        caption:
          'Read-only custom MCP tools convert forensic artifacts into typed observations while preserving original evidence.',
        accent: palette.teal,
        background: 'rgba(20, 184, 166, 0.11)',
        icon: <ShieldCheck size={15} />,
      },
    },
    {
      id: 'proof-zone',
      type: 'groupFrame',
      position: { x: 2490, y: 70 },
      style: { width: 880, height: 720 },
      selectable: false,
      draggable: false,
      data: {
        label: 'Deterministic Verification and Evidence Graph',
        caption:
          'Code-based validators normalize timelines, detect anti-forensics, and downgrade unsupported claims before reporting.',
        accent: palette.indigo,
        background: 'rgba(67, 56, 202, 0.12)',
        icon: <Database size={15} />,
      },
    },
    {
      id: 'delivery-zone',
      type: 'groupFrame',
      position: { x: 3550, y: 70 },
      style: { width: 700, height: 720 },
      selectable: false,
      draggable: false,
      data: {
        label: 'Judge-Facing Proof Package',
        caption:
          'Reports, accuracy metrics, traces, and submission artifacts are linked back to graph evidence.',
        accent: palette.violet,
        background: 'rgba(88, 28, 135, 0.13)',
        icon: <FileCheck2 size={15} />,
      },
    },
    {
      id: 'user',
      type: 'architecture',
      position: { x: 40, y: 328 },
      style: { width: 240 },
      data: {
        label: 'User / CLI',
        kicker: 'Investigation Entry',
        description: 'proofsift run, benchmark, trace, and submission validation.',
        icon: Terminal,
        accent: '#94a3b8',
        badges: ['CLI', 'SIFT VM', 'Devpost'],
      },
    },
    {
      id: 'engine',
      type: 'architecture',
      parentId: 'prompt-layer',
      extent: 'parent',
      position: { x: 42, y: 132 },
      style: { width: 272 },
      data: {
        label: 'Iterative Engine',
        kicker: 'Loop Control',
        description: 'Coordinates max-iteration investigation, verifier feedback, and graceful recovery.',
        icon: Route,
        accent: palette.blue,
        badges: ['Plan', 'Run', 'Correct'],
      },
    },
    {
      id: 'investigator',
      type: 'architecture',
      parentId: 'prompt-layer',
      extent: 'parent',
      position: { x: 392, y: 108 },
      style: { width: 318 },
      data: {
        label: 'Investigator Agent',
        kicker: 'Hypothesis Generation',
        description:
          'Generates candidate claims and selects forensic pivots across memory, disk, registry, and logs.',
        icon: Bot,
        accent: palette.blue,
        badges: ['C2', 'Execution', 'Persistence'],
      },
    },
    {
      id: 'critic',
      type: 'architecture',
      parentId: 'prompt-layer',
      extent: 'parent',
      position: { x: 392, y: 318 },
      style: { width: 318 },
      data: {
        label: 'Critic / Verifier Agent',
        kicker: 'Falsification Loop',
        description:
          'Blocks unsupported findings and requires multi-source corroboration before confirmation.',
        icon: ShieldAlert,
        accent: palette.amber,
        badges: ['Verify', 'Falsify', 'Downgrade'],
      },
    },
    {
      id: 'self-correction',
      type: 'architecture',
      parentId: 'prompt-layer',
      extent: 'parent',
      position: { x: 42, y: 390 },
      style: { width: 272 },
      data: {
        label: 'Self-Correction Scheduler',
        kicker: 'Targeted Re-Search',
        description:
          'Turns verifier gaps into exact next-tool instructions for missing attack-chain links.',
        icon: GitBranch,
        accent: palette.amber,
        badges: ['14 corrections', 'Trace-linked'],
      },
    },
    {
      id: 'prompt-contract',
      type: 'architecture',
      parentId: 'prompt-layer',
      extent: 'parent',
      position: { x: 112, y: 565 },
      style: { width: 548 },
      data: {
        label: 'Prompt Contract and Volatile Scratchpad',
        kicker: 'Soft Guardrails',
        description:
          'Reasoning stays disposable. Durable truth only lands through typed MCP outputs and graph writes.',
        icon: BrainCircuit,
        accent: palette.amber,
        badges: ['No raw evidence write', 'No shell terminal', 'Tool-only pivots'],
      },
    },
    {
      id: 'boundary',
      type: 'boundary',
      position: { x: 1130, y: 292 },
      style: { width: 310 },
      data: {
        label: 'SafePathPolicy & MCP JSON-RPC Bridge',
      },
    },
    {
      id: 'evidence-root',
      type: 'architecture',
      parentId: 'sift-zone',
      extent: 'parent',
      position: { x: 44, y: 105 },
      style: { width: 302 },
      data: {
        label: 'Read-Only Evidence Root',
        kicker: 'Immutable Case Mount',
        description: 'Case artifacts are opened through SafePathPolicy and never modified in place.',
        icon: LockKeyhole,
        accent: palette.teal,
        badges: ['deny writes', 'path scoped', 'hash first'],
      },
    },
    {
      id: 'tool-registry',
      type: 'architecture',
      parentId: 'sift-zone',
      extent: 'parent',
      position: { x: 436, y: 105 },
      style: { width: 344 },
      data: {
        label: 'Typed MCP Tool Registry',
        kicker: 'Parser Facade',
        description:
          'Pydantic-like typed contracts expose forensic parsers instead of arbitrary command execution.',
        icon: Braces,
        accent: palette.teal,
        badges: ['JSON-RPC', 'structured errors', 'no shell'],
      },
    },
    {
      id: 'disk',
      type: 'architecture',
      parentId: 'sift-zone',
      extent: 'parent',
      position: { x: 44, y: 300 },
      style: { width: 238 },
      data: {
        label: 'Disk Parsers',
        kicker: 'Prefetch / Amcache / MFT',
        description: 'Execution caches, filesystem timelines, Shimcache, and USN correlation.',
        icon: HardDrive,
        accent: palette.teal,
        badges: ['MFT', 'USN', 'Prefetch'],
      },
    },
    {
      id: 'memory',
      type: 'architecture',
      parentId: 'sift-zone',
      extent: 'parent',
      position: { x: 312, y: 300 },
      style: { width: 238 },
      data: {
        label: 'Memory Parsers',
        kicker: 'Volatility / Malfind',
        description: 'pslist, psscan, netscan, and injected-memory region extraction.',
        icon: MemoryStick,
        accent: palette.teal,
        badges: ['psscan', 'netscan', 'malfind'],
      },
    },
    {
      id: 'logs',
      type: 'architecture',
      parentId: 'sift-zone',
      extent: 'parent',
      position: { x: 580, y: 300 },
      style: { width: 238 },
      data: {
        label: 'Log Parsers',
        kicker: 'EVTX / PowerShell',
        description: 'Security 4688, PowerShell, and event timeline validation.',
        icon: FileJson,
        accent: palette.teal,
        badges: ['4688', 'EVTX', 'PS Logs'],
      },
    },
    {
      id: 'malformed-signal',
      type: 'architecture',
      parentId: 'sift-zone',
      extent: 'parent',
      position: { x: 44, y: 520 },
      style: { width: 360 },
      data: {
        label: 'Structured Parser Anomaly Capture',
        kicker: 'Defensive Degradation',
        description:
          'Malformed artifacts become graph signals instead of crashing or silently disappearing.',
        icon: ShieldAlert,
        accent: palette.green,
        badges: ['exception to observation', 'trace logged'],
      },
    },
    {
      id: 'spoliation-probe',
      type: 'architecture',
      parentId: 'sift-zone',
      extent: 'parent',
      position: { x: 462, y: 520 },
      style: { width: 356 },
      data: {
        label: 'Blocked Spoliation Probe',
        kicker: 'Administrative Proof',
        description:
          'Intentional write attempts are denied and recorded for the accuracy report.',
        icon: ShieldCheck,
        accent: palette.green,
        badges: ['blocked write', 'audit proof'],
      },
    },
    {
      id: 'evidence-graph',
      type: 'architecture',
      parentId: 'proof-zone',
      extent: 'parent',
      position: { x: 46, y: 100 },
      style: { width: 326 },
      data: {
        label: 'SQLite Evidence Graph',
        kicker: 'Claims and Observations',
        description:
          'Artifacts, claims, corrections, anomalies, and source trace links share one queryable audit surface.',
        icon: Database,
        accent: palette.indigo,
        background: 'linear-gradient(180deg, rgba(49,46,129,0.96), rgba(17,24,39,0.98))',
        metrics: [
          { value: '6', label: 'claims' },
          { value: '49', label: 'events' },
        ],
        badges: ['observations', 'claim_evidence', 'corrections'],
      },
    },
    {
      id: 'confidence',
      type: 'architecture',
      parentId: 'proof-zone',
      extent: 'parent',
      position: { x: 46, y: 332 },
      style: { width: 326 },
      data: {
        label: 'Claim Confidence Scorer',
        kicker: 'Verify-Falsify Gate',
        description:
          'Requires multi-source corroboration and downgrades claims when counter-evidence appears.',
        icon: Activity,
        accent: palette.indigo,
        badges: ['precision 1.0', 'recall 1.0', 'no hallucinated confirmed'],
      },
    },
    {
      id: 'execution-log',
      type: 'architecture',
      parentId: 'proof-zone',
      extent: 'parent',
      position: { x: 46, y: 535 },
      style: { width: 326 },
      data: {
        label: 'execution_log.jsonl',
        kicker: 'Granular Tool Trace',
        description:
          'Timestamped tool calls, correction reasons, token metrics, and blocked write attempts.',
        icon: Radar,
        accent: palette.violet,
        background: 'linear-gradient(180deg, rgba(76,29,149,0.94), rgba(17,24,39,0.98))',
        badges: ['JSONL', 'tokens', 'spoliation'],
      },
    },
    {
      id: 'clock-drift',
      type: 'architecture',
      parentId: 'proof-zone',
      extent: 'parent',
      position: { x: 456, y: 82 },
      style: { width: 360 },
      data: {
        label: 'Clock-Drift Normalizer',
        kicker: 'Temporal Delta',
        description:
          'Finds shared anchor events and offsets cross-source timestamps before correlation.',
        icon: Clock,
        accent: palette.indigo,
        badges: ['anchor match', '+120s delta', 'UTC normalized'],
      },
    },
    {
      id: 'anti-forensics',
      type: 'architecture',
      parentId: 'proof-zone',
      extent: 'parent',
      position: { x: 456, y: 292 },
      style: { width: 360 },
      data: {
        label: 'Differential Anti-Forensics Detector',
        kicker: 'Timestomp Signal',
        description:
          'Compares MFT, USN, and Prefetch execution order for impossible or divergent timestamps.',
        icon: FileSearch,
        accent: palette.red,
        badges: ['MFT vs Prefetch', '2 anomalies', 'confidence multiplier'],
      },
    },
    {
      id: 'mitre',
      type: 'architecture',
      parentId: 'proof-zone',
      extent: 'parent',
      position: { x: 456, y: 505 },
      style: { width: 360 },
      data: {
        label: 'MITRE ATT&CK Sequence Validator',
        kicker: 'Behavioral State Machine',
        description:
          'Requires logical progression from execution or persistence before high-impact C2 findings.',
        icon: Network,
        accent: palette.amber,
        badges: ['Execution', 'Persistence', 'C2'],
      },
    },
    {
      id: 'final-report',
      type: 'architecture',
      parentId: 'delivery-zone',
      extent: 'parent',
      position: { x: 42, y: 100 },
      style: { width: 280 },
      data: {
        label: 'Final Forensic Report',
        kicker: 'Judge-Readable Finding',
        description:
          'Only confirmed claims are promoted, with graph-backed evidence and correction history.',
        icon: ScrollText,
        accent: palette.violet,
        badges: ['report_3.md', 'HTML', 'Markdown'],
      },
    },
    {
      id: 'benchmark',
      type: 'architecture',
      parentId: 'delivery-zone',
      extent: 'parent',
      position: { x: 376, y: 100 },
      style: { width: 280 },
      data: {
        label: 'Benchmark Harness',
        kicker: 'Ground Truth Scoring',
        description:
          'Validates expected findings, false positives, hallucinated confirmations, and recall.',
        icon: Activity,
        accent: palette.green,
        metrics: [
          { value: '1.0', label: 'precision' },
          { value: '1.0', label: 'recall' },
        ],
        badges: ['passed', '0 FP'],
      },
    },
    {
      id: 'accuracy-report',
      type: 'architecture',
      parentId: 'delivery-zone',
      extent: 'parent',
      position: { x: 42, y: 315 },
      style: { width: 280 },
      data: {
        label: 'Accuracy and Spoliation Report',
        kicker: 'Submission Proof',
        description:
          'Documents false-positive metrics, clock drift, anomalies, and blocked write tests.',
        icon: ShieldCheck,
        accent: palette.violet,
        badges: ['accuracy_report.md', 'blocked writes'],
      },
    },
    {
      id: 'submission-docs',
      type: 'architecture',
      parentId: 'delivery-zone',
      extent: 'parent',
      position: { x: 376, y: 315 },
      style: { width: 280 },
      data: {
        label: 'Submission Docs Bundle',
        kicker: 'Devpost-Ready',
        description:
          'License, README, dataset documentation, architecture diagram, and execution traces.',
        icon: FileCheck2,
        accent: palette.violet,
        badges: ['MIT', 'README', 'dataset docs'],
      },
    },
    {
      id: 'capability-matrix',
      type: 'capabilityMatrix',
      parentId: 'delivery-zone',
      extent: 'parent',
      position: { x: 42, y: 522 },
      style: { width: 614 },
      data: {
        label: 'ProofSIFT Capability Matrix',
        kicker: 'Integrated Production Surface',
        capabilities: chipSets.capabilityMatrix,
      },
    },
  ];
}

function buildEdges() {
  return [
    makeEdge('user-engine', 'user', 'engine', 'blue', 'CLI command starts loop'),
    makeEdge('engine-investigator', 'engine', 'investigator', 'blue', 'volatile reasoning flow'),
    makeEdge('investigator-critic', 'investigator', 'critic', 'blue', 'candidate claim review'),
    makeEdge('critic-correction', 'critic', 'self-correction', 'amber', 'missing proof becomes next pivot'),
    makeEdge('correction-engine', 'self-correction', 'engine', 'amber', 'retry with targeted tools', {
      borderRadius: 36,
    }),
    makeEdge('critic-boundary', 'critic', 'boundary', 'red', 'Type-Safe Call (No Shell Access)', {
      strokeWidth: 5.2,
      dashed: false,
      animated: false,
      zIndex: 5,
    }),
    makeEdge('boundary-root', 'boundary', 'evidence-root', 'red', 'Path policy validates evidence root', {
      strokeWidth: 4.2,
      dashed: false,
      animated: false,
    }),
    makeEdge('boundary-tools', 'boundary', 'tool-registry', 'red', 'MCP JSON-RPC schema gate', {
      strokeWidth: 4.2,
      dashed: false,
      animated: false,
    }),
    makeEdge('root-disk', 'evidence-root', 'disk', 'teal', 'read-only artifact access'),
    makeEdge('root-memory', 'evidence-root', 'memory', 'teal', 'read-only artifact access'),
    makeEdge('root-logs', 'evidence-root', 'logs', 'teal', 'read-only artifact access'),
    makeEdge('tools-disk', 'tool-registry', 'disk', 'teal', 'typed parser call'),
    makeEdge('tools-memory', 'tool-registry', 'memory', 'teal', 'typed parser call'),
    makeEdge('tools-logs', 'tool-registry', 'logs', 'teal', 'typed parser call'),
    makeEdge('disk-graph', 'disk', 'evidence-graph', 'teal', 'Read-Only Output Extraction'),
    makeEdge('memory-graph', 'memory', 'evidence-graph', 'teal', 'Read-Only Output Extraction'),
    makeEdge('logs-graph', 'logs', 'evidence-graph', 'teal', 'Read-Only Output Extraction'),
    makeEdge('parser-signal-graph', 'malformed-signal', 'evidence-graph', 'green', 'malformed input logged as signal'),
    makeEdge('probe-log', 'spoliation-probe', 'execution-log', 'green', 'blocked write trace'),
    makeEdge('graph-clock', 'evidence-graph', 'clock-drift', 'indigo', 'anchor event optimization'),
    makeEdge('graph-anti', 'evidence-graph', 'anti-forensics', 'indigo', 'MFT / USN / Prefetch diff'),
    makeEdge('graph-mitre', 'evidence-graph', 'mitre', 'indigo', 'claim sequence validation'),
    makeEdge('clock-confidence', 'clock-drift', 'confidence', 'indigo', 'normalized timeline'),
    makeEdge('anti-confidence', 'anti-forensics', 'confidence', 'red', 'confidence adjustment'),
    makeEdge('mitre-confidence', 'mitre', 'confidence', 'amber', 'logical chain gate'),
    makeEdge('mitre-correction', 'mitre', 'self-correction', 'amber', 'targeted missing-link instruction'),
    makeEdge('confidence-report', 'confidence', 'final-report', 'violet', 'confirmed claims only'),
    makeEdge('log-benchmark', 'execution-log', 'benchmark', 'violet', 'trace and token metrics'),
    makeEdge('confidence-accuracy', 'confidence', 'accuracy-report', 'violet', 'precision / recall / FP accounting'),
    makeEdge('report-docs', 'final-report', 'submission-docs', 'violet', 'judge package cross-links'),
    makeEdge('benchmark-docs', 'benchmark', 'submission-docs', 'green', 'reproducible score evidence'),
    makeEdge('docs-matrix', 'submission-docs', 'capability-matrix', 'violet', 'integrated feature map'),
  ];
}

function GuardrailToast({ onClose }) {
  return (
    <div className="guardrail-toast" role="status">
      <div className="guardrail-toast__header">
        <ShieldAlert size={20} />
        <span>SPOLIATION BLOCKED</span>
      </div>
      <div className="guardrail-toast__body">
        All writes to the evidence root are structurally intercepted and dropped by the Python
        Custom MCP Server.
      </div>
      <button type="button" onClick={onClose}>
        Dismiss
      </button>
    </div>
  );
}

function NodeInspector({ node }) {
  if (!node) {
    return (
      <div className="node-inspector">
        <div className="node-inspector__kicker">Selection Inspector</div>
        <div className="node-inspector__title">Click any proof layer</div>
        <div className="node-inspector__body">
          The panel shows full component text here, so compact graph nodes never need to hide
          important audit wording.
        </div>
      </div>
    );
  }

  const details = node.data ?? {};

  return (
    <div className="node-inspector">
      <div className="node-inspector__kicker">{details.kicker ?? 'Architecture Layer'}</div>
      <div className="node-inspector__title">{details.label}</div>
      {details.description && <div className="node-inspector__body">{details.description}</div>}
      {details.badges?.length > 0 && (
        <div className="node-inspector__chips">
          {details.badges.map((badge) => (
            <span key={badge}>{badge}</span>
          ))}
        </div>
      )}
    </div>
  );
}

function ViewControls({ onFit }) {
  return (
    <div className="view-controls">
      <button type="button" onClick={onFit}>
        Fit All
      </button>
      <span>Drag, zoom, and click the red boundary for the enforcement proof.</span>
    </div>
  );
}

function DiagramSurface() {
  const nodes = useMemo(() => buildNodes(), []);
  const edges = useMemo(() => buildEdges(), []);
  const [toastVisible, setToastVisible] = useState(false);
  const [selectedNode, setSelectedNode] = useState(null);
  const flow = useReactFlow();

  const handleNodeClick = useCallback((_, node) => {
    setSelectedNode(node);
    if (node.id === 'boundary') {
      setToastVisible(true);
    }
  }, []);

  const fitAll = useCallback(() => {
    flow.fitView({ duration: 520, padding: 0.12 });
  }, [flow]);

  return (
    <section className="architecture-shell">
      <div className="architecture-frame">
        <ReactFlow
          className="proof-flow"
          nodes={nodes}
          edges={edges}
          nodeTypes={nodeTypes}
          edgeTypes={edgeTypes}
          fitView
          fitViewOptions={{ padding: 0.14, minZoom: 0.18, maxZoom: 1.02 }}
          minZoom={0.16}
          maxZoom={1.35}
          nodesDraggable
          nodesConnectable={false}
          elementsSelectable
          panOnDrag
          zoomOnScroll
          elevateEdgesOnSelect
          onNodeClick={handleNodeClick}
          onPaneClick={() => setSelectedNode(null)}
          defaultEdgeOptions={{ zIndex: 3 }}
          proOptions={{ hideAttribution: true }}
        >
          <Background color="#334155" gap={26} size={1} />
          <Controls position="bottom-left" className="proof-controls" />
          <MiniMap
            position="bottom-right"
            pannable
            zoomable
            nodeStrokeWidth={3}
            nodeColor={(node) => {
              if (node.id === 'boundary') return palette.red;
              if (node.parentId === 'sift-zone') return palette.teal;
              if (node.parentId === 'prompt-layer') return palette.amber;
              if (node.parentId === 'proof-zone') return palette.indigo;
              if (node.parentId === 'delivery-zone') return palette.violet;
              return '#64748b';
            }}
            className="proof-minimap"
          />
          <Panel position="top-left">
            <div className="hero-panel">
              <div className="hero-panel__eyebrow">ProofSIFT Security Visualization</div>
              <div className="hero-panel__title">Trust-Boundary Architecture</div>
              <div className="hero-panel__body">
                Prompt guardrails, code guardrails, forensic extraction, and judge-facing audit
                outputs are separated into explicit zones.
              </div>
            </div>
          </Panel>
          <Panel position="top-center">
            <ViewControls onFit={fitAll} />
          </Panel>
          <Panel position="bottom-center">
            <div className="legend-panel">
              <span className="legend-panel__item legend-panel__item--blue">Reasoning</span>
              <span className="legend-panel__item legend-panel__item--red">Security Gate</span>
              <span className="legend-panel__item legend-panel__item--teal">Read-Only Tools</span>
              <span className="legend-panel__item legend-panel__item--indigo">Verification</span>
              <span className="legend-panel__item legend-panel__item--violet">Deliverables</span>
            </div>
          </Panel>
          <Panel position="top-right">
            {toastVisible ? (
              <GuardrailToast onClose={() => setToastVisible(false)} />
            ) : (
              <NodeInspector node={selectedNode} />
            )}
          </Panel>
        </ReactFlow>
      </div>
    </section>
  );
}

export default function ProofSIFTArchitectureFlow() {
  return (
    <ReactFlowProvider>
      <DiagramSurface />
    </ReactFlowProvider>
  );
}
