import React, { memo, useCallback, useEffect, useMemo, useState } from 'react';
import {
  Background,
  BaseEdge,
  Handle,
  MarkerType,
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
  minHeight: 128,
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
    opacity: 0,
  };
}

function renderHandles(accent) {
  return (
    <>
      <Handle id="target-left" type="target" position={Position.Left} style={nodeHandleStyle(accent)} />
      <Handle id="source-left" type="source" position={Position.Left} style={nodeHandleStyle(accent)} />
      <Handle id="target-right" type="target" position={Position.Right} style={nodeHandleStyle(accent)} />
      <Handle id="source-right" type="source" position={Position.Right} style={nodeHandleStyle(accent)} />
      <Handle id="target-top" type="target" position={Position.Top} style={nodeHandleStyle(accent)} />
      <Handle id="source-top" type="source" position={Position.Top} style={nodeHandleStyle(accent)} />
      <Handle id="target-bottom" type="target" position={Position.Bottom} style={nodeHandleStyle(accent)} />
      <Handle id="source-bottom" type="source" position={Position.Bottom} style={nodeHandleStyle(accent)} />
    </>
  );
}

const ArchitectureNode = memo(function ArchitectureNode({ data, selected }) {
  const Icon = data.icon ?? Braces;
  const accent = data.accent ?? palette.blue;

  return (
    <div
      className={`proof-node ${data.compact ? 'proof-node--compact' : ''} ${
        selected ? 'proof-node--selected' : ''
      }`}
      style={{
        '--node-accent': accent,
        '--node-background':
          data.background ??
          'linear-gradient(180deg, rgba(15,23,42,0.98), rgba(9,9,11,0.98))',
        minWidth: data.minWidth ?? nodeDefaults.minWidth,
        minHeight: data.minHeight ?? nodeDefaults.minHeight,
      }}
    >
      {data.handles !== false && renderHandles(accent)}

      <div className="proof-node__header">
        <div className="proof-node__icon" aria-hidden="true">
          <Icon size={21} strokeWidth={2.25} />
        </div>
        <div className="proof-node__copy">
          {data.kicker && <div className="proof-node__kicker">{data.kicker}</div>}
          <div className="proof-node__title">{data.label}</div>
        </div>
      </div>

      {data.description && !data.compact && (
        <div className="proof-node__description">{data.description}</div>
      )}

      {data.metrics?.length > 0 && !data.compact && (
        <div className="proof-node__metrics">
          {data.metrics.map((metric) => (
            <div className="proof-node__metric" key={`${data.label}-${metric.value}`}>
              <span>{metric.value}</span>
              <small>{metric.label}</small>
            </div>
          ))}
        </div>
      )}

      {data.badges?.length > 0 && (!data.compact || data.showBadges) && (
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
    <div
      className={`boundary-node ${data.compact ? 'boundary-node--compact' : ''} ${
        selected ? 'boundary-node--selected' : ''
      }`}
    >
      {renderHandles(palette.red)}

      <div className="boundary-node__header">
        <div className="boundary-node__icon" aria-hidden="true">
          <LockKeyhole size={26} />
        </div>
        <div>
          <div className="boundary-node__kicker">Structural Chokepoint</div>
          <div className="boundary-node__title">{data.label}</div>
        </div>
      </div>

      {!data.compact && (
        <>
          <div className="boundary-node__body">
            Type-safe JSON-RPC calls cross here. The LLM receives no raw shell executor,
            and writes to registered evidence roots are denied before tools run.
          </div>

          <div className="boundary-node__callout">Click to verify zero-spoliation enforcement</div>
        </>
      )}
      {data.compact && <div className="boundary-node__callout">Click: zero-spoliation proof</div>}
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
  const visibleCapabilities = data.compact ? data.capabilities.slice(0, 10) : data.capabilities;
  const hiddenCount = data.capabilities.length - visibleCapabilities.length;

  return (
    <div className={`capability-node ${selected ? 'capability-node--selected' : ''}`}>
      {renderHandles(palette.violet)}
      <div className="capability-node__header">
        <FileCheck2 size={20} />
        <div>
          <div className="capability-node__kicker">{data.kicker}</div>
          <div className="capability-node__title">{data.label}</div>
        </div>
      </div>
      <div className="capability-node__chips">
        {visibleCapabilities.map((capability) => (
          <span key={capability}>{capability}</span>
        ))}
        {hiddenCount > 0 && <span>+{hiddenCount} more</span>}
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
  const [edgePath] = getSmoothStepPath({
    sourceX,
    sourceY,
    sourcePosition,
    targetX,
    targetY,
    targetPosition,
    borderRadius: data?.borderRadius ?? 24,
  });

  return (
    <BaseEdge
      id={id}
      path={edgePath}
      markerEnd={markerEnd}
      style={style}
      className="trust-edge-path trust-edge-path--dynamic"
    />
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

function makeEdge(id, source, target, tone, _label, options = {}) {
  const color = toneMap[tone] ?? palette.blue;

  return {
    id,
    source,
    target,
    type: 'trust',
    sourceHandle: options.sourceHandle ?? 'source-right',
    targetHandle: options.targetHandle ?? 'target-left',
    markerEnd: marker(color),
    zIndex: options.zIndex ?? 3,
    data: {
      tone,
      borderRadius: options.borderRadius,
    },
    style: {
      stroke: color,
      strokeWidth: options.strokeWidth ?? 3.4,
      strokeDasharray: options.dash ?? '14 10',
      filter: `drop-shadow(0 0 9px ${color}cc)`,
    },
  };
}

const nodeCatalog = {
  user: {
    type: 'architecture',
    data: {
      label: 'User / CLI',
      kicker: 'Investigation Entry',
      description: 'proofsift run, benchmark, trace, and submission validation.',
      icon: Terminal,
      accent: '#94a3b8',
      badges: ['CLI', 'SIFT VM', 'Devpost'],
    },
  },
  engine: {
    type: 'architecture',
    data: {
      label: 'Iterative Engine',
      kicker: 'Loop Control',
      description: 'Coordinates max-iteration investigation, verifier feedback, and recovery.',
      icon: Route,
      accent: palette.blue,
      badges: ['Plan', 'Run', 'Correct'],
    },
  },
  investigator: {
    type: 'architecture',
    data: {
      label: 'Investigator Agent',
      kicker: 'Hypothesis Generation',
      description: 'Creates candidate findings and selects forensic pivots across artifact classes.',
      icon: Bot,
      accent: palette.blue,
      badges: ['C2', 'Execution', 'Persistence'],
    },
  },
  critic: {
    type: 'architecture',
    data: {
      label: 'Critic / Verifier Agent',
      kicker: 'Falsification Loop',
      description: 'Blocks unsupported claims and requires multi-source corroboration.',
      icon: ShieldAlert,
      accent: palette.amber,
      badges: ['Verify', 'Falsify', 'Downgrade'],
    },
  },
  'self-correction': {
    type: 'architecture',
    data: {
      label: 'Self-Correction Scheduler',
      kicker: 'Targeted Re-Search',
      description: 'Turns proof gaps into exact next-tool instructions.',
      icon: GitBranch,
      accent: palette.amber,
      badges: ['14 corrections', 'Trace-linked'],
    },
  },
  'prompt-contract': {
    type: 'architecture',
    data: {
      label: 'Volatile Prompt Contract',
      kicker: 'Soft Guardrail',
      description: 'Reasoning is disposable. Durable truth only enters via typed MCP outputs.',
      icon: BrainCircuit,
      accent: palette.amber,
      badges: ['No shell', 'No evidence writes', 'Tool-only pivots'],
    },
  },
  boundary: {
    type: 'boundary',
    data: {
      label: 'SafePathPolicy & MCP JSON-RPC Bridge',
    },
  },
  'evidence-root': {
    type: 'architecture',
    data: {
      label: 'Read-Only Evidence Root',
      kicker: 'Immutable Case Mount',
      description: 'Case artifacts are opened through scoped path checks and never modified.',
      icon: LockKeyhole,
      accent: palette.teal,
      badges: ['deny writes', 'path scoped', 'hash first'],
    },
  },
  'tool-registry': {
    type: 'architecture',
    data: {
      label: 'Typed MCP Tool Registry',
      kicker: 'Parser Facade',
      description: 'Structured JSON-RPC contracts expose parsers instead of arbitrary commands.',
      icon: Braces,
      accent: palette.teal,
      badges: ['JSON-RPC', 'structured errors', 'no shell'],
    },
  },
  disk: {
    type: 'architecture',
    data: {
      label: 'Disk Parsers',
      kicker: 'Prefetch / Amcache / MFT',
      description: 'Execution caches, filesystem timelines, Shimcache, and USN correlation.',
      icon: HardDrive,
      accent: palette.teal,
      badges: ['MFT', 'USN', 'Prefetch'],
    },
  },
  memory: {
    type: 'architecture',
    data: {
      label: 'Memory Parsers',
      kicker: 'Volatility / Malfind',
      description: 'pslist, psscan, netscan, and injected-memory region extraction.',
      icon: MemoryStick,
      accent: palette.teal,
      badges: ['psscan', 'netscan', 'malfind'],
    },
  },
  logs: {
    type: 'architecture',
    data: {
      label: 'Log Parsers',
      kicker: 'EVTX / PowerShell',
      description: 'Security 4688, PowerShell, and event timeline validation.',
      icon: FileJson,
      accent: palette.teal,
      badges: ['4688', 'EVTX', 'PS Logs'],
    },
  },
  'malformed-signal': {
    type: 'architecture',
    data: {
      label: 'Parser Anomaly Capture',
      kicker: 'Defensive Degradation',
      description: 'Malformed artifacts become graph signals instead of silent failures.',
      icon: ShieldAlert,
      accent: palette.green,
      badges: ['exception to observation', 'trace logged'],
    },
  },
  'spoliation-probe': {
    type: 'architecture',
    data: {
      label: 'Blocked Spoliation Probe',
      kicker: 'Administrative Proof',
      description: 'Intentional write attempts are denied and recorded for reporting.',
      icon: ShieldCheck,
      accent: palette.green,
      badges: ['blocked write', 'audit proof'],
    },
  },
  'evidence-graph': {
    type: 'architecture',
    data: {
      label: 'SQLite Evidence Graph',
      kicker: 'Claims and Observations',
      description: 'Artifacts, claims, corrections, anomalies, and trace links share one graph.',
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
  confidence: {
    type: 'architecture',
    data: {
      label: 'Claim Confidence Scorer',
      kicker: 'Verify-Falsify Gate',
      description: 'Promotes only corroborated claims and downgrades unsupported findings.',
      icon: Activity,
      accent: palette.indigo,
      badges: ['precision 1.0', 'recall 1.0', '0 hallucinated confirmed'],
    },
  },
  'execution-log': {
    type: 'architecture',
    data: {
      label: 'execution_log.jsonl',
      kicker: 'Granular Tool Trace',
      description: 'Timestamped tools, correction reasons, token metrics, and blocked writes.',
      icon: Radar,
      accent: palette.violet,
      background: 'linear-gradient(180deg, rgba(76,29,149,0.94), rgba(17,24,39,0.98))',
      badges: ['JSONL', 'tokens', 'spoliation'],
    },
  },
  'clock-drift': {
    type: 'architecture',
    data: {
      label: 'Clock-Drift Normalizer',
      kicker: 'Temporal Delta',
      description: 'Finds shared anchor events and offsets timestamps before correlation.',
      icon: Clock,
      accent: palette.indigo,
      badges: ['anchor match', '+120s delta', 'UTC normalized'],
    },
  },
  'anti-forensics': {
    type: 'architecture',
    data: {
      label: 'Differential Anti-Forensics Detector',
      kicker: 'Timestomp Signal',
      description: 'Compares MFT, USN, and Prefetch for impossible timestamp order.',
      icon: FileSearch,
      accent: palette.red,
      badges: ['MFT vs Prefetch', '2 anomalies', 'confidence multiplier'],
    },
  },
  mitre: {
    type: 'architecture',
    data: {
      label: 'MITRE ATT&CK Sequence Validator',
      kicker: 'Behavioral State Machine',
      description: 'Requires logical execution or persistence before high-impact C2 findings.',
      icon: Network,
      accent: palette.amber,
      badges: ['Execution', 'Persistence', 'C2'],
    },
  },
  'final-report': {
    type: 'architecture',
    data: {
      label: 'Final Forensic Report',
      kicker: 'Judge-Readable Finding',
      description: 'Confirmed claims are promoted with graph-backed evidence links.',
      icon: ScrollText,
      accent: palette.violet,
      badges: ['report_3.md', 'HTML', 'Markdown'],
    },
  },
  benchmark: {
    type: 'architecture',
    data: {
      label: 'Benchmark Harness',
      kicker: 'Ground Truth Scoring',
      description: 'Validates expected findings, false positives, hallucinated claims, and recall.',
      icon: Activity,
      accent: palette.green,
      metrics: [
        { value: '1.0', label: 'precision' },
        { value: '1.0', label: 'recall' },
      ],
      badges: ['passed', '0 FP'],
    },
  },
  'accuracy-report': {
    type: 'architecture',
    data: {
      label: 'Accuracy and Spoliation Report',
      kicker: 'Submission Proof',
      description: 'Documents false positives, drift, anomalies, and blocked write tests.',
      icon: ShieldCheck,
      accent: palette.violet,
      badges: ['accuracy_report.md', 'blocked writes'],
    },
  },
  'submission-docs': {
    type: 'architecture',
    data: {
      label: 'Submission Docs Bundle',
      kicker: 'Devpost-Ready',
      description: 'License, README, dataset notes, architecture diagram, and traces.',
      icon: FileCheck2,
      accent: palette.violet,
      badges: ['MIT', 'README', 'dataset docs'],
    },
  },
  'capability-matrix': {
    type: 'capabilityMatrix',
    data: {
      label: 'ProofSIFT Capability Matrix',
      kicker: 'Integrated Production Surface',
      capabilities: chipSets.capabilityMatrix,
    },
  },
};

const zoneCatalog = {
  prompt: {
    label: 'Prompt-Based Isolation Layer',
    caption: 'Volatile LLM reasoning can plan and critique, but cannot mutate evidence.',
    accent: palette.amber,
    borderStyle: 'dashed',
    background: 'rgba(120, 53, 15, 0.16)',
    icon: <BrainCircuit size={15} />,
  },
  guardrail: {
    label: 'Strict Architectural Guardrails (Zero Spoliation)',
    caption: 'Read-only custom MCP tools preserve evidence and emit typed observations.',
    accent: palette.teal,
    background: 'rgba(20, 184, 166, 0.11)',
    icon: <ShieldCheck size={15} />,
  },
  proof: {
    label: 'Deterministic Verification and Evidence Graph',
    caption: 'Code-based validators normalize, falsify, and score claims before reporting.',
    accent: palette.indigo,
    background: 'rgba(67, 56, 202, 0.12)',
    icon: <Database size={15} />,
  },
  delivery: {
    label: 'Judge-Facing Proof Package',
    caption: 'Reports, metrics, traces, and submission artifacts remain evidence-linked.',
    accent: palette.violet,
    background: 'rgba(88, 28, 135, 0.13)',
    icon: <FileCheck2 size={15} />,
  },
};

function makeNode(id, x, y, width, options = {}) {
  const base = nodeCatalog[id];
  const compact = options.data?.compact ?? true;

  return {
    id,
    type: base.type,
    position: { x, y },
    style: { width, ...(options.style ?? {}) },
    data: { ...base.data, compact, ...(options.data ?? {}) },
    zIndex: options.zIndex ?? 2,
  };
}

function makeZone(id, zoneId, x, y, width, height, options = {}) {
  return {
    id,
    type: 'groupFrame',
    position: { x, y },
    style: { width, height },
    selectable: false,
    draggable: false,
    data: { ...zoneCatalog[zoneId], ...(options.data ?? {}) },
    zIndex: 0,
  };
}

const phases = [
  {
    id: 'reasoning',
    number: '01',
    tone: 'blue',
    eyebrow: 'Volatile Reasoning',
    title: 'Autonomous loop without evidence authority',
    summary:
      'ProofSIFT lets the LLM plan and critique, but keeps those thoughts volatile until typed tools produce durable evidence.',
    proof: ['Prompt layer is visually dashed amber', 'Self-correction is explicit', 'No raw shell or evidence write path exists here'],
    nodes: [
      makeZone('prompt-zone', 'prompt', 20, 46, 860, 560),
      makeNode('user', 36, 280, 220),
      makeNode('engine', 300, 140, 240),
      makeNode('investigator', 600, 100, 230),
      makeNode('critic', 600, 310, 230),
      makeNode('self-correction', 300, 350, 240),
      makeNode('prompt-contract', 300, 480, 520),
    ],
    edges: [
      makeEdge('user-engine', 'user', 'engine', 'blue'),
      makeEdge('engine-investigator', 'engine', 'investigator', 'blue'),
      makeEdge('investigator-critic', 'investigator', 'critic', 'blue', undefined, {
        sourceHandle: 'source-bottom',
        targetHandle: 'target-top',
      }),
      makeEdge('critic-correction', 'critic', 'self-correction', 'amber', undefined, {
        sourceHandle: 'source-left',
        targetHandle: 'target-right',
      }),
      makeEdge('correction-engine', 'self-correction', 'engine', 'amber', undefined, {
        borderRadius: 36,
        sourceHandle: 'source-top',
        targetHandle: 'target-bottom',
      }),
    ],
  },
  {
    id: 'boundary',
    number: '02',
    tone: 'red',
    eyebrow: 'Hard Security Boundary',
    title: 'The only crossing point is SafePathPolicy',
    summary:
      'The red bridge is the audit-critical separation between prompt-generated intent and code-enforced filesystem safety.',
    proof: [
      'Type-Safe Call (No Shell Access)',
      'MCP Schema Gate',
      'Evidence-root writes are intercepted structurally',
    ],
    nodes: [
      makeZone('prompt-zone', 'prompt', 20, 70, 340, 460),
      makeZone('guardrail-zone', 'guardrail', 620, 70, 440, 460),
      makeNode('critic', 60, 240, 260),
      makeNode('boundary', 380, 230, 340),
      makeNode('evidence-root', 800, 140, 240),
      makeNode('tool-registry', 800, 340, 240),
    ],
    edges: [
      makeEdge('critic-boundary', 'critic', 'boundary', 'red', undefined, {
        strokeWidth: 5.2,
        dashed: false,
      }),
      makeEdge('boundary-root', 'boundary', 'evidence-root', 'red', undefined, {
        strokeWidth: 4.2,
        dashed: false,
        sourceHandle: 'source-right',
        targetHandle: 'target-left',
      }),
      makeEdge('boundary-tools', 'boundary', 'tool-registry', 'red', undefined, {
        strokeWidth: 4.2,
        dashed: false,
        sourceHandle: 'source-right',
        targetHandle: 'target-left',
      }),
    ],
  },
  {
    id: 'extraction',
    number: '03',
    tone: 'teal',
    eyebrow: 'Read-Only Extraction',
    title: 'Forensic tools produce typed observations',
    summary:
      'Disk, memory, and log parsers are isolated behind the MCP facade, with parser failures recorded as forensic signal.',
    proof: [
      'Read-Only Output Extraction',
      'Malformed inputs degrade safely',
      'Blocked write probes become audit evidence',
    ],
    nodes: [
      makeZone('guardrail-zone', 'guardrail', 20, 46, 980, 560),
      makeNode('boundary', 44, 240, 270),
      makeNode('evidence-root', 370, 100, 250),
      makeNode('tool-registry', 370, 330, 250),
      makeNode('disk', 690, 70, 240),
      makeNode('memory', 690, 250, 240),
      makeNode('logs', 690, 430, 240),
      makeNode('malformed-signal', 60, 460, 270),
      makeNode('spoliation-probe', 370, 480, 250),
    ],
    edges: [
      makeEdge('boundary-root', 'boundary', 'evidence-root', 'red', undefined, {
        strokeWidth: 4,
        dashed: false,
      }),
      makeEdge('boundary-tools', 'boundary', 'tool-registry', 'red', undefined, {
        strokeWidth: 4,
        dashed: false,
      }),
      makeEdge('root-tools', 'evidence-root', 'tool-registry', 'teal', undefined, {
        sourceHandle: 'source-bottom',
        targetHandle: 'target-top',
      }),
      makeEdge('tools-disk', 'tool-registry', 'disk', 'teal', undefined, {
        sourceHandle: 'source-top',
        targetHandle: 'target-left',
      }),
      makeEdge('tools-memory', 'tool-registry', 'memory', 'teal', undefined, {
        sourceHandle: 'source-right',
        targetHandle: 'target-left',
      }),
      makeEdge('tools-logs', 'tool-registry', 'logs', 'teal', undefined, {
        sourceHandle: 'source-bottom',
        targetHandle: 'target-left',
      }),
      makeEdge('tools-parser-signal', 'tool-registry', 'malformed-signal', 'green', undefined, {
        sourceHandle: 'source-left',
        targetHandle: 'target-right',
      }),
      makeEdge('tools-spoliation', 'tool-registry', 'spoliation-probe', 'green', undefined, {
        sourceHandle: 'source-bottom',
        targetHandle: 'target-top',
      }),
    ],
  },
  {
    id: 'verification',
    number: '04',
    tone: 'indigo',
    eyebrow: 'Deterministic Verification',
    title: 'Claims are normalized, challenged, and scored',
    summary:
      'The graph feeds strict validators for clock drift, timestomping, MITRE progression, and confidence scoring.',
    proof: ['Clock drift uses anchor events', 'Timestomp anomalies adjust confidence', 'MITRE gaps force targeted self-correction'],
    nodes: [
      makeZone('proof-zone', 'proof', 20, 46, 1000, 560),
      makeNode('evidence-graph', 50, 120, 300),
      makeNode('execution-log', 50, 380, 300),
      makeNode('clock-drift', 430, 70, 320),
      makeNode('anti-forensics', 430, 270, 320),
      makeNode('mitre', 430, 470, 320),
      makeNode('confidence', 800, 260, 260),
      makeNode('self-correction', 800, 460, 260),
    ],
    edges: [
      makeEdge('graph-clock', 'evidence-graph', 'clock-drift', 'indigo', undefined, {
        sourceHandle: 'source-right',
        targetHandle: 'target-left',
      }),
      makeEdge('graph-anti', 'evidence-graph', 'anti-forensics', 'indigo', undefined, {
        sourceHandle: 'source-right',
        targetHandle: 'target-left',
      }),
      makeEdge('graph-mitre', 'evidence-graph', 'mitre', 'indigo', undefined, {
        sourceHandle: 'source-right',
        targetHandle: 'target-left',
      }),
      makeEdge('graph-log', 'evidence-graph', 'execution-log', 'violet', undefined, {
        sourceHandle: 'source-bottom',
        targetHandle: 'target-top',
      }),
      makeEdge('clock-confidence', 'clock-drift', 'confidence', 'indigo', undefined, {
        sourceHandle: 'source-right',
        targetHandle: 'target-top',
      }),
      makeEdge('anti-confidence', 'anti-forensics', 'confidence', 'red', undefined, {
        sourceHandle: 'source-right',
        targetHandle: 'target-left',
      }),
      makeEdge('mitre-confidence', 'mitre', 'confidence', 'amber', undefined, {
        sourceHandle: 'source-right',
        targetHandle: 'target-bottom',
      }),
      makeEdge('mitre-correction', 'mitre', 'self-correction', 'amber', undefined, {
        sourceHandle: 'source-right',
        targetHandle: 'target-left',
      }),
    ],
  },
  {
    id: 'delivery',
    number: '05',
    tone: 'violet',
    eyebrow: 'Judge-Facing Evidence',
    title: 'Every deliverable traces back to proof',
    summary:
      'Final reports, benchmark scores, spoliation results, and docs are tied back to the evidence graph and execution log.',
    proof: ['Precision and recall are surfaced', 'Submission bundle is explicit', 'Capability matrix shows integrated coverage'],
    nodes: [
      makeZone('delivery-zone', 'delivery', 20, 46, 1000, 600),
      makeNode('confidence', 52, 122, 236),
      makeNode('execution-log', 52, 350, 236),
      makeNode('final-report', 370, 80, 270),
      makeNode('benchmark', 370, 290, 270),
      makeNode('accuracy-report', 690, 80, 270),
      makeNode('submission-docs', 690, 290, 270),
      makeNode('capability-matrix', 272, 500, 700),
    ],
    edges: [
      makeEdge('confidence-report', 'confidence', 'final-report', 'violet'),
      makeEdge('confidence-accuracy', 'confidence', 'accuracy-report', 'violet', undefined, {
        sourceHandle: 'source-bottom',
        targetHandle: 'target-bottom',
        borderRadius: 40,
      }),
      makeEdge('log-benchmark', 'execution-log', 'benchmark', 'violet'),
      makeEdge('report-docs', 'final-report', 'submission-docs', 'violet', undefined, {
        sourceHandle: 'source-bottom',
        targetHandle: 'target-top',
      }),
      makeEdge('benchmark-docs', 'benchmark', 'submission-docs', 'green'),
      makeEdge('docs-matrix', 'submission-docs', 'capability-matrix', 'violet', undefined, {
        sourceHandle: 'source-bottom',
        targetHandle: 'target-top',
      }),
    ],
  },
];

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

function NodeInspector({ node, phase }) {
  if (!node) {
    return (
      <div className="node-inspector">
        <div className="node-inspector__kicker">{phase.eyebrow}</div>
        <div className="node-inspector__title">{phase.title}</div>
        <div className="node-inspector__body">{phase.summary}</div>
        <div className="node-inspector__chips">
          {phase.proof.map((item) => (
            <span key={item}>{item}</span>
          ))}
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
      {details.capabilities?.length > 0 && (
        <div className="node-inspector__chips">
          {details.capabilities.map((capability) => (
            <span key={capability}>{capability}</span>
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
        Fit Phase
      </button>
      <span>Click a phase card to focus the architecture.</span>
    </div>
  );
}

function DiagramSurface() {
  const [activePhaseIndex, setActivePhaseIndex] = useState(0);
  const activePhase = phases[activePhaseIndex];
  const nodes = useMemo(() => activePhase.nodes, [activePhase]);
  const edges = useMemo(() => activePhase.edges, [activePhase]);
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
    flow.fitView({ duration: 520, padding: 0.13 });
  }, [flow]);

  useEffect(() => {
    setSelectedNode(null);
    setToastVisible(false);
    const id = window.requestAnimationFrame(() => {
      flow.fitView({ duration: 520, padding: 0.13 });
    });

    return () => window.cancelAnimationFrame(id);
  }, [activePhaseIndex, flow]);

  return (
    <section className="architecture-shell">
      <header className="architecture-intro">
        <div>
          <div className="architecture-intro__eyebrow">ProofSIFT Security Visualization</div>
          <h1>Trust-Boundary Architecture Walkthrough</h1>
        </div>
        <p>
          A guided, layer-by-layer view of how volatile reasoning is separated from code-enforced
          read-only forensic tooling and evidence-backed reporting.
        </p>
      </header>

      <div className="architecture-experience">
        <nav className="story-rail" aria-label="ProofSIFT architecture phases">
          {phases.map((phase, index) => (
            <article
              className={`story-step ${activePhaseIndex === index ? 'story-step--active' : ''}`}
              key={phase.id}
              role="button"
              tabIndex={0}
              onClick={() => setActivePhaseIndex(index)}
              onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setActivePhaseIndex(index); } }}
            >
              <div className="story-step__header">
                <span className={`story-step__number story-step__number--${phase.tone}`}>
                  {phase.number}
                </span>
                <span>
                  <span className="story-step__eyebrow">{phase.eyebrow}</span>
                  <strong>{phase.title}</strong>
                </span>
              </div>
              <p className="story-step__summary">{phase.summary}</p>
              <ul className="story-step__proof">
                {phase.proof.map((item) => (
                  <li key={item}>{item}</li>
                ))}
              </ul>
            </article>
          ))}
        </nav>

        <div className="graph-stage">
          <div className="graph-toolbar">
            <div className={`phase-badge phase-badge--${activePhase.tone}`}>
              <span>{activePhase.number}</span>
              <strong>{activePhase.eyebrow}</strong>
            </div>
            <ViewControls onFit={fitAll} />
          </div>
          <div className="architecture-frame">
            <ReactFlow
              className="proof-flow"
              nodes={nodes}
              edges={edges}
              nodeTypes={nodeTypes}
              edgeTypes={edgeTypes}
              fitView
              fitViewOptions={{ padding: 0.13, minZoom: 0.56, maxZoom: 1.05 }}
              minZoom={0.46}
              maxZoom={1.3}
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
              <Background color="#334155" gap={24} size={1} />
            </ReactFlow>
          </div>
          <div className="graph-detail-row">
            {toastVisible ? (
              <GuardrailToast onClose={() => setToastVisible(false)} />
            ) : (
              <NodeInspector node={selectedNode} phase={activePhase} />
            )}
            <div className="legend-panel">
              <span className="legend-panel__item legend-panel__item--blue">Reasoning</span>
              <span className="legend-panel__item legend-panel__item--red">Security Gate</span>
              <span className="legend-panel__item legend-panel__item--teal">Read-Only Tools</span>
              <span className="legend-panel__item legend-panel__item--indigo">Verification</span>
              <span className="legend-panel__item legend-panel__item--violet">Deliverables</span>
            </div>
          </div>
        </div>
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
