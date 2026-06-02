import React, { useCallback, useMemo, useState } from 'react';
import {
  Background,
  Controls,
  Handle,
  MarkerType,
  MiniMap,
  Panel,
  Position,
  ReactFlow,
  ReactFlowProvider,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import {
  Bot,
  BrainCircuit,
  Braces,
  Database,
  FileJson,
  HardDrive,
  LockKeyhole,
  MemoryStick,
  Radar,
  Route,
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
  zinc950: '#09090b',
  slate950: '#020617',
  slate900: '#0f172a',
  slate800: '#1e293b',
  slate300: '#cbd5e1',
};

const nodeShell = {
  width: '100%',
  height: '100%',
  borderRadius: 8,
  position: 'relative',
  overflow: 'hidden',
  display: 'flex',
  flexDirection: 'column',
  justifyContent: 'space-between',
};

function ArchitectureNode({ data, selected }) {
  const Icon = data.icon ?? Braces;
  const accent = data.accent ?? palette.blue;

  return (
    <div
      style={{
        ...nodeShell,
        minWidth: data.minWidth ?? 210,
        minHeight: data.minHeight ?? 92,
        padding: 16,
        border: `1px solid ${selected ? '#f8fafc' : accent}`,
        background:
          data.background ??
          'linear-gradient(180deg, rgba(15,23,42,0.96), rgba(9,9,11,0.98))',
        boxShadow: selected
          ? `0 0 0 1px #f8fafc, 0 0 36px ${accent}66`
          : `0 0 24px ${accent}22`,
      }}
    >
      {data.handles !== false && (
        <>
          <Handle
            type="target"
            position={Position.Left}
            style={{ width: 8, height: 8, background: accent, borderColor: '#020617' }}
          />
          <Handle
            type="source"
            position={Position.Right}
            style={{ width: 8, height: 8, background: accent, borderColor: '#020617' }}
          />
        </>
      )}

      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        <div
          style={{
            width: 38,
            height: 38,
            borderRadius: 8,
            display: 'grid',
            placeItems: 'center',
            color: accent,
            background: `${accent}18`,
            border: `1px solid ${accent}44`,
          }}
        >
          <Icon size={20} strokeWidth={2.2} />
        </div>
        <div>
          <div
            style={{
              color: '#f8fafc',
              fontSize: 15,
              fontWeight: 760,
              letterSpacing: 0,
              lineHeight: 1.15,
            }}
          >
            {data.label}
          </div>
          {data.kicker && (
            <div
              style={{
                marginTop: 4,
                color: data.kickerColor ?? palette.slate300,
                fontSize: 11,
                fontWeight: 700,
                textTransform: 'uppercase',
                letterSpacing: 0,
              }}
            >
              {data.kicker}
            </div>
          )}
        </div>
      </div>

      {data.description && (
        <div
          style={{
            marginTop: 12,
            color: '#94a3b8',
            fontSize: 12,
            lineHeight: 1.35,
          }}
        >
          {data.description}
        </div>
      )}

      {data.badges?.length > 0 && (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginTop: 12 }}>
          {data.badges.map((badge) => (
            <span
              key={badge}
              style={{
                color: '#e2e8f0',
                border: `1px solid ${accent}55`,
                background: `${accent}14`,
                borderRadius: 6,
                padding: '4px 7px',
                fontSize: 10,
                fontWeight: 650,
                letterSpacing: 0,
              }}
            >
              {badge}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

function BoundaryNode({ data, selected }) {
  return (
    <div
      style={{
        ...nodeShell,
        minWidth: 300,
        minHeight: 148,
        padding: 18,
        border: `2px solid ${selected ? '#fff1f2' : palette.red}`,
        background: 'linear-gradient(180deg, rgba(69,10,10,0.98), rgba(9,9,11,0.98))',
        boxShadow: `0 0 0 1px ${palette.red}55, 0 0 44px ${palette.red}88, inset 0 0 28px ${palette.red}20`,
      }}
    >
      <Handle
        type="target"
        position={Position.Left}
        style={{ width: 10, height: 10, background: palette.red, borderColor: '#fff1f2' }}
      />
      <Handle
        type="source"
        position={Position.Right}
        style={{ width: 10, height: 10, background: palette.red, borderColor: '#fff1f2' }}
      />

      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        <div
          style={{
            width: 46,
            height: 46,
            borderRadius: 8,
            display: 'grid',
            placeItems: 'center',
            color: '#fff1f2',
            background: `${palette.red}2b`,
            border: `1px solid ${palette.red}`,
          }}
        >
          <LockKeyhole size={24} />
        </div>
        <div>
          <div style={{ color: '#fff1f2', fontSize: 17, fontWeight: 820, lineHeight: 1.1 }}>
            {data.label}
          </div>
          <div
            style={{
              marginTop: 5,
              color: '#fecdd3',
              fontSize: 11,
              fontWeight: 760,
              textTransform: 'uppercase',
              letterSpacing: 0,
            }}
          >
            Structural Chokepoint
          </div>
        </div>
      </div>

      <div style={{ color: '#fecdd3', fontSize: 12, lineHeight: 1.45, marginTop: 14 }}>
        Type-safe JSON-RPC calls cross here. The LLM layer receives no raw shell executor
        and cannot write to registered evidence roots.
      </div>

      <div
        style={{
          marginTop: 12,
          color: '#fff1f2',
          fontSize: 11,
          fontWeight: 760,
          border: '1px solid rgba(255,255,255,0.18)',
          background: 'rgba(255,255,255,0.07)',
          borderRadius: 6,
          padding: '8px 10px',
        }}
      >
        Click to verify zero-spoliation enforcement
      </div>
    </div>
  );
}

function GroupFrame({ data, selected }) {
  const borderStyle = data.borderStyle ?? 'solid';
  const accent = data.accent ?? palette.teal;

  return (
    <div
      style={{
        width: '100%',
        height: '100%',
        borderRadius: 8,
        border: `${data.borderWidth ?? 2}px ${borderStyle} ${accent}`,
        background: data.background ?? 'rgba(15,23,42,0.34)',
        boxShadow: selected ? `0 0 0 1px #f8fafc, 0 0 36px ${accent}44` : `0 0 32px ${accent}18`,
        padding: 14,
        pointerEvents: 'none',
      }}
    >
      <div
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: 8,
          color: data.labelColor ?? '#f8fafc',
          fontSize: 12,
          fontWeight: 820,
          textTransform: 'uppercase',
          letterSpacing: 0,
          padding: '6px 9px',
          borderRadius: 6,
          background: 'rgba(2,6,23,0.74)',
          border: `1px solid ${accent}55`,
        }}
      >
        {data.icon}
        {data.label}
      </div>
      {data.caption && (
        <div
          style={{
            marginTop: 8,
            maxWidth: 420,
            color: '#94a3b8',
            fontSize: 11,
            lineHeight: 1.35,
          }}
        >
          {data.caption}
        </div>
      )}
    </div>
  );
}

const nodeTypes = {
  architecture: ArchitectureNode,
  boundary: BoundaryNode,
  groupFrame: GroupFrame,
};

const marker = (color) => ({
  type: MarkerType.ArrowClosed,
  width: 18,
  height: 18,
  color,
});

const blueEdge = {
  type: 'smoothstep',
  animated: true,
  markerEnd: marker(palette.blue),
  style: { stroke: palette.blue, strokeWidth: 2.4, strokeDasharray: '8 7' },
};

const redEdge = {
  type: 'smoothstep',
  markerEnd: marker(palette.red),
  style: { stroke: palette.red, strokeWidth: 4.8 },
  labelStyle: { fill: '#fecdd3', fontWeight: 800, fontSize: 12 },
  labelBgStyle: { fill: 'rgba(69,10,10,0.96)', stroke: palette.red, strokeWidth: 1 },
  labelBgPadding: [10, 6],
  labelBgBorderRadius: 6,
};

const tealEdge = {
  type: 'smoothstep',
  animated: true,
  markerEnd: marker(palette.teal),
  style: { stroke: palette.teal, strokeWidth: 2.8, strokeDasharray: '10 6' },
  labelStyle: { fill: '#ccfbf1', fontWeight: 800, fontSize: 12 },
  labelBgStyle: { fill: 'rgba(19,78,74,0.92)', stroke: palette.teal, strokeWidth: 1 },
  labelBgPadding: [10, 6],
  labelBgBorderRadius: 6,
};

function buildNodes() {
  return [
    {
      id: 'prompt-layer',
      type: 'groupFrame',
      position: { x: 280, y: 56 },
      style: { width: 540, height: 430 },
      draggable: true,
      data: {
        label: 'Prompt-Based Isolation Layer',
        caption: 'Volatile LLM generation is allowed to reason, plan, and critique, but not to mutate evidence or execute shell commands.',
        accent: palette.amber,
        borderStyle: 'dashed',
        background: 'rgba(120, 53, 15, 0.18)',
        icon: <BrainCircuit size={14} />,
      },
    },
    {
      id: 'sift-tools',
      type: 'groupFrame',
      position: { x: 1190, y: 58 },
      style: { width: 500, height: 430 },
      draggable: true,
      data: {
        label: 'Strict Architectural Guardrails (Zero Spoliation)',
        caption: 'Typed wrappers expose read-only forensic extraction. Original evidence roots are never writable from this zone.',
        accent: palette.teal,
        background: 'rgba(20, 184, 166, 0.12)',
        icon: <ShieldCheck size={14} />,
      },
    },
    {
      id: 'user',
      type: 'architecture',
      position: { x: 40, y: 205 },
      style: { width: 210, height: 116 },
      data: {
        label: 'User / CLI',
        kicker: 'Investigation Entry',
        description: 'proofsift run / benchmark / trace',
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
      position: { x: 44, y: 112 },
      style: { width: 205, height: 120 },
      data: {
        label: 'Iterative Engine',
        kicker: 'Loop Control',
        description: 'Max-iteration orchestration with graceful degradation.',
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
      position: { x: 286, y: 82 },
      style: { width: 214, height: 124 },
      data: {
        label: 'Investigator Agent',
        kicker: 'Hypothesis Generation',
        description: 'Creates candidate findings and selects forensic pivots.',
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
      position: { x: 286, y: 260 },
      style: { width: 214, height: 126 },
      data: {
        label: 'Critic / Verifier Agent',
        kicker: 'Falsification Loop',
        description: 'Validates MITRE sequence, clock drift, and anti-forensics gaps.',
        icon: ShieldAlert,
        accent: palette.amber,
        badges: ['Verify', 'Falsify', 'Downgrade'],
      },
    },
    {
      id: 'boundary',
      type: 'boundary',
      position: { x: 885, y: 208 },
      style: { width: 300, height: 156 },
      data: {
        label: 'SafePathPolicy & MCP JSON-RPC Bridge',
      },
    },
    {
      id: 'disk',
      type: 'architecture',
      parentId: 'sift-tools',
      extent: 'parent',
      position: { x: 36, y: 96 },
      style: { width: 210, height: 118 },
      data: {
        label: 'Disk Parsers',
        kicker: 'Prefetch / Amcache / MFT',
        description: 'Execution caches, filesystem timelines, Shimcache, and USN.',
        icon: HardDrive,
        accent: palette.teal,
        badges: ['MFT', 'USN', 'Prefetch'],
      },
    },
    {
      id: 'memory',
      type: 'architecture',
      parentId: 'sift-tools',
      extent: 'parent',
      position: { x: 270, y: 96 },
      style: { width: 210, height: 118 },
      data: {
        label: 'Memory Parsers',
        kicker: 'Volatility / Malfind',
        description: 'pslist, psscan, netscan, and injected-memory regions.',
        icon: MemoryStick,
        accent: palette.teal,
        badges: ['psscan', 'netscan', 'malfind'],
      },
    },
    {
      id: 'logs',
      type: 'architecture',
      parentId: 'sift-tools',
      extent: 'parent',
      position: { x: 154, y: 270 },
      style: { width: 220, height: 118 },
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
      id: 'evidence-graph',
      type: 'architecture',
      position: { x: 1780, y: 142 },
      style: { width: 250, height: 128 },
      data: {
        label: 'SQLite Evidence Graph',
        kicker: 'Provable Audit Trail',
        description: 'Claims, observations, corrections, anomalies, and trace links.',
        icon: Database,
        accent: palette.indigo,
        background: 'linear-gradient(180deg, rgba(49,46,129,0.96), rgba(17,24,39,0.98))',
        badges: ['claims', 'observations', 'trace'],
      },
    },
    {
      id: 'execution-log',
      type: 'architecture',
      position: { x: 1780, y: 332 },
      style: { width: 250, height: 128 },
      data: {
        label: 'execution_log.jsonl',
        kicker: 'Timestamped Tool Trace',
        description: 'Every tool call, token metric, correction, and blocked spoliation probe.',
        icon: Radar,
        accent: palette.violet,
        background: 'linear-gradient(180deg, rgba(76,29,149,0.94), rgba(17,24,39,0.98))',
        badges: ['JSONL', 'tokens', 'corrections'],
      },
    },
  ];
}

function buildEdges() {
  return [
    { id: 'user-engine', source: 'user', target: 'engine', ...blueEdge },
    { id: 'engine-investigator', source: 'engine', target: 'investigator', ...blueEdge },
    { id: 'investigator-critic', source: 'investigator', target: 'critic', ...blueEdge },
    {
      id: 'critic-boundary',
      source: 'critic',
      target: 'boundary',
      label: 'Type-Safe Call (No Shell Access)',
      ...redEdge,
    },
    {
      id: 'boundary-disk',
      source: 'boundary',
      target: 'disk',
      label: 'Read-Only Output Extraction',
      ...tealEdge,
    },
    {
      id: 'boundary-memory',
      source: 'boundary',
      target: 'memory',
      label: 'Read-Only Output Extraction',
      ...tealEdge,
    },
    {
      id: 'boundary-logs',
      source: 'boundary',
      target: 'logs',
      label: 'Read-Only Output Extraction',
      ...tealEdge,
    },
    {
      id: 'disk-graph',
      source: 'disk',
      target: 'evidence-graph',
      label: 'Read-Only Output Extraction',
      ...tealEdge,
    },
    {
      id: 'memory-graph',
      source: 'memory',
      target: 'evidence-graph',
      label: 'Read-Only Output Extraction',
      ...tealEdge,
    },
    {
      id: 'logs-graph',
      source: 'logs',
      target: 'evidence-graph',
      label: 'Read-Only Output Extraction',
      ...tealEdge,
    },
    {
      id: 'graph-log',
      source: 'evidence-graph',
      target: 'execution-log',
      animated: true,
      type: 'smoothstep',
      markerEnd: marker(palette.violet),
      style: { stroke: palette.violet, strokeWidth: 2.5, strokeDasharray: '7 7' },
    },
  ];
}

function GuardrailToast({ onClose }) {
  return (
    <div
      role="status"
      style={{
        width: 410,
        borderRadius: 8,
        border: `1px solid ${palette.red}`,
        background: 'rgba(69,10,10,0.96)',
        color: '#fff1f2',
        boxShadow: `0 0 42px ${palette.red}88`,
        padding: 16,
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <ShieldAlert size={20} />
        <div style={{ fontWeight: 860, fontSize: 13, letterSpacing: 0 }}>
          SPOLIATION BLOCKED
        </div>
      </div>
      <div style={{ marginTop: 9, fontSize: 12, lineHeight: 1.45, color: '#fecdd3' }}>
        All writes to the evidence root are structurally intercepted and dropped by
        the Python Custom MCP Server.
      </div>
      <button
        type="button"
        onClick={onClose}
        style={{
          marginTop: 12,
          height: 30,
          borderRadius: 6,
          border: '1px solid rgba(255,255,255,0.22)',
          background: 'rgba(255,255,255,0.08)',
          color: '#fff1f2',
          fontWeight: 760,
          cursor: 'pointer',
        }}
      >
        Dismiss
      </button>
    </div>
  );
}

function DiagramSurface() {
  const nodes = useMemo(() => buildNodes(), []);
  const edges = useMemo(() => buildEdges(), []);
  const [toastVisible, setToastVisible] = useState(false);

  const handleNodeClick = useCallback((_, node) => {
    if (node.id === 'boundary') {
      setToastVisible(true);
    }
  }, []);

  return (
    <section
      style={{
        width: '100%',
        height: '100vh',
        minHeight: 720,
        background:
          'radial-gradient(circle at 50% 0%, rgba(14,165,233,0.10), transparent 32%), #020617',
        padding: 18,
      }}
    >
      <div
        style={{
          height: '100%',
          border: '1px solid rgba(148,163,184,0.18)',
          borderRadius: 8,
          background: 'rgba(9,9,11,0.82)',
          overflow: 'hidden',
          boxShadow: '0 30px 80px rgba(0,0,0,0.45)',
        }}
      >
        <ReactFlow
          nodes={nodes}
          edges={edges}
          nodeTypes={nodeTypes}
          fitView
          fitViewOptions={{ padding: 0.11, minZoom: 0.42, maxZoom: 1.2 }}
          minZoom={0.3}
          maxZoom={1.35}
          nodesDraggable
          nodesConnectable={false}
          elementsSelectable
          panOnDrag
          zoomOnScroll
          onNodeClick={handleNodeClick}
          defaultEdgeOptions={{ type: 'smoothstep' }}
          proOptions={{ hideAttribution: true }}
        >
          <Background color="#334155" gap={22} size={1} />
          <Controls
            position="bottom-left"
            style={{
              background: 'rgba(15,23,42,0.92)',
              border: '1px solid rgba(148,163,184,0.22)',
              borderRadius: 8,
              overflow: 'hidden',
            }}
          />
          <MiniMap
            position="bottom-right"
            pannable
            zoomable
            nodeStrokeWidth={3}
            nodeColor={(node) => {
              if (node.id === 'boundary') return palette.red;
              if (node.parentId === 'sift-tools') return palette.teal;
              if (node.parentId === 'prompt-layer') return palette.amber;
              if (node.id.includes('graph') || node.id.includes('log')) return palette.indigo;
              return '#64748b';
            }}
            style={{
              width: 170,
              height: 108,
              background: 'rgba(15,23,42,0.94)',
              border: '1px solid rgba(148,163,184,0.22)',
              borderRadius: 8,
            }}
          />
          <Panel position="top-left">
            <div
              style={{
                borderRadius: 8,
                border: '1px solid rgba(148,163,184,0.22)',
                background: 'rgba(2,6,23,0.84)',
                padding: '12px 14px',
                maxWidth: 430,
              }}
            >
              <div style={{ color: '#f8fafc', fontWeight: 860, fontSize: 16 }}>
                ProofSIFT Trust Architecture
              </div>
              <div style={{ marginTop: 5, color: '#94a3b8', fontSize: 12, lineHeight: 1.4 }}>
                Prompt reasoning is visually separated from code-enforced,
                read-only MCP boundaries and provable audit outputs.
              </div>
            </div>
          </Panel>
          <Panel position="top-right">
            {toastVisible && <GuardrailToast onClose={() => setToastVisible(false)} />}
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

