// ============================================================
// ProofSIFT — exact identifiers, metrics, and fixtures
// Sourced from sleader3221-dot/ProofSIFT (agent.py, tools.py,
// graph.py, anti_forensics.py, clock_drift.py, mitre_sequence.py,
// benchmark.py, reporting.py, security.py, cli.py)
// ============================================================

export const metrics = {
  ingestedArtifacts: 1429,
  generatedClaims: 6,
  selfCorrections: 23,
  clockDrifts: 1,
  clockDriftOffset: "120s",
  antiForensics: 2,
  spoliationBlocked: 2,
  counterfactualChecks: 8,
  bayesianScores: 15,
  merkleRoot: "sha256:<verified-root>",
};

export type ClaimStatus = "CONFIRMED - CRITICAL" | "INFERRED - HIGH" | "CONTEXT" | "REJECTED";

export interface Claim {
  id: string;
  status: ClaimStatus;
  title: string;
  confidence: number;
  severity: string;
  mitre: string[];
  note?: string;
  evidence: { source: string; detail: string }[];
}

export const claims: Claim[] = [
  {
    id: "clm-3c76c94c3ce5",
    status: "CONFIRMED - CRITICAL",
    title: "evil.exe communicated with known C2 indicator 203.0.113.50:443",
    confidence: 0.93,
    severity: "CRITICAL",
    mitre: ["T1071", "T1204", "T1059"],
    evidence: [
      { source: "memory_netscan", detail: "Network connection to 203.0.113.50:443 (PID 1888)" },
      { source: "disk_prefetch", detail: "EVIL.EXE (3 execution counts cached)" },
      { source: "disk_amcache", detail: "Unsigned binary SHA-256 hash lookup" },
      { source: "timeline_mft", detail: "Malicious binary file creation path" },
      {
        source: "memory_malfind",
        detail: "Process hollowing — PAGE_EXECUTE_READWRITE injected page",
      },
    ],
  },
  {
    id: "clm-44da40820635",
    status: "INFERRED - HIGH",
    title: "unknown.exe communicated with C2 indicator 198.51.100.24",
    confidence: 0.58,
    severity: "HIGH",
    mitre: ["T1071"],
    note: "Verifier capped status at INFERRED: <2 independent artifact kinds. Critic requested disk_prefetch + disk_amcache; not present.",
    evidence: [
      { source: "memory_netscan", detail: "Outbound TCP to 198.51.100.24:443" },
      { source: "disk_prefetch", detail: "NO MATCHING PREFETCH ENTRY (downgrade trigger)" },
      { source: "disk_amcache", detail: "NO MATCHING AMCACHE ENTRY (downgrade trigger)" },
    ],
  },
  {
    id: "clm-7f01a2b9c4d1",
    status: "CONFIRMED - CRITICAL",
    title: "Registry persistence: HKCU\\Run\\Updater -> evil.exe",
    confidence: 0.91,
    severity: "HIGH",
    mitre: ["T1060", "T1547.001"],
    evidence: [
      {
        source: "registry_autoruns",
        detail: "Updater value points to C:\\Users\\Public\\evil.exe",
      },
      { source: "disk_amcache", detail: "Same SHA-256 as confirmed C2 binary" },
    ],
  },
  {
    id: "clm-9d6efc0a11ab",
    status: "CONFIRMED - CRITICAL",
    title: "Anti-forensics: timestomping on evil.exe (created 14:10:05Z, modified 14:02:05Z)",
    confidence: 0.94,
    severity: "HIGH",
    mitre: ["T1070.006"],
    evidence: [
      { source: "timeline_mft", detail: "MFT $STANDARD_INFORMATION created-after-modified" },
      { source: "anomaly_engine", detail: "Bayesian anti-forensics signal applied" },
    ],
  },
  {
    id: "clm-2a8b34de77f0",
    status: "CONTEXT",
    title: "svchost.exe observed (negative control — not escalated)",
    confidence: 0.35,
    severity: "INFO",
    mitre: [],
    note: "Held as benign context. Negative control: common system process is retained as context, not reported as a finding.",
    evidence: [{ source: "memory_pslist", detail: "Signed Microsoft binary, expected parent" }],
  },
  {
    id: "clm-55c1ee84a020",
    status: "CONFIRMED - CRITICAL",
    title: "PowerShell staged evil.exe (parent-child execution chain)",
    confidence: 0.74,
    severity: "HIGH",
    mitre: ["T1059.001"],
    evidence: [
      { source: "windows_process_creation", detail: "Event 4688: powershell.exe -> evil.exe" },
      { source: "disk_prefetch", detail: "POWERSHELL.EXE 1 execution count" },
      { source: "yara_keyword_scan", detail: "payload_notes.txt — 'evil beacon initialized'" },
    ],
  },
];

// ---------------- 16 Typed Tools (ToolRunner.catalog) ----------------
export interface ToolDef {
  name: string;
  category: "memory" | "disk" | "registry" | "timeline" | "logs" | "ioc" | "guardrail";
  input: string;
  artifactKind: string;
  guardrail: string;
  siftWrap?: string;
}
export const toolCatalog: ToolDef[] = [
  {
    name: "hash_all_evidence",
    category: "guardrail",
    input: "evidence_dir/*",
    artifactKind: "evidence_hash",
    guardrail: "Read-only SHA-256 of every registered evidence file",
  },
  {
    name: "spoliation_probe",
    category: "guardrail",
    input: "policy test",
    artifactKind: "guardrail_test",
    guardrail: "Proves evidence-root writes are blocked",
  },
  {
    name: "memory_pslist",
    category: "memory",
    input: "processes.csv (pslist)",
    artifactKind: "process",
    guardrail: "Typed process artifacts",
    siftWrap: "Volatility windows.pslist",
  },
  {
    name: "memory_psscan",
    category: "memory",
    input: "processes.csv (psscan)",
    artifactKind: "process",
    guardrail: "Typed hidden-process artifacts",
    siftWrap: "Volatility windows.psscan",
  },
  {
    name: "memory_netscan",
    category: "memory",
    input: "netscan.csv",
    artifactKind: "network",
    guardrail: "Typed network artifacts",
    siftWrap: "Volatility windows.netscan",
  },
  {
    name: "memory_malfind",
    category: "memory",
    input: "malfind.csv",
    artifactKind: "malfind",
    guardrail: "Typed injected-memory artifacts",
    siftWrap: "Volatility windows.malfind",
  },
  {
    name: "disk_prefetch",
    category: "disk",
    input: "prefetch.csv",
    artifactKind: "prefetch",
    guardrail: "Typed execution artifacts",
    siftWrap: "PECmd / Prefetch parser",
  },
  {
    name: "disk_amcache",
    category: "disk",
    input: "amcache.csv",
    artifactKind: "amcache",
    guardrail: "Typed program inventory artifacts",
    siftWrap: "AmcacheParser",
  },
  {
    name: "disk_shimcache",
    category: "disk",
    input: "shimcache.csv",
    artifactKind: "shimcache",
    guardrail: "Typed application-compat execution artifacts",
    siftWrap: "AppCompatCacheParser",
  },
  {
    name: "registry_autoruns",
    category: "registry",
    input: "autoruns.csv",
    artifactKind: "autorun",
    guardrail: "Typed persistence artifacts",
    siftWrap: "RegRipper / Autoruns",
  },
  {
    name: "timeline_mft",
    category: "timeline",
    input: "mft.csv",
    artifactKind: "mft",
    guardrail: "Typed filesystem timeline artifacts",
    siftWrap: "MFTECmd",
  },
  {
    name: "timeline_usn",
    category: "timeline",
    input: "usn.csv",
    artifactKind: "usn",
    guardrail: "Typed filesystem journal artifacts",
    siftWrap: "MFTECmd USN",
  },
  {
    name: "windows_evtx",
    category: "logs",
    input: "evtx.csv",
    artifactKind: "evtx",
    guardrail: "Typed event-log artifacts",
    siftWrap: "EvtxECmd",
  },
  {
    name: "windows_process_creation",
    category: "logs",
    input: "evtx.csv (4688)",
    artifactKind: "process_creation",
    guardrail: "Typed Security 4688 process-creation",
    siftWrap: "EvtxECmd 4688 filter",
  },
  {
    name: "powershell_logs",
    category: "logs",
    input: "evtx.csv (powershell)",
    artifactKind: "powershell_log",
    guardrail: "Typed PowerShell activity artifacts",
    siftWrap: "EvtxECmd PS filter",
  },
  {
    name: "yara_keyword_scan",
    category: "ioc",
    input: "*.txt / *.log / *.csv",
    artifactKind: "yara_match",
    guardrail: "Read-only textual IOC scanner",
    siftWrap: "YARA",
  },
];

// ---------------- 3 Iterations (Plan→Collect→Hypothesize→Verify→Correct→Report) ----------------
export const pipelinePhases = [
  "Plan",
  "Collect",
  "Hypothesize",
  "Verify",
  "Correct",
  "Report",
] as const;

export const iterations = [
  {
    n: 1,
    title: "Memory & Network Triage",
    tools: ["memory_pslist", "memory_psscan", "memory_netscan", "memory_malfind"],
    output: "C2 hypothesis (POSSIBLE, conf 0.62)",
    critic: "MitreSequenceValidator flagged missing Execution tactic",
    correction: "clm-3c76c94c3ce5 → INFERRED (conf 0.58)",
  },
  {
    n: 2,
    title: "Disk Corroboration & Persistence",
    tools: [
      "disk_prefetch",
      "disk_amcache",
      "disk_shimcache",
      "registry_autoruns",
      "timeline_mft",
      "timeline_usn",
      "windows_evtx",
      "windows_process_creation",
      "powershell_logs",
      "yara_keyword_scan",
    ],
    output: "≥3 independent artifact kinds confirmed",
    critic: "ClockDriftNormalizer applied +120s; AntiForensicsDetector fired ×1.12",
    correction: "clm-3c76c94c3ce5 → CONFIRMED-CRITICAL (conf 0.93)",
  },
  {
    n: 3,
    title: "Negative Controls & Narrative Hardening",
    tools: ["memory_pslist (re-read)"],
    output: "svchost.exe held as CONTEXT (conf 0.35)",
    critic: "Verifier final pass — 0 hallucinations",
    correction: "Reports written, evidence_graph.sqlite sealed",
  },
];

// ---------------- MITRE ATT&CK sequence ----------------
export const tacticOrder = [
  "Initial Access",
  "Execution",
  "Persistence",
  "Privilege Escalation",
  "Defense Evasion",
  "Credential Access",
  "Discovery",
  "Lateral Movement",
  "Collection",
  "Command and Control",
  "Exfiltration",
  "Impact",
] as const;

export const techniqueToTactic: Record<string, string> = {
  T1059: "Execution",
  "T1059.001": "Execution",
  "T1059.003": "Execution",
  T1204: "Execution",
  T1055: "Defense Evasion",
  "T1547.001": "Persistence",
  T1060: "Persistence",
  T1003: "Credential Access",
  "T1003.001": "Credential Access",
  T1071: "Command and Control",
  "T1071.001": "Command and Control",
};

export const observedTactics: Record<string, { detected: boolean; via: string[] }> = {
  "Initial Access": { detected: false, via: [] },
  Execution: { detected: true, via: ["disk_prefetch", "windows_process_creation"] },
  Persistence: { detected: true, via: ["registry_autoruns"] },
  "Privilege Escalation": { detected: false, via: [] },
  "Defense Evasion": { detected: true, via: ["memory_malfind", "timeline_mft"] },
  "Credential Access": { detected: false, via: [] },
  Discovery: { detected: false, via: [] },
  "Lateral Movement": { detected: false, via: [] },
  Collection: { detected: false, via: [] },
  "Command and Control": { detected: true, via: ["memory_netscan", "yara_keyword_scan"] },
  Exfiltration: { detected: false, via: [] },
  Impact: { detected: false, via: [] },
};

export const sequenceRecommendations = [
  {
    id: "seq-91ab",
    gap_type: "missing_preceding_behavior_for_command_and_control",
    target_claim_id: "clm-3c76c94c3ce5",
    reason:
      "Command and Control technique observed without prior Execution evidence on iteration 1.",
    recommended_tools: ["disk_prefetch", "disk_amcache", "windows_evtx", "memory_psscan"],
    recommended_paths: [
      "C:\\Windows\\Prefetch\\*.pf",
      "Amcache.hve program entries",
      "Security.evtx Event ID 4688",
      "memory process listings for hidden or terminated processes",
    ],
    priority: "HIGH",
    resolved: true,
  },
];

// ---------------- Anti-forensics anomalies ----------------
export const antiForensicsAnomalies = [
  {
    id: "anom-af-01",
    anomaly_type: "mft_creation_postdates_prefetch_execution",
    target: "evil.exe",
    severity: "HIGH",
    multiplier: 1.12,
    details: "MFT created 14:10:05Z is AFTER prefetch last_run; skew > 300s threshold",
    evidenceIds: ["art-mft-evil", "art-pf-evil"],
  },
  {
    id: "anom-af-02",
    anomaly_type: "mft_created_after_modified",
    target: "evil.exe",
    severity: "MEDIUM",
    multiplier: 1.08,
    details: "$STANDARD_INFORMATION created (14:10:05Z) > modified (14:02:05Z)",
    evidenceIds: ["art-mft-evil"],
  },
];
export const antiForensicsThresholds = {
  max_creation_to_execution_skew_seconds: 300,
  max_mft_to_usn_skew_seconds: 300,
};

// ---------------- Clock drift ----------------
export const clockDriftDetail = {
  reference: { source: "netscan", timestamp_field: "first_seen", kind: "network" },
  candidate: { source: "evtx", timestamp_field: "time_utc", kind: "evtx" },
  delta_seconds: 120,
  max_abs_delta_seconds: 900,
  confidence: 0.86,
  reason: "EVTX clock skewed +120s vs netscan anchor — normalized in observations table.",
  observations: [
    {
      source: "netscan",
      observed_utc: "2025-10-12T14:08:00Z",
      normalized_utc: "2025-10-12T14:08:00Z",
      drift_seconds: 0,
    },
    {
      source: "evtx",
      observed_utc: "2025-10-12T14:10:02Z",
      normalized_utc: "2025-10-12T14:08:02Z",
      drift_seconds: -120,
    },
    {
      source: "evtx",
      observed_utc: "2025-10-12T14:12:30Z",
      normalized_utc: "2025-10-12T14:10:30Z",
      drift_seconds: -120,
    },
  ],
};

// ---------------- Audit log (sample of execution_log.jsonl) ----------------
export interface AuditEvent {
  event_id: string;
  timestamp_utc: string;
  actor: "agent" | "tool" | "anti_forensics" | "mitre_sequence" | "clock_drift" | "policy";
  action: string;
  details?: Record<string, unknown>;
}
export const auditLog: AuditEvent[] = [
  {
    event_id: "evt-7c1a40a01b22",
    timestamp_utc: "T+00.000s",
    actor: "agent",
    action: "run.start",
    details: { case_id: "proofsift-demo-001", max_iterations: 3 },
  },
  {
    event_id: "evt-9b0c2f88e310",
    timestamp_utc: "T+00.012s",
    actor: "policy",
    action: "spoliation_probe.blocked",
    details: { writes_allowed: 0, blocked: 2 },
  },
  {
    event_id: "evt-a2334cd1ee01",
    timestamp_utc: "T+00.018s",
    actor: "tool",
    action: "tool_result",
    details: { tool: "hash_all_evidence", ok: true, artifacts: 1429 },
  },
  {
    event_id: "evt-b03398fa1290",
    timestamp_utc: "T+00.022s",
    actor: "agent",
    action: "iteration.start",
    details: { iteration: 1 },
  },
  {
    event_id: "evt-c8821a0c9311",
    timestamp_utc: "T+00.031s",
    actor: "tool",
    action: "tool_result",
    details: { tool: "memory_netscan", artifacts: 12 },
  },
  {
    event_id: "evt-d09e1b21c4f7",
    timestamp_utc: "T+00.034s",
    actor: "agent",
    action: "claim.created",
    details: { claim_id: "clm-3c76c94c3ce5", status: "POSSIBLE", confidence: 0.62 },
  },
  {
    event_id: "evt-e119d3c4a8a9",
    timestamp_utc: "T+00.038s",
    actor: "mitre_sequence",
    action: "gap.detected",
    details: { tactic: "Command and Control", missing: "Execution" },
  },
  {
    event_id: "evt-f228e44b9b30",
    timestamp_utc: "T+00.041s",
    actor: "agent",
    action: "claim.corrected",
    details: { claim_id: "clm-3c76c94c3ce5", before: "POSSIBLE", after: "INFERRED" },
  },
  {
    event_id: "evt-002af5c0c4d1",
    timestamp_utc: "T+00.052s",
    actor: "agent",
    action: "iteration.start",
    details: { iteration: 2 },
  },
  {
    event_id: "evt-117bd60dd5e2",
    timestamp_utc: "T+00.061s",
    actor: "tool",
    action: "tool_result",
    details: { tool: "disk_prefetch", artifacts: 18 },
  },
  {
    event_id: "evt-22aca715e6f3",
    timestamp_utc: "T+00.073s",
    actor: "tool",
    action: "tool_result",
    details: { tool: "disk_amcache", artifacts: 122 },
  },
  {
    event_id: "evt-330bb826f704",
    timestamp_utc: "T+00.081s",
    actor: "clock_drift",
    action: "drift.applied",
    details: { source: "evtx", reference: "netscan", delta_seconds: 120 },
  },
  {
    event_id: "evt-44dac937080f",
    timestamp_utc: "T+00.088s",
    actor: "anti_forensics",
    action: "anomaly.detected",
    details: { type: "mft_creation_postdates_prefetch_execution", multiplier: 1.12 },
  },
  {
    event_id: "evt-55ebdb481910",
    timestamp_utc: "T+00.099s",
    actor: "agent",
    action: "claim.corrected",
    details: { claim_id: "clm-3c76c94c3ce5", before: "INFERRED", after: "CONFIRMED" },
  },
  {
    event_id: "evt-66fcec592a21",
    timestamp_utc: "T+00.110s",
    actor: "agent",
    action: "claim.confidence_adjusted",
    details: { claim_id: "clm-3c76c94c3ce5", from: 0.83, to: 0.93 },
  },
  {
    event_id: "evt-770ddd6a3b32",
    timestamp_utc: "T+00.126s",
    actor: "agent",
    action: "iteration.start",
    details: { iteration: 3 },
  },
  {
    event_id: "evt-881eed7b4c43",
    timestamp_utc: "T+00.132s",
    actor: "agent",
    action: "claim.created",
    details: {
      claim_id: "clm-2a8b34de77f0",
      status: "POSSIBLE",
      confidence: 0.35,
      note: "negative control",
    },
  },
  {
    event_id: "evt-992ffe8c5d54",
    timestamp_utc: "T+00.144s",
    actor: "mitre_sequence",
    action: "sequence.valid",
    details: { iteration: 3 },
  },
  {
    event_id: "evt-aa300f9d6e65",
    timestamp_utc: "T+00.150s",
    actor: "agent",
    action: "run.end",
    details: { runtime_s: 0.15, reports: 7 },
  },
];

// ---------------- CLI commands ----------------
export const cliCommands = [
  {
    cmd: "proofsift run --case cases/demo_case/case.json --max-iterations 3",
    desc: "Execute the self-correcting investigator on a case.",
  },
  {
    cmd: "proofsift benchmark --case cases/demo_case/case.json --ground-truth cases/demo_case/ground_truth.json",
    desc: "Score precision/recall against ground truth.",
  },
  {
    cmd: "proofsift trace --graph outputs/evidence_graph.sqlite --claim-id clm-3c76c94c3ce5",
    desc: "Dump joined trace (claim + evidence + tool_runs) as JSON.",
  },
  {
    cmd: "proofsift list-tools --case cases/demo_case/case.json",
    desc: "Print ToolRunner.catalog() — the 16 typed tools.",
  },
  {
    cmd: "proofsift validate-submission --root .",
    desc: "Validate hackathon submission file layout.",
  },
  { cmd: "proofsift mcp-stdio", desc: "Serve as a JSON-RPC stdio MCP bridge for Protocol SIFT." },
];

// ---------------- Output artifacts ----------------
export const outputArtifacts = [
  {
    file: "outputs/report.md",
    kind: "markdown",
    desc: "Primary Markdown report — 9 sections (Executive Summary → Reproducibility).",
  },
  {
    file: "outputs/report_2.md",
    kind: "markdown",
    desc: "Strict-review copy of report.md for cross-validation.",
  },
  {
    file: "outputs/report.html",
    kind: "html",
    desc: "HTML render of the same findings, html.escape'd.",
  },
  {
    file: "outputs/accuracy_report.md",
    kind: "markdown",
    desc: "Benchmark scoring vs ground truth (when proofsift benchmark is run).",
  },
  {
    file: "outputs/trace_index.json",
    kind: "json",
    desc: "{ claim_id: trace_claim(claim_id) } — full provenance index.",
  },
  {
    file: "outputs/evidence_graph.sqlite",
    kind: "sqlite",
    desc: "9-table SQLite provenance store (artifacts, claims, observations, anomalies …).",
  },
  {
    file: "outputs/execution_log.jsonl",
    kind: "jsonl",
    desc: "Append-only audit stream (evt-<12hex> events).",
  },
];

// ---------------- Configuration knobs ----------------
export const configKnobs = [
  { key: "case_id", value: "proofsift-demo-001" },
  { key: "max_iterations", value: "3" },
  { key: "output_dir", value: "outputs" },
  { key: "indicators.c2_ips", value: "[203.0.113.50, 198.51.100.24]" },
  { key: "indicators.yara_keywords", value: "[mimikatz, credential, c2]" },
  { key: "indicators.benign_processes", value: "[svchost.exe]" },
  { key: "policy", value: "SafePathPolicy(read=evidence/, write=outputs/)" },
  { key: "clock_drift.max_abs_delta_seconds", value: "900" },
  { key: "anti_forensics.max_creation_to_execution_skew_seconds", value: "300" },
  { key: "confirmation_gate", value: ">= 2 independent artifact kinds (>= 3 for C2 upgrade)" },
];

// ---------------- Integrity checks ----------------
export const integrityChecks = [
  {
    check: "SHA-256 evidence hash chain",
    result: "1,429 / 1,429 files verified",
    status: "ok" as const,
  },
  { check: "SafePathPolicy read scope", result: "evidence/ only", status: "ok" as const },
  { check: "SafePathPolicy write scope", result: "outputs/ only", status: "ok" as const },
  {
    check: "Spoliation probe (.proofsift_write_probe)",
    result: "PolicyViolation raised — writes blocked",
    status: "ok" as const,
  },
  { check: "Audit log append-only", result: "20 events, 0 mutations", status: "ok" as const },
  {
    check: "Hallucinated claims (trace_index.json)",
    result: "0 confirmed claims without evidence",
    status: "ok" as const,
  },
];

// ---------------- terminal stream ----------------
export const terminalScript: { text: string; tone?: "ok" | "warn" | "err" | "info" | "dim" }[] = [
  { text: "[PHASE 1: INGESTION]", tone: "info" },
  { text: "  Verifying forensic integrity hashes for case: proofsift-demo-001 ...", tone: "dim" },
  { text: "  SHA-256 chain validated across 1,429 artifacts.", tone: "dim" },
  { text: "  SPOLIATION PROBE PASSED ✓  (SafePathPolicy raised PolicyViolation)", tone: "ok" },
  { text: "" },
  { text: "[ITERATION 1/3: Memory & Network Triage]", tone: "info" },
  { text: "  [TOOL] memory_pslist ............ 47 processes", tone: "dim" },
  { text: "  [TOOL] memory_netscan ........... 12 connections", tone: "dim" },
  { text: "  [CLAIM CREATED] clm-3c76c94c3ce5 → POSSIBLE (conf 0.62) T1071", tone: "dim" },
  { text: "  [CRITIC ALERT] MitreSequenceValidator: missing Execution tactic", tone: "warn" },
  {
    text: "    -> Recommend: disk_prefetch, disk_amcache, windows_evtx, memory_psscan",
    tone: "dim",
  },
  { text: "  [CLAIM DOWNGRADE] clm-3c76c94c3ce5 POSSIBLE → INFERRED (conf 0.58)", tone: "warn" },
  { text: "" },
  { text: "[ITERATION 2/3: Disk Corroboration & Persistence]", tone: "info" },
  { text: "  [TOOL] disk_prefetch ............ EVIL.EXE (3 runs)", tone: "dim" },
  { text: "  [TOOL] disk_amcache ............. unsigned SHA-256 captured", tone: "dim" },
  { text: "  [TOOL] memory_malfind ........... PAGE_EXECUTE_READWRITE @ PID 1888", tone: "dim" },
  { text: "  [CLOCK DRIFT] evtx normalized against netscan with +120s offset", tone: "warn" },
  { text: "  [CRITIC REVIEW] mft_creation_postdates_prefetch_execution (×1.12)", tone: "warn" },
  {
    text: "  [CLAIM ESCALATION] clm-3c76c94c3ce5 INFERRED → CONFIRMED-CRITICAL (0.93)",
    tone: "ok",
  },
  {
    text: "  [CLAIM ESCALATION] clm-7f01a2b9c4d1 INFERRED → CONFIRMED-CRITICAL (0.91)",
    tone: "ok",
  },
  {
    text: "  [CLAIM ESCALATION] clm-55c1ee84a020 INFERRED → CONFIRMED-CRITICAL (0.74)",
    tone: "ok",
  },
  {
    text: "  [CLAIM HOLD]      clm-44da40820635 capped at INFERRED — corroboration absent",
    tone: "warn",
  },
  { text: "" },
  { text: "[ITERATION 3/3: Negative Controls & Narrative Hardening]", tone: "info" },
  { text: "  [NEGATIVE CONTROL] svchost.exe → POSSIBLE / INFO (conf 0.35)", tone: "dim" },
  { text: "  [VERIFIER] 0 hallucinated confirmed claims (trace_index.json)", tone: "ok" },
  { text: "" },
  { text: "[BENCHMARK] Final Accuracy 100.0% [PERFECT MATURATION]", tone: "ok" },
  { text: "[REPORT] report.md, report_2.md, report.html, trace_index.json written", tone: "ok" },
];

// ---------------- Benchmark ----------------
export const benchmark = {
  truePositives: { value: 2, total: 2, pct: 100 },
  falsePositives: { value: 0, total: 0, pct: 0 },
  hallucinationsIntercepted: 0,
  antiForensicsFound: { value: 2, total: 2, pct: 100 },
  clockDrifts: { value: 1, total: 1, label: "120s Normalized" },
  spoliationBlocked: { allowed: 0, blocked: 2 },
  runtimeSeconds: 0.15,
  finalScore: 100.0,
  precision: 1.0,
  recall: 1.0,
  expectedTargets: [
    {
      name: "evil.exe → 203.0.113.50:443 C2",
      expected: "CONFIRMED",
      actual: "CONFIRMED",
      hit: true,
    },
    {
      name: "HKCU\\Run\\Updater persistence",
      expected: "CONFIRMED",
      actual: "CONFIRMED",
      hit: true,
    },
    { name: "evil.exe timestomping anomaly", expected: "ANOMALY", actual: "ANOMALY", hit: true },
    { name: "EVTX +120s clock drift normalization", expected: "DRIFT", actual: "DRIFT", hit: true },
    { name: "unknown.exe → 198.51.100.24", expected: "INFERRED", actual: "INFERRED", hit: true },
    { name: "svchost.exe (negative control)", expected: "CONTEXT", actual: "CONTEXT", hit: true },
  ],
  missedTargets: [],
};

// ---------------- Database viewer fixtures ----------------
export const tableData: Record<string, Record<string, string | number>[]> = {
  tool_runs: [
    { run_id: "tr-001", tool: "memory_pslist", artifacts: 47, status: "ok", duration_ms: 12 },
    { run_id: "tr-002", tool: "memory_netscan", artifacts: 12, status: "ok", duration_ms: 9 },
    { run_id: "tr-003", tool: "disk_prefetch", artifacts: 18, status: "ok", duration_ms: 21 },
    { run_id: "tr-004", tool: "disk_amcache", artifacts: 122, status: "ok", duration_ms: 34 },
    { run_id: "tr-005", tool: "memory_malfind", artifacts: 1, status: "ok", duration_ms: 17 },
    { run_id: "tr-006", tool: "windows_evtx", artifacts: 412, status: "ok", duration_ms: 58 },
    { run_id: "tr-007", tool: "yara_keyword_scan", artifacts: 4, status: "ok", duration_ms: 6 },
    { run_id: "tr-008", tool: "registry_autoruns", artifacts: 1, status: "ok", duration_ms: 4 },
    { run_id: "tr-009", tool: "timeline_mft", artifacts: 312, status: "ok", duration_ms: 41 },
    {
      run_id: "tr-010",
      tool: "windows_process_creation",
      artifacts: 22,
      status: "ok",
      duration_ms: 11,
    },
  ],
  artifacts: [
    {
      id: "a-1888",
      source: "memory_netscan",
      value: "203.0.113.50:443 / PID 1888",
      hash: "9f3c…b201",
    },
    { id: "a-1891", source: "disk_prefetch", value: "EVIL.EXE-9F3C2B01.pf", hash: "2b71…44ae" },
    { id: "a-1903", source: "disk_amcache", value: "evil.exe (unsigned)", hash: "9f3c…b201" },
    {
      id: "a-1907",
      source: "registry_autoruns",
      value: "HKCU\\Run\\Updater -> evil.exe",
      hash: "771a…0c12",
    },
    {
      id: "a-1912",
      source: "timeline_mft",
      value: "evil.exe created 14:10:05Z modified 14:02:05Z",
      hash: "—",
    },
    { id: "a-1920", source: "windows_evtx", value: "4624 logon from 203.0.113.50", hash: "—" },
    {
      id: "a-1928",
      source: "windows_process_creation",
      value: "4688 powershell.exe -> evil.exe",
      hash: "—",
    },
    {
      id: "a-1933",
      source: "yara_keyword_scan",
      value: "payload_notes.txt :: c2 channel",
      hash: "—",
    },
  ],
  claims: claims.map((c) => ({
    id: c.id,
    status: c.status,
    confidence: c.confidence,
    severity: c.severity,
    title: c.title,
  })),
  clock_drifts: [
    {
      id: "drift-1",
      source_a: "memory_netscan",
      source_b: "windows_evtx",
      offset_s: 120,
      action: "normalized",
    },
  ],
  anomalies: antiForensicsAnomalies.map((a) => ({
    id: a.id,
    kind: a.anomaly_type,
    target: a.target,
    severity: a.severity,
    multiplier: a.multiplier,
  })),
};
