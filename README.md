# ProofSIFT

Evidence-proven, self-correcting autonomous DFIR triage for the SANS Find Evil hackathon.

ProofSIFT is built around one principle: **the agent cannot make a confirmed finding unless it can prove the finding with traceable forensic evidence**. Every claim is linked to the exact artifact, parser, command ID, timestamped audit event, and evidence hash that produced it.

## Quick Start

```powershell
# One-time install
python -m pip install -e .

# Run investigation
proofsift run --case cases/demo_case/case.json --max-iterations 3

# Run benchmark against ground truth
proofsift benchmark --case cases/demo_case/case.json --ground-truth cases/demo_case/ground_truth.json --max-iterations 3

# Verify cryptographic evidence graph integrity
proofsift verify-integrity --graph cases/demo_case/outputs/evidence_graph.sqlite

# Run tests
python -m unittest discover -s tests -v
```

Without install (module entry point):

```powershell
$env:PYTHONPATH="src"; python -m proofsift run --case cases/demo_case/case.json --max-iterations 3
```

## Terminal Output

The agent displays real-time reasoning during execution:

```
[PHASE 1: INGESTION]
  Verifying forensic integrity hashes for case: proofsift-demo-001... [OK]
[PHASE 2: INVESTIGATE]
  Investigator spawned. Running triage across memory and disk artifacts...
[CLAIM DOWNGRADE] downgraded to INFERRED - disk execution evidence missing
[CRITIC ALERT] MitreSequenceValidator flagged a structural gap!
  -> Detected: clm-xxx
  -> Missing: Execution artifacts.
[TOOL] disk_prefetch: Prefetch execution artifacts parsed
[CLOCK DRIFT] evtx normalized against netscan with 120s offset
[COUNTERFACTUAL FAILURE] Denied escalation - Expected execution artifact in Shimcache/AppCompatCache entry missing
[CLAIM ESCALATION] upgraded from [INFERRED] to [CONFIRMED - CRITICAL]
[CRITIC REVIEW] Anomaly: mft_creation_postdates_prefetch_execution -> Bayesian posterior scoring
[Z3 SOLVER] SMT timeline constraints... UNSAT: USN record sequence violates causal time-density bounds.
[MFT ENTROPY] Structural metadata entropy spike detected: C:\Users\victim\AppData\Roaming\evil.exe
[KNOWLEDGE GRAPH] NetworkX PageRank center of gravity and blast radius calculated
[PROVENANCE] Evidence IDs, rules, and calculations linked to every claim
[REMEDIATION] Approval-gated playbooks generated; 0 commands executed
[INTEGRITY] Merkle-DAG root seal: sha256:<root>
```

## Benchmark Output

```
======================================================================
          PROOFSIFT ACCURACY BENCHMARK HARNESS
======================================================================
 FORENSIC DETECTION RESULTS:
  Forensic True Positives Caught : 2 / 2  (100.0%)
   False Positive Claims Raised   : 0      (0.00%)
   Hallucinated Items Intercepted : 0     (Enforced via Critic)
   Anti-Forensics Anomalies Found : 3 / 3  (100.0%)
  Clock-Drift Adjustments Applied: 1 / 1  (120s Normalized)
   Counterfactual Alibi Checks    : 8 (4 denied escalations)
   Bayesian Posterior Scores      : 15 computed
   BMC Timeline Contradictions    : 3 proven
   MFT Entropy Anomalies          : 1 / 1 analyzed
   MCP Ephemeral Authorizations   : 16 / 16 accepted
   Z3 Unsatisfiable Proofs         : 3 reproducible proofs
   Knowledge Graph Metrics         : 34 PageRank records
   Explainable Provenance Traces   : 6 evidence-and-rule traces
   Approval-Gated Playbooks        : 2 generated, 0 executed
   Merkle-DAG Integrity Seal      : sha256:<root>
   Evidence Spoliation Attempts   : 0 Writes Allowed (2 Blocked by Policy)
 SYSTEM METRICS:
   Total Execution Runtime        : 0.15 seconds
   Final Benchmark Accuracy Score : 100.0% [PERFECT MATURATION]
======================================================================
```

## What The Demo Shows

The demo case contains:
- A real malicious chain: `powershell.exe` stages `evil.exe`, `evil.exe` executes, persists through HKCU Run, and communicates with a known C2 IP.
- A deliberate weak signal: `unknown.exe` appears in a network artifact with a C2-looking IP but lacks process, disk, and execution corroboration.
- A negative control: `svchost.exe` is observed but must not be escalated as malicious without proof.

Expected behavior:
- `evil.exe` C2 communication becomes `CONFIRMED` only after disk and log corroboration.
- `unknown.exe` is not confirmed.
- `svchost.exe` is kept as context, not a malicious finding.
- EVTX timestamps are normalized by a detected `+120s` drift against memory network evidence.
- `evil.exe` timestomping-style metadata divergence is flagged as anti-forensics signal.
- Z3 proves three unsatisfiable timeline constraint sets across Prefetch, Amcache, MFT, and USN, retaining tracked cores and SMT-LIB.
- MFT sequence entropy flags `evil.exe` as an anomalous malicious timestomping pattern.
- Every typed tool execution is covered by a one-time HMAC-SHA256 nonce authorization record.
- MITRE ATT&CK sequence gaps trigger targeted tool recommendations before confirmation.
- NetworkX builds a typed process/file/IP/registry/claim graph and calculates PageRank plus blast radius.
- Ghidra and eBPF adapters are capability-gated: unavailable hosts are logged honestly, Ghidra requires explicit opt-in, and eBPF is read-only import mode.
- Every claim receives an evidence-and-rule provenance trace; private model chain-of-thought and hidden prompts are not stored.
- Confirmed claims can produce analyst-reviewed containment playbooks, but ProofSIFT never executes response commands.

## Demo Evidence Files

| File | Content | Purpose |
|------|---------|---------|
| `processes.csv` | svchost.exe, explorer.exe, evil.exe, powershell.exe | Process listings (pslist + psscan) |
| `netscan.csv` | Connections to 203.0.113.50:443 (evil.exe), 198.51.100.24:443 (unknown.exe) | Network C2 indicators |
| `prefetch.csv` | EVIL.EXE (3 runs), POWERSHELL.EXE (1 run) | Execution artifacts |
| `amcache.csv` | evil.exe (unsigned, SHA-256), powershell.exe (Microsoft signed) | Program inventory |
| `shimcache.csv` | evil.exe, powershell.exe | AppCompatCache execution |
| `mft.csv` | evil.exe (created 14:10:05Z, modified 14:02:05Z) | Filesystem timeline with timestomping |
| `usn.csv` | evil.exe FILE_CREATE + BASIC_INFO_CHANGE | USN journal |
| `evtx.csv` | 4624 logon (203.0.113.50), 4688 process creation, 7045 service failure | Event logs with clock drift anchor |
| `malfind.csv` | evil.exe PID 1888, PAGE_EXECUTE_READWRITE, MZ header | Injected memory |
| `autoruns.csv` | Updater -> evil.exe in HKCU\Run | Registry persistence |
| `payload_notes.txt` | "evil beacon initialized", "c2 channel: 203.0.113.50:443" | Keyword/YARA IOC match |

## 135 Advanced Features

| # | Feature | Category |
|---|---------|----------|
| 1-7 | Typed tool facade, read-only policy, output-only write, spoliation probe, SHA-256 hashing, SafePathPolicy, file mode audit | Security & Constraints |
| 6-10 | SQLite graph, claim-artifact provenance, tool-run provenance, JSONL execution log, token estimation | Evidence Graph |
| 11-18 | Max-iteration loop, downgrade gate, upgrade gate, 4 claim states, confidence scoring, severity scoring, MITRE technique tags | Self-Correction |
| 19-22 | Process list, hidden process scan, network connections, malfind injected memory | Memory Parsers |
| 23-28 | Prefetch, Amcache, Shimcache, autoruns, MFT, USN | Disk Parsers |
| 29-31 | EVTX, Security 4688, PowerShell logs | Log Parsers |
| 32-36 | Keyword YARA scan, cross-source correlation, negative-control handling, benchmark harness, precision/recall | IOC Scanning |
| 37-39 | Markdown report, strict-review report_2, HTML report | Reporting |
| 40 | Stdio JSON-RPC bridge for Protocol SIFT | MCP Bridge |
| 41-50 | Observations table, automatic extraction, drift anchors, network-EVTX matching, delta calculation, normalized updates, indexed queries, audit events, correction traces, report section | Clock Drift |
| 51-58 | MFT-Prefetch timestomping, MFT-USN timestomping, created-after-modified, anomaly table, Bayesian anomaly signals, audit events, claim adjustment, report section | Anti-Forensics |
| 59-68 | Tactic mapping, behavioral state machine, C2 validation, Credential Access validation, Execution prerequisite detection, tool recommendations, path recommendations, audit events, correction traces, report section | MITRE ATT&CK |
| 69-71 | Parser anomaly artifacts, graceful degradation, error capture without modification | Parser Resilience |
| 72-75 | Expanded benchmark scoring, advanced verification tests, clock drift fixture, anti-forensics fixture | Testing |
| 76-80 | Artifact content hashes, signed claim-evidence relationship blocks, Merkle-DAG node hashing, root seal generation, integrity verification CLI | Cryptographic Chain of Custody |
| 81-85 | Counterfactual alibi checks, denied-escalation logs, missing Shimcache/Amcache/Event 4688 tests, confirmed-claim downgrade gate, SQLite counterfactual audit table | Active Falsification |
| 86-90 | Bayesian prior model, likelihood matrix, posterior confidence formula, score persistence, benchmark/report integration | Mathematical Confidence |
| 91-95 | Bounded model checker, causal time-density constraints, satisfiability status, contradiction persistence, BMC audit traces | Formal Timeline Verification |
| 96-100 | MFT sequence entropy, record-number baseline, execution-to-metadata density scoring, structural timestomp verdict, report/benchmark integration | Metadata Entropy |
| 101-105 | One-time MCP nonce issue, HMAC-SHA256 signature, payload hash binding, replay rejection, tool authorization evidence table | Ephemeral Tool Authorization |
| 106-110 | Real Z3 integer constraints, tracked assertions, UNSAT cores, SMT-LIB persistence, solver-version audit events | Neuro-Symbolic Verification |
| 111-115 | Typed process/file/IP/registry nodes, evidence relationships, NetworkX PageRank, center-of-gravity ranking, blast-radius metrics | Attack Knowledge Graph |
| 116-120 | Ghidra capability detection, explicit opt-in mode, output-bound projects, eBPF capability detection, read-only telemetry import | Advanced Collectors |
| 121-125 | Claim-level evidence IDs, verifier rules, Bayesian calculations, counterfactual outcomes, explicit no-hidden-reasoning policy | Explainable Provenance |
| 126-130 | Generate-only playbooks, analyst approval flag, non-destructive inspection, PowerShell WhatIf containment, rollback guidance | Human-Gated Response |
| 131-135 | Knowledge graph Merkle nodes, signed graph relationships, provenance sealing, capability sealing, remediation sealing | Extended Chain of Custody |

## Repository Layout

```
src/proofsift/              Core package
├── agent.py                SelfCorrectingInvestigator — orchestration loop
├── anti_forensics.py       AntiForensicsDetector — timestomping analysis
├── audit.py                AuditLogger — JSONL event stream
├── benchmark.py            run_benchmark — ground-truth scoring + matrix output
├── cli.py                  CLI — run, benchmark, trace, list-tools, validate, mcp-stdio
├── clock_drift.py          ClockDriftNormalizer — cross-source timestamp alignment
├── constraint_engine.py    TimelineConstraintEngine — Z3 satisfiability proofs
├── crypto_auth.py          EphemeralToolAuthorizer — one-time MCP nonce envelopes
├── advanced_collectors.py  Capability-gated Ghidra and eBPF adapters
├── graph.py                EvidenceGraph — SQLite provenance store
├── integrity.py            Merkle-DAG graph sealing and verification
├── knowledge_graph.py      NetworkX entity graph, PageRank, blast radius
├── mcp_server.py           JSON-RPC stdio bridge for Protocol SIFT
├── mitre_sequence.py       MitreSequenceValidator — tactic state machine
├── mft_entropy.py          MftEntropyAnalyzer — structural timestomp scoring
├── models.py               Data classes: Artifact, Claim, ToolResult, CaseConfig
├── provenance.py           Evidence-and-rule XAI provenance traces
├── remediation.py          Generate-only, approval-gated response playbooks
├── reporting.py            Markdown/HTML report generators
├── security.py             SafePathPolicy, SHA-256, path validation
├── terminal.py             Styled terminal output for agent reasoning
├── time_utils.py           Timestamp parsing, formatting, UTC helpers
├── tools.py                ToolRunner — 16 typed forensic tools
├── __init__.py             Package metadata
└── __main__.py             Entry: python -m proofsift

cases/demo_case/            Runnable demo evidence and ground truth
tests/                      Unit tests (17 tests)
setup_sift.sh               One-command installer for SIFT Workstation
```

Additional advanced modules provide posterior confidence calculus, active missing-evidence falsification, Merkle-DAG verification, Z3 proofs, structural MFT entropy, NetworkX graph analytics, capability-gated native collectors, explainable provenance, and human-gated response playbooks.

## Setup Script (SIFT Workstation)

```bash
chmod +x setup_sift.sh
./setup_sift.sh
```

Automates: system dependencies, Python venv, package install, submission validation.

## Architecture Visualizer

The repo includes a Vite + React Flow architecture visualizer for judges and security reviewers:

```bash
npm install
npm run dev
npm run build
```

Vercel settings:

- Framework Preset: `Vite`
- Root Directory: `.`
- Build Command: `npm run build`
- Output Directory: `dist`

See [docs/vercel_deployment.md](docs/vercel_deployment.md).

## Trace a Claim

```bash
proofsift trace --graph cases/demo_case/outputs/evidence_graph.sqlite --claim-id <claim-id>
```

## Verify Graph Integrity

```bash
proofsift verify-integrity --graph cases/demo_case/outputs/evidence_graph.sqlite
```

Returns a single `sha256:<root>` Merkle-DAG seal over tool runs, artifacts, observations, claims, signed relationships, corrections, solver results, graph analytics, provenance traces, capability checks, remediation plans, and tool authorizations.

## Validate Submission

```bash
proofsift validate-submission --root .
```

## Judging Criteria Mapping

| Criterion | ProofSIFT Implementation |
|-----------|--------------------------|
| Autonomous execution quality | Deterministic Plan-Collect-Hypothesize-Verify-Correct-Report loop with max-iteration caps |
| IR accuracy | CONFIRMED requires >=2 independent artifact kinds; negative controls prevent benign escalation |
| Breadth and depth | 16 typed tools across memory, network, execution, registry, filesystem, event logs, IOC scans |
| Constraint implementation | Typed tools + SafePathPolicy instead of raw shell access; spoliation probe proves writes blocked |
| Audit trail quality | JSONL execution log, SQLite evidence graph, Merkle-DAG root seal, trace command, Markdown + HTML reports |
| Advanced verification | Z3 UNSAT proofs, MFT entropy, NetworkX PageRank, Bayesian calculus, counterfactual alibis, and nonce-backed MCP calls |
| Explainability and response | Evidence-and-rule provenance plus generate-only, approval-gated containment playbooks |
| Usability | Reproducible Python dependencies; optional native collectors degrade gracefully when unavailable |

## Built With

Python 3.10+, SQLite 3, Z3, NetworkX, MCP (Model Context Protocol), JSON/JSONL, CSV

## License

MIT.
