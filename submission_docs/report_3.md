# ProofSIFT Investigation Report: ProofSIFT Demo - Self-Correcting Windows Triage

## Executive Summary

- Case ID: `proofsift-demo-001`
- Evidence directory: `cases\demo_case\evidence`
- Claims produced: `6`
- Self-corrections recorded: `31`
- Clock drift adjustments: `1`
- Anti-forensics anomalies: `3`
- MITRE sequence recommendations: `2`
- Counterfactual checks: `8`
- Formal BMC contradictions: `3`
- MFT entropy analyses: `1`
- Ephemeral tool authorizations: `16`
- Knowledge graph: `34` nodes / `22` edges
- Explainable provenance traces: `6`
- Review-only remediation playbooks: `2`
- Merkle-DAG root seal: `sha256:19bfc734783dc4ffa43f1cceeb3fe079e1388dde4ef9a372b9f37598878e5045`

## Findings

### clm-a3e20d29ed1a - CONFIRMED - CRITICAL

evil.exe communicated with known C2 indicator 203.0.113.50:443

- Confidence: `1.00`
- Rationale: C2 communication is corroborated by memory, execution, filesystem, event-log, and indicator evidence. Anti-forensics detector flagged mft_creation_postdates_prefetch_execution on C:\Users\victim\AppData\Roaming\evil.exe. Anti-forensics detector flagged mft_created_after_modified on C:\Users\victim\AppData\Roaming\evil.exe. Anti-forensics detector flagged mft_creation_postdates_usn_activity on C:\Users\victim\AppData\Roaming\evil.exe.
- MITRE: `T1071, T1204, T1059`
- Trace: `proofsift trace --graph outputs/evidence_graph.sqlite --claim-id clm-a3e20d29ed1a`

| Evidence ID | Kind | Source | Tool | Key Fields |
| --- | --- | --- | --- | --- |
| `art-2b7be93688ba` | `mft` | `mft` | `timeline_mft` | `{"path": "C:\\Users\\victim\\AppData\\Roaming\\evil.exe"}` |
| `art-4413ed49ff43` | `process_creation` | `security_4688` | `windows_process_creation` | `{"time_utc": "2026-05-20T14:02:10Z"}` |
| `art-63a5e675a05b` | `amcache` | `amcache` | `disk_amcache` | `{"path": "C:\\Users\\victim\\AppData\\Roaming\\evil.exe", "sha256": "4f7b4e9e1a2d9f0d934c06b9f39e4c6f1ef88aaad861a4c60b8636b32701f7a7"}` |
| `art-84837085c743` | `process` | `psscan` | `memory_psscan` | `{"name": "evil.exe", "pid": "1888"}` |
| `art-8c37f94cd7bd` | `powershell_log` | `powershell` | `powershell_logs` | `{"time_utc": "2026-05-20T14:02:10Z"}` |
| `art-937278ded559` | `network` | `netscan` | `memory_netscan` | `{"pid": "1888", "process": "evil.exe", "remote_ip": "203.0.113.50", "remote_port": "443"}` |
| `art-d6f6c94d6935` | `shimcache` | `shimcache` | `disk_shimcache` | `{"entry_type": "AppCompatCache", "file_path": "C:\\Users\\victim\\AppData\\Roaming\\evil.exe", "last_modified_utc": "2026-05-20T14:02:05Z", "source": "System hive"}` |
| `art-da987c310942` | `malfind` | `malfind` | `memory_malfind` | `{"pid": "1888", "process": "evil.exe"}` |
| `art-de0749cd0978` | `prefetch` | `prefetch` | `disk_prefetch` | `{"executable": "EVIL.EXE", "last_run_utc": "2026-05-20T14:02:13Z", "path": "C:\\Windows\\Prefetch\\EVIL.EXE-9A8B7C6D.pf"}` |
| `art-f4d542409c79` | `evtx` | `evtx` | `windows_evtx` | `{"time_utc": "2026-05-20T14:02:10Z"}` |

### clm-2d40f3d29d12 - CONFIRMED - HIGH

evil.exe established user-level persistence through an autorun registry location

- Confidence: `1.00`
- Rationale: Autorun evidence points to the same executable corroborated by execution artifacts. Anti-forensics detector flagged mft_creation_postdates_prefetch_execution on C:\Users\victim\AppData\Roaming\evil.exe. Anti-forensics detector flagged mft_created_after_modified on C:\Users\victim\AppData\Roaming\evil.exe. Anti-forensics detector flagged mft_creation_postdates_usn_activity on C:\Users\victim\AppData\Roaming\evil.exe.
- MITRE: `T1060, T1547.001`
- Trace: `proofsift trace --graph outputs/evidence_graph.sqlite --claim-id clm-2d40f3d29d12`

| Evidence ID | Kind | Source | Tool | Key Fields |
| --- | --- | --- | --- | --- |
| `art-2b7be93688ba` | `mft` | `mft` | `timeline_mft` | `{"path": "C:\\Users\\victim\\AppData\\Roaming\\evil.exe"}` |
| `art-4413ed49ff43` | `process_creation` | `security_4688` | `windows_process_creation` | `{"time_utc": "2026-05-20T14:02:10Z"}` |
| `art-445a5726bc15` | `autorun` | `autoruns` | `registry_autoruns` | `{"name": "Updater", "path": "C:\\Users\\victim\\AppData\\Roaming\\evil.exe", "registry_key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"}` |
| `art-63a5e675a05b` | `amcache` | `amcache` | `disk_amcache` | `{"path": "C:\\Users\\victim\\AppData\\Roaming\\evil.exe", "sha256": "4f7b4e9e1a2d9f0d934c06b9f39e4c6f1ef88aaad861a4c60b8636b32701f7a7"}` |
| `art-84837085c743` | `process` | `psscan` | `memory_psscan` | `{"name": "evil.exe", "pid": "1888"}` |
| `art-8c37f94cd7bd` | `powershell_log` | `powershell` | `powershell_logs` | `{"time_utc": "2026-05-20T14:02:10Z"}` |
| `art-d6f6c94d6935` | `shimcache` | `shimcache` | `disk_shimcache` | `{"entry_type": "AppCompatCache", "file_path": "C:\\Users\\victim\\AppData\\Roaming\\evil.exe", "last_modified_utc": "2026-05-20T14:02:05Z", "source": "System hive"}` |
| `art-da987c310942` | `malfind` | `malfind` | `memory_malfind` | `{"pid": "1888", "process": "evil.exe"}` |
| `art-de0749cd0978` | `prefetch` | `prefetch` | `disk_prefetch` | `{"executable": "EVIL.EXE", "last_run_utc": "2026-05-20T14:02:13Z", "path": "C:\\Windows\\Prefetch\\EVIL.EXE-9A8B7C6D.pf"}` |
| `art-f4d542409c79` | `evtx` | `evtx` | `windows_evtx` | `{"time_utc": "2026-05-20T14:02:10Z"}` |

### clm-e7c909d861c3 - INFERRED - HIGH

evil.exe contains suspicious executable memory regions consistent with injected code

- Confidence: `1.00`
- Rationale: Volatile memory malfind evidence indicates suspicious executable memory; disk and process context are required for confirmation. Anti-forensics detector flagged mft_creation_postdates_prefetch_execution on C:\Users\victim\AppData\Roaming\evil.exe. Anti-forensics detector flagged mft_created_after_modified on C:\Users\victim\AppData\Roaming\evil.exe. Anti-forensics detector flagged mft_creation_postdates_usn_activity on C:\Users\victim\AppData\Roaming\evil.exe.
- MITRE: `T1055`
- Trace: `proofsift trace --graph outputs/evidence_graph.sqlite --claim-id clm-e7c909d861c3`

| Evidence ID | Kind | Source | Tool | Key Fields |
| --- | --- | --- | --- | --- |
| `art-da987c310942` | `malfind` | `malfind` | `memory_malfind` | `{"pid": "1888", "process": "evil.exe"}` |

### clm-2916f168b3e0 - INFERRED - HIGH

unknown.exe communicated with known C2 indicator 198.51.100.24:443

- Confidence: `0.15`
- Rationale: Initial network triage matched a configured C2 indicator; disk execution evidence is required before confirmation.
- MITRE: `T1071`
- Trace: `proofsift trace --graph outputs/evidence_graph.sqlite --claim-id clm-2916f168b3e0`

| Evidence ID | Kind | Source | Tool | Key Fields |
| --- | --- | --- | --- | --- |
| `art-6e3e58144768` | `network` | `netscan` | `memory_netscan` | `{"pid": "4444", "process": "unknown.exe", "remote_ip": "198.51.100.24", "remote_port": "443"}` |

### clm-a7c382ee8707 - INFERRED - MEDIUM

PowerShell process creation events show script-based staging before malicious execution

- Confidence: `1.00`
- Rationale: Event logs show staging behavior; no claim is confirmed without matching payload and execution artifacts. Anti-forensics detector flagged mft_creation_postdates_prefetch_execution on C:\Users\victim\AppData\Roaming\evil.exe. Anti-forensics detector flagged mft_created_after_modified on C:\Users\victim\AppData\Roaming\evil.exe. Anti-forensics detector flagged mft_creation_postdates_usn_activity on C:\Users\victim\AppData\Roaming\evil.exe.
- MITRE: `T1059.001`
- Trace: `proofsift trace --graph outputs/evidence_graph.sqlite --claim-id clm-a7c382ee8707`

| Evidence ID | Kind | Source | Tool | Key Fields |
| --- | --- | --- | --- | --- |
| `art-51ba55c4f60d` | `powershell_log` | `powershell` | `powershell_logs` | `{"time_utc": "2026-05-20T14:01:55Z"}` |
| `art-8c37f94cd7bd` | `powershell_log` | `powershell` | `powershell_logs` | `{"time_utc": "2026-05-20T14:02:10Z"}` |

### clm-37074f26f665 - POSSIBLE - INFO

svchost.exe was observed but not escalated without malicious corroboration

- Confidence: `0.03`
- Rationale: Negative control: common system process is retained as context, not reported as a finding.
- MITRE: `n/a`
- Trace: `proofsift trace --graph outputs/evidence_graph.sqlite --claim-id clm-37074f26f665`

| Evidence ID | Kind | Source | Tool | Key Fields |
| --- | --- | --- | --- | --- |
| `art-787c0cbcda0e` | `process` | `pslist` | `memory_pslist` | `{"name": "svchost.exe", "pid": "412"}` |

## Self-Corrections

- Iteration `1` corrected `clm-2916f168b3e0`: Command and Control claim `clm-2916f168b3e0` exists without preceding Execution evidence in the current ATT&CK sequence. [COUNTERFACTUAL FAILURE] Denied escalation - Expected execution artifact in Shimcache, Amcache, Prefetch, or Security Event ID 4688 missing.
- Iteration `1` corrected `clm-2916f168b3e0`: Bayesian posterior recalculated from forensic probability matrix
- Iteration `1` corrected `clm-a3e20d29ed1a`: Command and Control claim `clm-a3e20d29ed1a` exists without preceding Execution evidence in the current ATT&CK sequence. [COUNTERFACTUAL FAILURE] Denied escalation - Expected execution artifact in Shimcache, Amcache, Prefetch, or Security Event ID 4688 missing.
- Iteration `1` corrected `clm-a3e20d29ed1a`: downgraded pending disk corroboration
- Iteration `1` corrected `clm-2916f168b3e0`: downgraded pending disk corroboration
- Iteration `1` corrected `clm-a3e20d29ed1a`: Bayesian posterior recalculated from forensic probability matrix
- Iteration `1` corrected `clm-a3e20d29ed1a`: Bayesian posterior recalculated from forensic probability matrix
- Iteration `1` corrected `clm-2916f168b3e0`: Bayesian posterior recalculated from forensic probability matrix
- Iteration `2` corrected `clm-e7c909d861c3`: anti-forensics anomaly added to Bayesian scoring context
- Iteration `2` corrected `clm-2d40f3d29d12`: Bayesian posterior recalculated from forensic probability matrix
- Iteration `2` corrected `clm-e7c909d861c3`: anti-forensics anomaly added to Bayesian scoring context
- Iteration `2` corrected `clm-e7c909d861c3`: anti-forensics anomaly added to Bayesian scoring context
- Iteration `2` corrected `clm-a7c382ee8707`: anti-forensics anomaly added to Bayesian scoring context
- Iteration `2` corrected `None`: clock drift normalization applied to cross-source observations
- Iteration `2` corrected `None`: formal bounded model checker detected impossible timeline for C:\Users\victim\AppData\Roaming\evil.exe
- Iteration `2` corrected `clm-a7c382ee8707`: Bayesian posterior recalculated from forensic probability matrix
- Iteration `2` corrected `None`: formal bounded model checker detected impossible timeline for C:\Users\victim\AppData\Roaming\evil.exe
- Iteration `2` corrected `clm-a3e20d29ed1a`: anti-forensics anomaly added to Bayesian scoring context
- Iteration `2` corrected `clm-a3e20d29ed1a`: anti-forensics anomaly added to Bayesian scoring context
- Iteration `2` corrected `clm-2d40f3d29d12`: anti-forensics anomaly added to Bayesian scoring context
- Iteration `2` corrected `clm-a7c382ee8707`: anti-forensics anomaly added to Bayesian scoring context
- Iteration `2` corrected `clm-2d40f3d29d12`: anti-forensics anomaly added to Bayesian scoring context
- Iteration `2` corrected `clm-a7c382ee8707`: anti-forensics anomaly added to Bayesian scoring context
- Iteration `2` corrected `clm-a3e20d29ed1a`: upgraded after disk and event-log corroboration
- Iteration `2` corrected `clm-e7c909d861c3`: Bayesian posterior recalculated from forensic probability matrix
- Iteration `2` corrected `None`: formal bounded model checker detected impossible timeline for C:\Users\victim\AppData\Roaming\evil.exe
- Iteration `2` corrected `clm-a3e20d29ed1a`: Bayesian posterior recalculated from forensic probability matrix
- Iteration `2` corrected `None`: MFT sequence entropy analyzer flagged structural timestomping signal for C:\Users\victim\AppData\Roaming\evil.exe
- Iteration `2` corrected `clm-a3e20d29ed1a`: anti-forensics anomaly added to Bayesian scoring context
- Iteration `2` corrected `clm-2d40f3d29d12`: anti-forensics anomaly added to Bayesian scoring context
- Iteration `3` corrected `clm-37074f26f665`: Bayesian posterior recalculated from forensic probability matrix

## Clock Drift Normalization

- `evtx` normalized against `netscan` with `120` second offset; confidence `0.92`. Reason: shared anchor matched remote IP 203.0.113.50 across netscan and evtx

## Anti-Forensics Anomalies

- `mft_creation_postdates_prefetch_execution` on `C:\Users\victim\AppData\Roaming\evil.exe` (HIGH, multiplier `1.12`), evidence `art-2b7be93688ba, art-de0749cd0978`. MFT creation time occurs after observed execution, consistent with timestomping or metadata manipulation.
- `mft_creation_postdates_usn_activity` on `C:\Users\victim\AppData\Roaming\evil.exe` (HIGH, multiplier `1.1`), evidence `art-2b7be93688ba, art-a649867edf1c`. USN activity predates MFT creation metadata for the same executable.
- `mft_created_after_modified` on `C:\Users\victim\AppData\Roaming\evil.exe` (MEDIUM, multiplier `1.08`), evidence `art-2b7be93688ba`. Creation timestamp occurs after modification timestamp.

## Formal Bounded Model Checking

- `CONTRADICTION` `mft_creation_must_not_postdate_prefetch_execution` on `C:\Users\victim\AppData\Roaming\evil.exe` with timeline validity `0.00`. Contradiction: Prefetch execution predates MFT creation beyond bounded OS causality tolerance. Evidence: `art-2b7be93688ba, art-de0749cd0978`. Solver: `Z3 4.16.0` / `unsat`; unsat core: `observed_mft_created, observed_prefetch_last_run, causal_mft_creation_must_not_postdate_prefetch_execution`.
- `CONTRADICTION` `usn_activity_must_not_predate_mft_creation` on `C:\Users\victim\AppData\Roaming\evil.exe` with timeline validity `0.00`. Contradiction: USN record sequence violates causal time-density bounds. Evidence: `art-2b7be93688ba, art-a649867edf1c`. Solver: `Z3 4.16.0` / `unsat`; unsat core: `observed_mft_created, causal_usn_activity_must_not_predate_mft_creation, observed_usn_activity`.
- `CONTRADICTION` `mft_creation_must_not_postdate_amcache_first_run` on `C:\Users\victim\AppData\Roaming\evil.exe` with timeline validity `0.00`. Contradiction: Amcache first-run observation predates MFT creation beyond bounded OS causality tolerance. Evidence: `art-2b7be93688ba, art-63a5e675a05b`. Solver: `Z3 4.16.0` / `unsat`; unsat core: `observed_mft_created, observed_amcache_first_run, causal_mft_creation_must_not_postdate_amcache_first_run`.

## MFT Structural Entropy

- `ANOMALOUS_MALICIOUS_TIMESTOMPING` on `C:\Users\victim\AppData\Roaming\evil.exe` with entropy `1.4729` bits. Baseline delta/record `15.3030s`, target delta/record `14.5455s`. Signals: `execution_timestamp_diverges_from_mft_creation, usn_activity_diverges_from_mft_creation, high_temporal_density_delta`. Evidence: `art-0ac9bd546bde, art-2b7be93688ba, art-4fb069e9bec9, art-63a5e675a05b, art-a649867edf1c, art-de0749cd0978`.

## MITRE ATT&CK Sequence Recommendations

- `missing_preceding_behavior_for_command_and_control` for claim `clm-a3e20d29ed1a`: Command and Control claim `clm-a3e20d29ed1a` exists without preceding Execution evidence in the current ATT&CK sequence. [COUNTERFACTUAL FAILURE] Denied escalation - Expected execution artifact in Shimcache, Amcache, Prefetch, or Security Event ID 4688 missing. Tools: `disk_amcache, disk_prefetch, memory_psscan, windows_evtx`. Paths: Amcache.hve program entries; C:\Windows\Prefetch\*.pf; Security.evtx Event ID 4688; Shimcache/AppCompatCache entries; memory process listings for hidden or terminated processes
- `missing_preceding_behavior_for_command_and_control` for claim `clm-2916f168b3e0`: Command and Control claim `clm-2916f168b3e0` exists without preceding Execution evidence in the current ATT&CK sequence. [COUNTERFACTUAL FAILURE] Denied escalation - Expected execution artifact in Shimcache, Amcache, Prefetch, or Security Event ID 4688 missing. Tools: `disk_amcache, disk_prefetch, memory_psscan, windows_evtx`. Paths: Amcache.hve program entries; C:\Windows\Prefetch\*.pf; Security.evtx Event ID 4688; Shimcache/AppCompatCache entries; memory process listings for hidden or terminated processes

## Counterfactual Falsification

- `PASS` `registry_persistence_requires_prior_execution_alibi` for claim `clm-2d40f3d29d12`. Present: Registry autorun entry, Prefetch execution cache, Amcache program inventory, Shimcache/AppCompatCache entry, Security.evtx Event ID 4688. Missing: none. Action: `allow_escalation`.
- `FAIL` `command_and_control_requires_execution_cache_and_timeline_alibi` for claim `clm-a3e20d29ed1a`. Present: none. Missing: $MFT timeline entry, $UsnJrnl file transition, Amcache program inventory, Prefetch execution cache, Security.evtx Event ID 4688, Shimcache/AppCompatCache entry. Action: `denied_escalation`.
- `PASS` `command_and_control_requires_execution_cache_and_timeline_alibi` for claim `clm-a3e20d29ed1a`. Present: Prefetch execution cache, Amcache program inventory, Shimcache/AppCompatCache entry, Security.evtx Event ID 4688, $MFT timeline entry. Missing: none. Action: `allow_escalation`.
- `FAIL` `command_and_control_requires_execution_cache_and_timeline_alibi` for claim `clm-2916f168b3e0`. Present: none. Missing: $MFT timeline entry, $UsnJrnl file transition, Amcache program inventory, Prefetch execution cache, Security.evtx Event ID 4688, Shimcache/AppCompatCache entry. Action: `denied_escalation`.
- `PASS` `command_and_control_requires_execution_cache_and_timeline_alibi` for claim `clm-a3e20d29ed1a`. Present: Prefetch execution cache, Amcache program inventory, Shimcache/AppCompatCache entry, Security.evtx Event ID 4688, $MFT timeline entry. Missing: none. Action: `allow_escalation`.
- `PASS` `registry_persistence_requires_prior_execution_alibi` for claim `clm-2d40f3d29d12`. Present: Registry autorun entry, Prefetch execution cache, Amcache program inventory, Shimcache/AppCompatCache entry, Security.evtx Event ID 4688. Missing: none. Action: `allow_escalation`.
- `FAIL` `command_and_control_requires_execution_cache_and_timeline_alibi` for claim `clm-2916f168b3e0`. Present: none. Missing: $MFT timeline entry, $UsnJrnl file transition, Amcache program inventory, Prefetch execution cache, Security.evtx Event ID 4688, Shimcache/AppCompatCache entry. Action: `denied_escalation`.
- `FAIL` `command_and_control_requires_execution_cache_and_timeline_alibi` for claim `clm-2916f168b3e0`. Present: none. Missing: $MFT timeline entry, $UsnJrnl file transition, Amcache program inventory, Prefetch execution cache, Security.evtx Event ID 4688, Shimcache/AppCompatCache entry. Action: `denied_escalation`.

## Bayesian Forensic Calculus

Formula: `P(H|E) = P(E|H) * P(H) / P(E)`.
- Claim `clm-2916f168b3e0` posterior `0.1535` from prior `0.1000`, P(E|H) `0.620000`, P(E|not H) `0.380000`. Signals: `network`.
- Claim `clm-2d40f3d29d12` posterior `0.9999` from prior `0.1200`, P(E|H) `0.062874`, P(E|not H) `0.000000`. Signals: `amcache, autorun, evtx, malfind, mft, powershell_log, prefetch, process, process_creation, shimcache, mft_created_after_modified, mft_creation_postdates_prefetch_execution, mft_creation_postdates_usn_activity`.
- Claim `clm-37074f26f665` posterior `0.0322` from prior `0.0300`, P(E|H) `0.700000`, P(E|not H) `0.650000`. Signals: `process`.
- Claim `clm-a3e20d29ed1a` posterior `0.1633` from prior `0.1000`, P(E|H) `0.434000`, P(E|not H) `0.247000`. Signals: `network, process`.
- Claim `clm-a7c382ee8707` posterior `0.9999` from prior `0.1800`, P(E|H) `0.449085`, P(E|not H) `0.000000`. Signals: `powershell_log, mft_created_after_modified, mft_creation_postdates_prefetch_execution, mft_creation_postdates_usn_activity`.
- Claim `clm-e7c909d861c3` posterior `0.9999` from prior `0.1600`, P(E|H) `0.596642`, P(E|not H) `0.000000`. Signals: `malfind, mft_created_after_modified, mft_creation_postdates_prefetch_execution, mft_creation_postdates_usn_activity`.

## Ephemeral MCP Tool Authorization

- `16` of `16` tool executions carried one-time HMAC-SHA256 nonce authorization envelopes.
- Each authorization stores a nonce hash, payload hash, signature, status, and expiry in the evidence graph.

## Attack Knowledge Graph

- NetworkX PageRank center of gravity: `evil.exe established user-level persistence through an autorun registry location` with score `0.10496901` and blast radius `0` nodes.
- Typed graph contains `34` entity nodes and `22` evidence relationships.

## Advanced Collector Capabilities

- `ebpf_telemetry`: `UNAVAILABLE` in `read_only_import` mode. Requires Linux with bpftool; Windows runs degrade gracefully.
- `ghidra_headless`: `UNAVAILABLE` in `manual_opt_in_read_only` mode. Set GHIDRA_HOME or place analyzeHeadless on PATH.

## Explainable Provenance

ProofSIFT stores evidence IDs, verifier rules, and calculations. It does not store or claim to expose private model chain-of-thought or hidden prompts.
- Claim `clm-2916f168b3e0`: INFERRED at 15.35%: 1 independent artifact kinds were evaluated under corroboration, counterfactual, Bayesian, and temporal rules. Artifact kinds: `network`.
- Claim `clm-2d40f3d29d12`: CONFIRMED at 99.99%: 10 independent artifact kinds were evaluated under corroboration, counterfactual, Bayesian, and temporal rules. Artifact kinds: `amcache, autorun, evtx, malfind, mft, powershell_log, prefetch, process, process_creation, shimcache`.
- Claim `clm-37074f26f665`: POSSIBLE at 3.22%: 1 independent artifact kinds were evaluated under corroboration, counterfactual, Bayesian, and temporal rules. Artifact kinds: `process`.
- Claim `clm-a3e20d29ed1a`: CONFIRMED at 99.99%: 10 independent artifact kinds were evaluated under corroboration, counterfactual, Bayesian, and temporal rules. Artifact kinds: `amcache, evtx, malfind, mft, network, powershell_log, prefetch, process, process_creation, shimcache`.
- Claim `clm-a7c382ee8707`: INFERRED at 99.99%: 1 independent artifact kinds were evaluated under corroboration, counterfactual, Bayesian, and temporal rules. Artifact kinds: `powershell_log`.
- Claim `clm-e7c909d861c3`: INFERRED at 99.99%: 1 independent artifact kinds were evaluated under corroboration, counterfactual, Bayesian, and temporal rules. Artifact kinds: `malfind`.

## Approval-Gated Remediation

- `play-5a69ab8a66e5` for `clm-2d40f3d29d12` is `generate_only` with analyst approval required. Generated steps: `3`. No command was executed by ProofSIFT.
- `play-7e057b309d56` for `clm-a3e20d29ed1a` is `generate_only` with analyst approval required. Generated steps: `3`. No command was executed by ProofSIFT.

## Evidence Integrity

- Evidence files were hashed before analysis.
- Merkle-DAG root seal: `sha256:19bfc734783dc4ffa43f1cceeb3fe079e1388dde4ef9a372b9f37598878e5045`.
- Merkle-DAG nodes: `297` total; relationship blocks: `47`.
- Merkle-DAG verification status: `True`.
- The path policy allowed reads from registered evidence roots only.
- The spoliation probe verified that writes into the evidence root are blocked.
- Report, graph, and logs are written only under the configured output directory.
- Re-verify with: `proofsift verify-integrity --graph outputs/evidence_graph.sqlite`.
- Knowledge nodes, graph edges, PageRank metrics, provenance traces, capability checks, and remediation playbooks are included in the Merkle seal.

## Reproducibility

Run the same case with:

```bash
proofsift run --case cases/demo_case/case.json --max-iterations 3
proofsift benchmark --case cases/demo_case/case.json --ground-truth cases/demo_case/ground_truth.json
```
