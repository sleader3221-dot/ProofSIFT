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
- Merkle-DAG root seal: `sha256:3ac7d3e11efd441a3cb96b1e0b3e77ff07cacba5fceb332d30aff087fdaf172e`

## Findings

### clm-65ec35afbefb - CONFIRMED - CRITICAL

evil.exe communicated with known C2 indicator 203.0.113.50:443

- Confidence: `1.00`
- Rationale: C2 communication is corroborated by memory, execution, filesystem, event-log, and indicator evidence. Anti-forensics detector flagged mft_creation_postdates_prefetch_execution on C:\Users\victim\AppData\Roaming\evil.exe. Anti-forensics detector flagged mft_created_after_modified on C:\Users\victim\AppData\Roaming\evil.exe. Anti-forensics detector flagged mft_creation_postdates_usn_activity on C:\Users\victim\AppData\Roaming\evil.exe.
- MITRE: `T1071, T1204, T1059`
- Trace: `proofsift trace --graph outputs/evidence_graph.sqlite --claim-id clm-65ec35afbefb`

| Evidence ID | Kind | Source | Tool | Key Fields |
| --- | --- | --- | --- | --- |
| `art-20132a25109b` | `malfind` | `malfind` | `memory_malfind` | `{"pid": "1888", "process": "evil.exe"}` |
| `art-26931b5b738b` | `mft` | `mft` | `timeline_mft` | `{"path": "C:\\Users\\victim\\AppData\\Roaming\\evil.exe"}` |
| `art-32b34cdf06d1` | `process` | `psscan` | `memory_psscan` | `{"name": "evil.exe", "pid": "1888"}` |
| `art-448c29d57e04` | `powershell_log` | `powershell` | `powershell_logs` | `{"time_utc": "2026-05-20T14:02:10Z"}` |
| `art-62a8e35bf523` | `process_creation` | `security_4688` | `windows_process_creation` | `{"time_utc": "2026-05-20T14:02:10Z"}` |
| `art-c07f340c31b5` | `network` | `netscan` | `memory_netscan` | `{"pid": "1888", "process": "evil.exe", "remote_ip": "203.0.113.50", "remote_port": "443"}` |
| `art-c7baa6f70f81` | `amcache` | `amcache` | `disk_amcache` | `{"path": "C:\\Users\\victim\\AppData\\Roaming\\evil.exe", "sha256": "4f7b4e9e1a2d9f0d934c06b9f39e4c6f1ef88aaad861a4c60b8636b32701f7a7"}` |
| `art-cb4d17a8bf22` | `shimcache` | `shimcache` | `disk_shimcache` | `{"entry_type": "AppCompatCache", "file_path": "C:\\Users\\victim\\AppData\\Roaming\\evil.exe", "last_modified_utc": "2026-05-20T14:02:05Z", "source": "System hive"}` |
| `art-cc867c29b973` | `prefetch` | `prefetch` | `disk_prefetch` | `{"executable": "EVIL.EXE", "last_run_utc": "2026-05-20T14:02:13Z", "path": "C:\\Windows\\Prefetch\\EVIL.EXE-9A8B7C6D.pf"}` |
| `art-ec639a3796bc` | `evtx` | `evtx` | `windows_evtx` | `{"time_utc": "2026-05-20T14:02:10Z"}` |

### clm-7034870b772f - CONFIRMED - HIGH

evil.exe established user-level persistence through an autorun registry location

- Confidence: `1.00`
- Rationale: Autorun evidence points to the same executable corroborated by execution artifacts. Anti-forensics detector flagged mft_creation_postdates_prefetch_execution on C:\Users\victim\AppData\Roaming\evil.exe. Anti-forensics detector flagged mft_created_after_modified on C:\Users\victim\AppData\Roaming\evil.exe. Anti-forensics detector flagged mft_creation_postdates_usn_activity on C:\Users\victim\AppData\Roaming\evil.exe.
- MITRE: `T1060, T1547.001`
- Trace: `proofsift trace --graph outputs/evidence_graph.sqlite --claim-id clm-7034870b772f`

| Evidence ID | Kind | Source | Tool | Key Fields |
| --- | --- | --- | --- | --- |
| `art-20132a25109b` | `malfind` | `malfind` | `memory_malfind` | `{"pid": "1888", "process": "evil.exe"}` |
| `art-26931b5b738b` | `mft` | `mft` | `timeline_mft` | `{"path": "C:\\Users\\victim\\AppData\\Roaming\\evil.exe"}` |
| `art-32b34cdf06d1` | `process` | `psscan` | `memory_psscan` | `{"name": "evil.exe", "pid": "1888"}` |
| `art-448c29d57e04` | `powershell_log` | `powershell` | `powershell_logs` | `{"time_utc": "2026-05-20T14:02:10Z"}` |
| `art-62a8e35bf523` | `process_creation` | `security_4688` | `windows_process_creation` | `{"time_utc": "2026-05-20T14:02:10Z"}` |
| `art-c7baa6f70f81` | `amcache` | `amcache` | `disk_amcache` | `{"path": "C:\\Users\\victim\\AppData\\Roaming\\evil.exe", "sha256": "4f7b4e9e1a2d9f0d934c06b9f39e4c6f1ef88aaad861a4c60b8636b32701f7a7"}` |
| `art-cb4d17a8bf22` | `shimcache` | `shimcache` | `disk_shimcache` | `{"entry_type": "AppCompatCache", "file_path": "C:\\Users\\victim\\AppData\\Roaming\\evil.exe", "last_modified_utc": "2026-05-20T14:02:05Z", "source": "System hive"}` |
| `art-cc867c29b973` | `prefetch` | `prefetch` | `disk_prefetch` | `{"executable": "EVIL.EXE", "last_run_utc": "2026-05-20T14:02:13Z", "path": "C:\\Windows\\Prefetch\\EVIL.EXE-9A8B7C6D.pf"}` |
| `art-ec479b320e40` | `autorun` | `autoruns` | `registry_autoruns` | `{"name": "Updater", "path": "C:\\Users\\victim\\AppData\\Roaming\\evil.exe", "registry_key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"}` |
| `art-ec639a3796bc` | `evtx` | `evtx` | `windows_evtx` | `{"time_utc": "2026-05-20T14:02:10Z"}` |

### clm-141f403d3112 - INFERRED - HIGH

evil.exe contains suspicious executable memory regions consistent with injected code

- Confidence: `1.00`
- Rationale: Volatile memory malfind evidence indicates suspicious executable memory; disk and process context are required for confirmation. Anti-forensics detector flagged mft_creation_postdates_prefetch_execution on C:\Users\victim\AppData\Roaming\evil.exe. Anti-forensics detector flagged mft_created_after_modified on C:\Users\victim\AppData\Roaming\evil.exe. Anti-forensics detector flagged mft_creation_postdates_usn_activity on C:\Users\victim\AppData\Roaming\evil.exe.
- MITRE: `T1055`
- Trace: `proofsift trace --graph outputs/evidence_graph.sqlite --claim-id clm-141f403d3112`

| Evidence ID | Kind | Source | Tool | Key Fields |
| --- | --- | --- | --- | --- |
| `art-20132a25109b` | `malfind` | `malfind` | `memory_malfind` | `{"pid": "1888", "process": "evil.exe"}` |

### clm-3b3b025a7663 - INFERRED - HIGH

unknown.exe communicated with known C2 indicator 198.51.100.24:443

- Confidence: `0.15`
- Rationale: Initial network triage matched a configured C2 indicator; disk execution evidence is required before confirmation.
- MITRE: `T1071`
- Trace: `proofsift trace --graph outputs/evidence_graph.sqlite --claim-id clm-3b3b025a7663`

| Evidence ID | Kind | Source | Tool | Key Fields |
| --- | --- | --- | --- | --- |
| `art-8087bd3ed677` | `network` | `netscan` | `memory_netscan` | `{"pid": "4444", "process": "unknown.exe", "remote_ip": "198.51.100.24", "remote_port": "443"}` |

### clm-f756b5943b93 - INFERRED - MEDIUM

PowerShell process creation events show script-based staging before malicious execution

- Confidence: `1.00`
- Rationale: Event logs show staging behavior; no claim is confirmed without matching payload and execution artifacts. Anti-forensics detector flagged mft_creation_postdates_prefetch_execution on C:\Users\victim\AppData\Roaming\evil.exe. Anti-forensics detector flagged mft_created_after_modified on C:\Users\victim\AppData\Roaming\evil.exe. Anti-forensics detector flagged mft_creation_postdates_usn_activity on C:\Users\victim\AppData\Roaming\evil.exe.
- MITRE: `T1059.001`
- Trace: `proofsift trace --graph outputs/evidence_graph.sqlite --claim-id clm-f756b5943b93`

| Evidence ID | Kind | Source | Tool | Key Fields |
| --- | --- | --- | --- | --- |
| `art-448c29d57e04` | `powershell_log` | `powershell` | `powershell_logs` | `{"time_utc": "2026-05-20T14:02:10Z"}` |
| `art-bf99ba2ed168` | `powershell_log` | `powershell` | `powershell_logs` | `{"time_utc": "2026-05-20T14:01:55Z"}` |

### clm-b0f4f72e0558 - POSSIBLE - INFO

svchost.exe was observed but not escalated without malicious corroboration

- Confidence: `0.03`
- Rationale: Negative control: common system process is retained as context, not reported as a finding.
- MITRE: `n/a`
- Trace: `proofsift trace --graph outputs/evidence_graph.sqlite --claim-id clm-b0f4f72e0558`

| Evidence ID | Kind | Source | Tool | Key Fields |
| --- | --- | --- | --- | --- |
| `art-6091be787caa` | `process` | `pslist` | `memory_pslist` | `{"name": "svchost.exe", "pid": "412"}` |

## Self-Corrections

- Iteration `1` corrected `clm-3b3b025a7663`: downgraded pending disk corroboration
- Iteration `1` corrected `clm-65ec35afbefb`: Bayesian posterior recalculated from forensic probability matrix
- Iteration `1` corrected `clm-65ec35afbefb`: Command and Control claim `clm-65ec35afbefb` exists without preceding Execution evidence in the current ATT&CK sequence. [COUNTERFACTUAL FAILURE] Denied escalation - Expected execution artifact in Shimcache, Amcache, Prefetch, or Security Event ID 4688 missing.
- Iteration `1` corrected `clm-3b3b025a7663`: Bayesian posterior recalculated from forensic probability matrix
- Iteration `1` corrected `clm-65ec35afbefb`: Bayesian posterior recalculated from forensic probability matrix
- Iteration `1` corrected `clm-3b3b025a7663`: Bayesian posterior recalculated from forensic probability matrix
- Iteration `1` corrected `clm-65ec35afbefb`: downgraded pending disk corroboration
- Iteration `1` corrected `clm-3b3b025a7663`: Command and Control claim `clm-3b3b025a7663` exists without preceding Execution evidence in the current ATT&CK sequence. [COUNTERFACTUAL FAILURE] Denied escalation - Expected execution artifact in Shimcache, Amcache, Prefetch, or Security Event ID 4688 missing.
- Iteration `2` corrected `None`: MFT sequence entropy analyzer flagged structural timestomping signal for C:\Users\victim\AppData\Roaming\evil.exe
- Iteration `2` corrected `None`: formal bounded model checker detected impossible timeline for C:\Users\victim\AppData\Roaming\evil.exe
- Iteration `2` corrected `clm-141f403d3112`: anti-forensics anomaly added to Bayesian scoring context
- Iteration `2` corrected `clm-141f403d3112`: anti-forensics anomaly added to Bayesian scoring context
- Iteration `2` corrected `clm-7034870b772f`: anti-forensics anomaly added to Bayesian scoring context
- Iteration `2` corrected `clm-65ec35afbefb`: anti-forensics anomaly added to Bayesian scoring context
- Iteration `2` corrected `clm-141f403d3112`: anti-forensics anomaly added to Bayesian scoring context
- Iteration `2` corrected `None`: clock drift normalization applied to cross-source observations
- Iteration `2` corrected `clm-7034870b772f`: anti-forensics anomaly added to Bayesian scoring context
- Iteration `2` corrected `clm-f756b5943b93`: anti-forensics anomaly added to Bayesian scoring context
- Iteration `2` corrected `clm-f756b5943b93`: anti-forensics anomaly added to Bayesian scoring context
- Iteration `2` corrected `None`: formal bounded model checker detected impossible timeline for C:\Users\victim\AppData\Roaming\evil.exe
- Iteration `2` corrected `clm-65ec35afbefb`: anti-forensics anomaly added to Bayesian scoring context
- Iteration `2` corrected `clm-7034870b772f`: anti-forensics anomaly added to Bayesian scoring context
- Iteration `2` corrected `clm-f756b5943b93`: anti-forensics anomaly added to Bayesian scoring context
- Iteration `2` corrected `clm-65ec35afbefb`: anti-forensics anomaly added to Bayesian scoring context
- Iteration `2` corrected `None`: formal bounded model checker detected impossible timeline for C:\Users\victim\AppData\Roaming\evil.exe
- Iteration `2` corrected `clm-141f403d3112`: Bayesian posterior recalculated from forensic probability matrix
- Iteration `2` corrected `clm-65ec35afbefb`: upgraded after disk and event-log corroboration
- Iteration `2` corrected `clm-f756b5943b93`: Bayesian posterior recalculated from forensic probability matrix
- Iteration `2` corrected `clm-65ec35afbefb`: Bayesian posterior recalculated from forensic probability matrix
- Iteration `2` corrected `clm-7034870b772f`: Bayesian posterior recalculated from forensic probability matrix
- Iteration `3` corrected `clm-b0f4f72e0558`: Bayesian posterior recalculated from forensic probability matrix

## Clock Drift Normalization

- `evtx` normalized against `netscan` with `120` second offset; confidence `0.92`. Reason: shared anchor matched remote IP 203.0.113.50 across netscan and evtx

## Anti-Forensics Anomalies

- `mft_creation_postdates_prefetch_execution` on `C:\Users\victim\AppData\Roaming\evil.exe` (HIGH, multiplier `1.12`), evidence `art-26931b5b738b, art-cc867c29b973`. MFT creation time occurs after observed execution, consistent with timestomping or metadata manipulation.
- `mft_creation_postdates_usn_activity` on `C:\Users\victim\AppData\Roaming\evil.exe` (HIGH, multiplier `1.1`), evidence `art-26931b5b738b, art-9967dfc1d649`. USN activity predates MFT creation metadata for the same executable.
- `mft_created_after_modified` on `C:\Users\victim\AppData\Roaming\evil.exe` (MEDIUM, multiplier `1.08`), evidence `art-26931b5b738b`. Creation timestamp occurs after modification timestamp.

## Formal Bounded Model Checking

- `CONTRADICTION` `usn_activity_must_not_predate_mft_creation` on `C:\Users\victim\AppData\Roaming\evil.exe` with timeline validity `0.00`. Contradiction: USN record sequence violates causal time-density bounds. Evidence: `art-26931b5b738b, art-9967dfc1d649`.
- `CONTRADICTION` `mft_creation_must_not_postdate_prefetch_execution` on `C:\Users\victim\AppData\Roaming\evil.exe` with timeline validity `0.00`. Contradiction: Prefetch execution predates MFT creation beyond bounded OS causality tolerance. Evidence: `art-26931b5b738b, art-cc867c29b973`.
- `CONTRADICTION` `mft_creation_must_not_postdate_amcache_first_run` on `C:\Users\victim\AppData\Roaming\evil.exe` with timeline validity `0.00`. Contradiction: Amcache first-run observation predates MFT creation beyond bounded OS causality tolerance. Evidence: `art-26931b5b738b, art-c7baa6f70f81`.

## MFT Structural Entropy

- `ANOMALOUS_MALICIOUS_TIMESTOMPING` on `C:\Users\victim\AppData\Roaming\evil.exe` with entropy `1.4729` bits. Baseline delta/record `15.3030s`, target delta/record `14.5455s`. Signals: `execution_timestamp_diverges_from_mft_creation, usn_activity_diverges_from_mft_creation, high_temporal_density_delta`. Evidence: `art-0d92135c5725, art-26931b5b738b, art-9967dfc1d649, art-c7baa6f70f81, art-cc867c29b973, art-e78297ba3302`.

## MITRE ATT&CK Sequence Recommendations

- `missing_preceding_behavior_for_command_and_control` for claim `clm-65ec35afbefb`: Command and Control claim `clm-65ec35afbefb` exists without preceding Execution evidence in the current ATT&CK sequence. [COUNTERFACTUAL FAILURE] Denied escalation - Expected execution artifact in Shimcache, Amcache, Prefetch, or Security Event ID 4688 missing. Tools: `disk_amcache, disk_prefetch, memory_psscan, windows_evtx`. Paths: Amcache.hve program entries; C:\Windows\Prefetch\*.pf; Security.evtx Event ID 4688; Shimcache/AppCompatCache entries; memory process listings for hidden or terminated processes
- `missing_preceding_behavior_for_command_and_control` for claim `clm-3b3b025a7663`: Command and Control claim `clm-3b3b025a7663` exists without preceding Execution evidence in the current ATT&CK sequence. [COUNTERFACTUAL FAILURE] Denied escalation - Expected execution artifact in Shimcache, Amcache, Prefetch, or Security Event ID 4688 missing. Tools: `disk_amcache, disk_prefetch, memory_psscan, windows_evtx`. Paths: Amcache.hve program entries; C:\Windows\Prefetch\*.pf; Security.evtx Event ID 4688; Shimcache/AppCompatCache entries; memory process listings for hidden or terminated processes

## Counterfactual Falsification

- `FAIL` `command_and_control_requires_execution_cache_and_timeline_alibi` for claim `clm-65ec35afbefb`. Present: none. Missing: $MFT timeline entry, $UsnJrnl file transition, Amcache program inventory, Prefetch execution cache, Security.evtx Event ID 4688, Shimcache/AppCompatCache entry. Action: `denied_escalation`.
- `FAIL` `command_and_control_requires_execution_cache_and_timeline_alibi` for claim `clm-3b3b025a7663`. Present: none. Missing: $MFT timeline entry, $UsnJrnl file transition, Amcache program inventory, Prefetch execution cache, Security.evtx Event ID 4688, Shimcache/AppCompatCache entry. Action: `denied_escalation`.
- `PASS` `registry_persistence_requires_prior_execution_alibi` for claim `clm-7034870b772f`. Present: Registry autorun entry, Prefetch execution cache, Amcache program inventory, Shimcache/AppCompatCache entry, Security.evtx Event ID 4688. Missing: none. Action: `allow_escalation`.
- `PASS` `command_and_control_requires_execution_cache_and_timeline_alibi` for claim `clm-65ec35afbefb`. Present: Prefetch execution cache, Amcache program inventory, Shimcache/AppCompatCache entry, Security.evtx Event ID 4688, $MFT timeline entry. Missing: none. Action: `allow_escalation`.
- `FAIL` `command_and_control_requires_execution_cache_and_timeline_alibi` for claim `clm-3b3b025a7663`. Present: none. Missing: $MFT timeline entry, $UsnJrnl file transition, Amcache program inventory, Prefetch execution cache, Security.evtx Event ID 4688, Shimcache/AppCompatCache entry. Action: `denied_escalation`.
- `PASS` `registry_persistence_requires_prior_execution_alibi` for claim `clm-7034870b772f`. Present: Registry autorun entry, Prefetch execution cache, Amcache program inventory, Shimcache/AppCompatCache entry, Security.evtx Event ID 4688. Missing: none. Action: `allow_escalation`.
- `PASS` `command_and_control_requires_execution_cache_and_timeline_alibi` for claim `clm-65ec35afbefb`. Present: Prefetch execution cache, Amcache program inventory, Shimcache/AppCompatCache entry, Security.evtx Event ID 4688, $MFT timeline entry. Missing: none. Action: `allow_escalation`.
- `FAIL` `command_and_control_requires_execution_cache_and_timeline_alibi` for claim `clm-3b3b025a7663`. Present: none. Missing: $MFT timeline entry, $UsnJrnl file transition, Amcache program inventory, Prefetch execution cache, Security.evtx Event ID 4688, Shimcache/AppCompatCache entry. Action: `denied_escalation`.

## Bayesian Forensic Calculus

Formula: `P(H|E) = P(E|H) * P(H) / P(E)`.
- Claim `clm-141f403d3112` posterior `0.9999` from prior `0.1600`, P(E|H) `0.596642`, P(E|not H) `0.000000`. Signals: `malfind, mft_created_after_modified, mft_creation_postdates_prefetch_execution, mft_creation_postdates_usn_activity`.
- Claim `clm-3b3b025a7663` posterior `0.1535` from prior `0.1000`, P(E|H) `0.620000`, P(E|not H) `0.380000`. Signals: `network`.
- Claim `clm-65ec35afbefb` posterior `0.1633` from prior `0.1000`, P(E|H) `0.434000`, P(E|not H) `0.247000`. Signals: `network, process`.
- Claim `clm-7034870b772f` posterior `0.9999` from prior `0.1200`, P(E|H) `0.062874`, P(E|not H) `0.000000`. Signals: `amcache, autorun, evtx, malfind, mft, powershell_log, prefetch, process, process_creation, shimcache, mft_created_after_modified, mft_creation_postdates_prefetch_execution, mft_creation_postdates_usn_activity`.
- Claim `clm-b0f4f72e0558` posterior `0.0322` from prior `0.0300`, P(E|H) `0.700000`, P(E|not H) `0.650000`. Signals: `process`.
- Claim `clm-f756b5943b93` posterior `0.9999` from prior `0.1800`, P(E|H) `0.449085`, P(E|not H) `0.000000`. Signals: `powershell_log, mft_created_after_modified, mft_creation_postdates_prefetch_execution, mft_creation_postdates_usn_activity`.

## Ephemeral MCP Tool Authorization

- `16` of `16` tool executions carried one-time HMAC-SHA256 nonce authorization envelopes.
- Each authorization stores a nonce hash, payload hash, signature, status, and expiry in the evidence graph.

## Evidence Integrity

- Evidence files were hashed before analysis.
- Merkle-DAG root seal: `sha256:3ac7d3e11efd441a3cb96b1e0b3e77ff07cacba5fceb332d30aff087fdaf172e`.
- Merkle-DAG nodes: `197` total; relationship blocks: `25`.
- Merkle-DAG verification status: `True`.
- The path policy allowed reads from registered evidence roots only.
- The spoliation probe verified that writes into the evidence root are blocked.
- Report, graph, and logs are written only under the configured output directory.
- Re-verify with: `proofsift verify-integrity --graph outputs/evidence_graph.sqlite`.

## Reproducibility

Run the same case with:

```bash
proofsift run --case cases/demo_case/case.json --max-iterations 3
proofsift benchmark --case cases/demo_case/case.json --ground-truth cases/demo_case/ground_truth.json
```
