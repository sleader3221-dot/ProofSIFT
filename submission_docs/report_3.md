# ProofSIFT Investigation Report: ProofSIFT Demo - Self-Correcting Windows Triage

## Executive Summary

- Case ID: `proofsift-demo-001`
- Evidence directory: `cases\demo_case\evidence`
- Claims produced: `6`
- Self-corrections recorded: `14`
- Clock drift adjustments: `1`
- Anti-forensics anomalies: `2`
- MITRE sequence recommendations: `2`

## Findings

### clm-3577b9dc1160 - CONFIRMED - CRITICAL

evil.exe communicated with known C2 indicator 203.0.113.50:443

- Confidence: `0.99`
- Rationale: C2 communication is corroborated by memory, execution, filesystem, event-log, and indicator evidence. Anti-forensics detector flagged mft_creation_postdates_prefetch_execution on C:\Users\victim\AppData\Roaming\evil.exe. Anti-forensics detector flagged mft_created_after_modified on C:\Users\victim\AppData\Roaming\evil.exe.
- MITRE: `T1071, T1204, T1059`
- Trace: `proofsift trace --graph outputs/evidence_graph.sqlite --claim-id clm-3577b9dc1160`

| Evidence ID | Kind | Source | Tool | Key Fields |
| --- | --- | --- | --- | --- |
| `art-09c4b92ab3ba` | `process_creation` | `security_4688` | `windows_process_creation` | `{"time_utc": "2026-05-20T14:02:10Z"}` |
| `art-108b1599a523` | `powershell_log` | `powershell` | `powershell_logs` | `{"time_utc": "2026-05-20T14:02:10Z"}` |
| `art-261bb9554f7e` | `malfind` | `malfind` | `memory_malfind` | `{"pid": "1888", "process": "evil.exe"}` |
| `art-61e0ceeb1ad2` | `mft` | `mft` | `timeline_mft` | `{"path": "C:\\Users\\victim\\AppData\\Roaming\\evil.exe"}` |
| `art-61e3634bc16e` | `prefetch` | `prefetch` | `disk_prefetch` | `{"executable": "EVIL.EXE", "last_run_utc": "2026-05-20T14:02:13Z", "path": "C:\\Windows\\Prefetch\\EVIL.EXE-9A8B7C6D.pf"}` |
| `art-7c6aebfa5ffd` | `shimcache` | `shimcache` | `disk_shimcache` | `{"entry_type": "AppCompatCache", "file_path": "C:\\Users\\victim\\AppData\\Roaming\\evil.exe", "last_modified_utc": "2026-05-20T14:02:05Z", "source": "System hive"}` |
| `art-868358c51755` | `evtx` | `evtx` | `windows_evtx` | `{"time_utc": "2026-05-20T14:02:10Z"}` |
| `art-bb224342756a` | `network` | `netscan` | `memory_netscan` | `{"pid": "1888", "process": "evil.exe", "remote_ip": "203.0.113.50", "remote_port": "443"}` |
| `art-ca92c409e897` | `process` | `psscan` | `memory_psscan` | `{"name": "evil.exe", "pid": "1888"}` |
| `art-ff9d3c913906` | `amcache` | `amcache` | `disk_amcache` | `{"path": "C:\\Users\\victim\\AppData\\Roaming\\evil.exe", "sha256": "4f7b4e9e1a2d9f0d934c06b9f39e4c6f1ef88aaad861a4c60b8636b32701f7a7"}` |

### clm-2f7d3efb1cc1 - CONFIRMED - HIGH

evil.exe established user-level persistence through an autorun registry location

- Confidence: `0.99`
- Rationale: Autorun evidence points to the same executable corroborated by execution artifacts. Anti-forensics detector flagged mft_creation_postdates_prefetch_execution on C:\Users\victim\AppData\Roaming\evil.exe. Anti-forensics detector flagged mft_created_after_modified on C:\Users\victim\AppData\Roaming\evil.exe.
- MITRE: `T1060, T1547.001`
- Trace: `proofsift trace --graph outputs/evidence_graph.sqlite --claim-id clm-2f7d3efb1cc1`

| Evidence ID | Kind | Source | Tool | Key Fields |
| --- | --- | --- | --- | --- |
| `art-09c4b92ab3ba` | `process_creation` | `security_4688` | `windows_process_creation` | `{"time_utc": "2026-05-20T14:02:10Z"}` |
| `art-108b1599a523` | `powershell_log` | `powershell` | `powershell_logs` | `{"time_utc": "2026-05-20T14:02:10Z"}` |
| `art-261bb9554f7e` | `malfind` | `malfind` | `memory_malfind` | `{"pid": "1888", "process": "evil.exe"}` |
| `art-61e0ceeb1ad2` | `mft` | `mft` | `timeline_mft` | `{"path": "C:\\Users\\victim\\AppData\\Roaming\\evil.exe"}` |
| `art-61e3634bc16e` | `prefetch` | `prefetch` | `disk_prefetch` | `{"executable": "EVIL.EXE", "last_run_utc": "2026-05-20T14:02:13Z", "path": "C:\\Windows\\Prefetch\\EVIL.EXE-9A8B7C6D.pf"}` |
| `art-7c6aebfa5ffd` | `shimcache` | `shimcache` | `disk_shimcache` | `{"entry_type": "AppCompatCache", "file_path": "C:\\Users\\victim\\AppData\\Roaming\\evil.exe", "last_modified_utc": "2026-05-20T14:02:05Z", "source": "System hive"}` |
| `art-868358c51755` | `evtx` | `evtx` | `windows_evtx` | `{"time_utc": "2026-05-20T14:02:10Z"}` |
| `art-b660018ed620` | `autorun` | `autoruns` | `registry_autoruns` | `{"name": "Updater", "path": "C:\\Users\\victim\\AppData\\Roaming\\evil.exe", "registry_key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"}` |
| `art-ca92c409e897` | `process` | `psscan` | `memory_psscan` | `{"name": "evil.exe", "pid": "1888"}` |
| `art-ff9d3c913906` | `amcache` | `amcache` | `disk_amcache` | `{"path": "C:\\Users\\victim\\AppData\\Roaming\\evil.exe", "sha256": "4f7b4e9e1a2d9f0d934c06b9f39e4c6f1ef88aaad861a4c60b8636b32701f7a7"}` |

### clm-4dc979975431 - INFERRED - HIGH

evil.exe contains suspicious executable memory regions consistent with injected code

- Confidence: `0.96`
- Rationale: Volatile memory malfind evidence indicates suspicious executable memory; disk and process context are required for confirmation. Anti-forensics detector flagged mft_creation_postdates_prefetch_execution on C:\Users\victim\AppData\Roaming\evil.exe. Anti-forensics detector flagged mft_created_after_modified on C:\Users\victim\AppData\Roaming\evil.exe.
- MITRE: `T1055`
- Trace: `proofsift trace --graph outputs/evidence_graph.sqlite --claim-id clm-4dc979975431`

| Evidence ID | Kind | Source | Tool | Key Fields |
| --- | --- | --- | --- | --- |
| `art-261bb9554f7e` | `malfind` | `malfind` | `memory_malfind` | `{"pid": "1888", "process": "evil.exe"}` |

### clm-3dbd0c828547 - INFERRED - HIGH

unknown.exe communicated with known C2 indicator 198.51.100.24:443

- Confidence: `0.58`
- Rationale: Initial network triage matched a configured C2 indicator; disk execution evidence is required before confirmation.
- MITRE: `T1071`
- Trace: `proofsift trace --graph outputs/evidence_graph.sqlite --claim-id clm-3dbd0c828547`

| Evidence ID | Kind | Source | Tool | Key Fields |
| --- | --- | --- | --- | --- |
| `art-c71aa43e7759` | `network` | `netscan` | `memory_netscan` | `{"pid": "4444", "process": "unknown.exe", "remote_ip": "198.51.100.24", "remote_port": "443"}` |

### clm-15324f8c311a - INFERRED - MEDIUM

PowerShell process creation events show script-based staging before malicious execution

- Confidence: `0.90`
- Rationale: Event logs show staging behavior; no claim is confirmed without matching payload and execution artifacts. Anti-forensics detector flagged mft_creation_postdates_prefetch_execution on C:\Users\victim\AppData\Roaming\evil.exe. Anti-forensics detector flagged mft_created_after_modified on C:\Users\victim\AppData\Roaming\evil.exe.
- MITRE: `T1059.001`
- Trace: `proofsift trace --graph outputs/evidence_graph.sqlite --claim-id clm-15324f8c311a`

| Evidence ID | Kind | Source | Tool | Key Fields |
| --- | --- | --- | --- | --- |
| `art-108b1599a523` | `powershell_log` | `powershell` | `powershell_logs` | `{"time_utc": "2026-05-20T14:02:10Z"}` |
| `art-475de9d374f1` | `powershell_log` | `powershell` | `powershell_logs` | `{"time_utc": "2026-05-20T14:01:55Z"}` |

### clm-93f40f0638ef - POSSIBLE - INFO

svchost.exe was observed but not escalated without malicious corroboration

- Confidence: `0.35`
- Rationale: Negative control: common system process is retained as context, not reported as a finding.
- MITRE: `n/a`
- Trace: `proofsift trace --graph outputs/evidence_graph.sqlite --claim-id clm-93f40f0638ef`

| Evidence ID | Kind | Source | Tool | Key Fields |
| --- | --- | --- | --- | --- |
| `art-26527afa2263` | `process` | `pslist` | `memory_pslist` | `{"name": "svchost.exe", "pid": "412"}` |

## Self-Corrections

- Iteration `1` corrected `clm-3dbd0c828547`: downgraded pending disk corroboration
- Iteration `1` corrected `clm-3dbd0c828547`: Command and Control claim `clm-3dbd0c828547` exists without preceding Execution evidence in the current ATT&CK sequence.
- Iteration `1` corrected `clm-3577b9dc1160`: downgraded pending disk corroboration
- Iteration `1` corrected `clm-3577b9dc1160`: Command and Control claim `clm-3577b9dc1160` exists without preceding Execution evidence in the current ATT&CK sequence.
- Iteration `2` corrected `clm-15324f8c311a`: anti-forensics confidence adjustment
- Iteration `2` corrected `clm-2f7d3efb1cc1`: anti-forensics confidence adjustment
- Iteration `2` corrected `None`: clock drift normalization applied to cross-source observations
- Iteration `2` corrected `clm-3577b9dc1160`: anti-forensics confidence adjustment
- Iteration `2` corrected `clm-2f7d3efb1cc1`: anti-forensics confidence adjustment
- Iteration `2` corrected `clm-4dc979975431`: anti-forensics confidence adjustment
- Iteration `2` corrected `clm-3577b9dc1160`: upgraded after disk and event-log corroboration
- Iteration `2` corrected `clm-4dc979975431`: anti-forensics confidence adjustment
- Iteration `2` corrected `clm-15324f8c311a`: anti-forensics confidence adjustment
- Iteration `2` corrected `clm-3577b9dc1160`: anti-forensics confidence adjustment

## Clock Drift Normalization

- `evtx` normalized against `netscan` with `120` second offset; confidence `0.92`. Reason: shared anchor matched remote IP 203.0.113.50 across netscan and evtx

## Anti-Forensics Anomalies

- `mft_creation_postdates_prefetch_execution` on `C:\Users\victim\AppData\Roaming\evil.exe` (HIGH, multiplier `1.12`), evidence `art-61e0ceeb1ad2, art-61e3634bc16e`. MFT creation time occurs after observed execution, consistent with timestomping or metadata manipulation.
- `mft_created_after_modified` on `C:\Users\victim\AppData\Roaming\evil.exe` (MEDIUM, multiplier `1.08`), evidence `art-61e0ceeb1ad2`. Creation timestamp occurs after modification timestamp.

## MITRE ATT&CK Sequence Recommendations

- `missing_preceding_behavior_for_command_and_control` for claim `clm-3577b9dc1160`: Command and Control claim `clm-3577b9dc1160` exists without preceding Execution evidence in the current ATT&CK sequence. Tools: `disk_amcache, disk_prefetch, memory_psscan, windows_evtx`. Paths: Amcache.hve program entries; C:\Windows\Prefetch\*.pf; Security.evtx Event ID 4688; memory process listings for hidden or terminated processes
- `missing_preceding_behavior_for_command_and_control` for claim `clm-3dbd0c828547`: Command and Control claim `clm-3dbd0c828547` exists without preceding Execution evidence in the current ATT&CK sequence. Tools: `disk_amcache, disk_prefetch, memory_psscan, windows_evtx`. Paths: Amcache.hve program entries; C:\Windows\Prefetch\*.pf; Security.evtx Event ID 4688; memory process listings for hidden or terminated processes

## Evidence Integrity

- Evidence files were hashed before analysis.
- The path policy allowed reads from registered evidence roots only.
- The spoliation probe verified that writes into the evidence root are blocked.
- Report, graph, and logs are written only under the configured output directory.

## Reproducibility

Run the same case with:

```bash
proofsift run --case cases/demo_case/case.json --max-iterations 3
proofsift benchmark --case cases/demo_case/case.json --ground-truth cases/demo_case/ground_truth.json
```
