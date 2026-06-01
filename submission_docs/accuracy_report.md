# Accuracy Report: ProofSIFT Demo Case

**Case ID:** proofsift-demo-001
**Benchmark Date:** 2026-06-01
**Agent Version:** 0.1.0
**Repository:** https://github.com/sleader3221-dot/ProofSIFT

---

## Summary

| Metric | Result |
|--------|--------|
| Benchmark Result | **PASSED** |
| Precision | **1.0** |
| Recall | **1.0** |
| Confirmed Claims | 2 |
| Self-Corrections | 14 |
| Clock Drifts Detected | 1 |
| Anti-Forensics Anomalies Found | 2 |
| MITRE Sequence Recommendations | 2 |
| Execution Runtime | ~0.15 seconds |

---

## Scoring Matrix

```
======================================================================
          PROOFSIFT ACCURACY BENCHMARK HARNESS
======================================================================
 FORENSIC DETECTION RESULTS:
  Forensic True Positives Caught : 2 / 2  (100.0%)
   False Positive Claims Raised   : 0      (0.00%)
   Hallucinated Items Intercepted : 0     (Enforced via Critic)
   Anti-Forensics Anomalies Found : 2 / 2  (100.0%)
  Clock-Drift Adjustments Applied: 1 / 1  (120s Normalized)
   Evidence Spoliation Attempts   : 0 Writes Allowed (2 Blocked by Policy)
 SYSTEM METRICS:
   Total Execution Runtime        : 0.15 seconds
   Final Benchmark Accuracy Score : 100.0% [PERFECT MATURATION]
======================================================================
```

---

## Expected Findings Matched

| Expected Finding | Claim ID | Status |
|-----------------|----------|--------|
| evil.exe communicated with known C2 indicator 203.0.113.50 | clm-* | **CONFIRMED** — CRITICAL (confidence 0.99) |
| evil.exe established user-level persistence through autorun | clm-* | **CONFIRMED** — HIGH (confidence 0.99) |

### Evidence Chain: C2 Communication (10+ artifact kinds)

| # | Artifact Kind | Source | Key Evidence |
|---|--------------|--------|-------------|
| 1 | network | netscan | evil.exe PID 1888 -> 203.0.113.50:443 ESTABLISHED |
| 2 | process | psscan | evil.exe PID 1888 (hidden process) |
| 3 | prefetch | disk_prefetch | EVIL.EXE 3 runs, last_run 14:02:13Z |
| 4 | amcache | disk_amcache | evil.exe unsigned, SHA-256: 4f7b4e9e... |
| 5 | shimcache | disk_shimcache | evil.exe in AppCompatCache |
| 6 | mft | timeline_mft | C:\Users\victim\AppData\Roaming\evil.exe |
| 7 | evtx | windows_evtx | Event ID 4688: evil.exe launched by powershell.exe |
| 8 | process_creation | windows_process_creation | Security 4688 filtered event |
| 9 | powershell_log | powershell_logs | PowerShell staging activity |
| 10 | malfind | memory_malfind | RWX region with MZ header in PID 1888 |
| 11 | yara_match | yara_keyword_scan | "evil beacon", "c2 channel" matched |

### Evidence Chain: Registry Persistence

| # | Artifact Kind | Source | Key Evidence |
|---|--------------|--------|-------------|
| 1 | autorun | registry_autoruns | "Updater" in HKCU\Run -> evil.exe |
| 2-11 | All above | All sources | Execution corroboration for same executable |

---

## Forbidden Confirmations (Zero False Positives)

| Forbidden Finding | Actual Status | Why Correct |
|------------------|--------------|-------------|
| unknown.exe C2 with 198.51.100.24 | **INFERRED** (not CONFIRMED) | Network-only — no disk/execution evidence; correctly not escalated |
| svchost.exe malicious | **POSSIBLE / INFO** (not escalated) | Negative control — benign process retained as context only |

**False Positive Claims Raised: 0**

---

## Hallucinated Claims

**Hallucinated Confirmed Claims: 0**

All 2 confirmed claims have verified artifact evidence chains via the SQLite provenance `claim_evidence` join table. Zero confirmed claims exist without linked evidence.

---

## Advanced Detection Results

### Clock Drift Normalization

| Source | Reference | Delta | Confidence | Anchor Matching |
|--------|-----------|-------|------------|----------------|
| evtx | netscan | **+120 seconds** | 0.92 | Remote IP `203.0.113.50` in netscan.first_seen (14:03:30Z) AND evtx 4624 logon message (14:01:30Z) |

**Method:** The normalizer discovered the shared anchor (remote IP 203.0.113.50) across memory network evidence and Windows Event Log. The timestamp delta (14:03:30Z - 14:01:30Z = +120s) was calculated and applied to all EVTX-derived observations in the SQLite observations table.

### Anti-Forensics Anomalies (2 detected)

| Anomaly Type | Target | Multiplier | Evidence |
|-------------|--------|:----------:|----------|
| mft_creation_postdates_prefetch_execution | evil.exe | **1.12x** | MFT created 14:10:05Z vs Prefetch last_run 14:02:13Z (skew = 472s) |
| mft_created_after_modified | evil.exe | **1.08x** | MFT created 14:10:05Z vs MFT modified 14:02:05Z |

Both anomalies are consistent with timestomping — an attacker retroactively modifying the MFT creation timestamp to obscure the true file origin. Confidence multipliers were applied to all claims referencing evil.exe.

### MITRE ATT&CK Sequence Recommendations (2 generated)

| Gap Type | Target Claim | Missing Tactic | Recommended Tools |
|----------|-------------|----------------|-------------------|
| missing_preceding_behavior_for_command_and_control | evil.exe C2 claim | Execution | disk_prefetch, disk_amcache, memory_psscan, windows_evtx |
| missing_preceding_behavior_for_command_and_control | unknown.exe C2 claim | Execution | disk_prefetch, disk_amcache, memory_psscan, windows_evtx |

These MITRE sequence gaps triggered the deployment of disk investigation tools in Iteration 2, which provided the execution evidence needed to upgrade the evil.exe C2 claim from INFERRED to CONFIRMED.

---

## Self-Correction Log (14 events)

| Iteration | Count | Key Corrections |
|-----------|:-----:|-----------------|
| 1 | 4 | 2 C2 claims downgraded to INFERRED (pending disk corroboration); 2 MITRE sequence gaps flagged |
| 2 | 9 | 1 claim upgraded to CONFIRMED (evil.exe C2); 6 anti-forensics confidence adjustments; 1 clock drift normalization; 1 additional adjustment |
| 3 | 1 | Final confidence adjustment carried forward |

---

## Evidence Integrity Verification

| Integrity Check | Result |
|----------------|:------:|
| SHA-256 hashing of all 11 evidence files before analysis | PASSED |
| Spoliation probe — evidence-root write attempted and blocked | PASSED |
| Read policy — all tool reads within registered evidence root | PASSED |
| Write policy — all output written to configured output directory | PASSED |
| SQLite provenance graph — every claim linked to artifacts via FK | PASSED |
| Parser anomaly recording — malformed rows captured without crash | PASSED |

---

## Reproducibility

This benchmark is fully deterministic and reproducible:

```bash
# Install
python -m pip install -e .

# Run benchmark
proofsift benchmark --case cases/demo_case/case.json --ground-truth cases/demo_case/ground_truth.json --max-iterations 3
```

The same evidence always produces the same claims, same corrections, same scores — no randomness, no LLM variance, no prompt dependency.

---

## Scoring Methodology

| Metric | Definition | Formula |
|--------|-----------|---------|
| Precision | Proportion of confirmed claims that match expected findings | `matched_expected / (matched_expected + false_positives)` |
| Recall | Proportion of expected findings that were confirmed | `matched_expected / expected_confirmed` |
| Hallucination | Confirmed claim with zero linked evidence artifacts | `evidence_count(claim_id) == 0` |
| Pass/Fail | All expected matched, zero false positives, zero hallucinations, zero missed anomalies/drifts | AND of all conditions |
