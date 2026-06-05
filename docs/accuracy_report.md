# Accuracy Report: ProofSIFT Demo Case

**Case ID:** proofsift-demo-001
**Benchmark Date:** 2026-06-01
**Agent Version:** 0.1.0

---

## Summary

| Metric | Result |
|--------|--------|
| **Benchmark Result** | PASSED |
| **Precision** | 1.0 |
| **Recall** | 1.0 |
| **Confirmed Claims** | 2 |
| **Self-Corrections** | 23 |
| **Clock Drifts Detected** | 1 |
| **Anti-Forensics Anomalies Found** | 2 |
| **MITRE Sequence Recommendations** | 2 |
| **Counterfactual Alibi Checks** | 8 |
| **Bayesian Posterior Scores** | 15 |
| **Merkle-DAG Integrity** | PASSED |
| **Execution Runtime** | ~0.15 seconds |

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
   Counterfactual Alibi Checks    : 8 (4 denied escalations)
   Bayesian Posterior Scores      : 15 computed
   Merkle-DAG Integrity Seal      : sha256:<root>
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
| evil.exe communicated with known C2 indicator 203.0.113.50 | clm-* | ✅ CONFIRMED — CRITICAL |
| evil.exe established user-level persistence | clm-* | ✅ CONFIRMED — HIGH |

**Evidence chain for C2 finding (10+ artifact kinds):**
1. `network` — netscan: PID 1888 evil.exe -> 203.0.113.50:443 (ESTABLISHED)
2. `process` — psscan: evil.exe PID 1888, hidden process
3. `prefetch` — EVIL.EXE 3 runs, last_run 14:02:13Z
4. `amcache` — evil.exe unsigned, SHA-256 recorded
5. `shimcache` — evil.exe in AppCompatCache
6. `mft` — evil.exe path in filesystem timeline
7. `evtx` — Event ID 4688: evil.exe launched by powershell.exe
8. `process_creation` — Security 4688 filtered event
9. `powershell_log` — PowerShell staging activity
10. `malfind` — evil.exe PID 1888, PAGE_EXECUTE_READWRITE with MZ header
11. `yara_match` — keyword match on "evil beacon" and "c2 channel"

**Evidence chain for Persistence finding:**
1. `autorun` — "Updater" entry in HKCU\Run points to evil.exe
2. Corroborated by all execution artifacts above (prefetch, amcache, MFT, EVTX, process)

---

## Forbidden Confirmations (False Positives)

| Forbidden Finding | Result | Reason |
|------------------|--------|--------|
| unknown.exe C2 with 198.51.100.24 | ✅ Correctly INFERRED (not CONFIRMED) | Network-only evidence, no disk corroboration |
| svchost.exe malicious | ✅ Correctly POSSIBLE/INFO (not escalated) | Negative control — benign process retained as context |

**False Positives Raised:** 0

---

## Hallucinated Claims

**Hallucinated Confirmed Claims:** 0

All confirmed claims have verified artifact evidence chains via the SQLite provenance graph.

---

## Advanced Detection Results

### Clock Drift Normalization

| Source | Reference | Delta | Confidence | Anchor |
|--------|-----------|-------|------------|--------|
| evtx | netscan | +120 seconds | 0.92 | Remote IP 203.0.113.50 in netscan.first_seen (14:03:30Z) and evtx 4624 logon message (14:01:30Z) |

The normalizer discovered the shared anchor (remote IP 203.0.113.50) across memory network evidence and Windows Event Log, calculated a +120 second EVTX lag, and applied the correction to all EVTX-derived observations.

### Anti-Forensics Anomalies

| Anomaly Type | Target | Multiplier | Evidence |
|-------------|--------|------------|----------|
| mft_creation_postdates_prefetch_execution | C:\Users\victim\AppData\Roaming\evil.exe | 1.12x | MFT created 14:10:05Z vs Prefetch last_run 14:02:13Z (skew 472s) |
| mft_created_after_modified | C:\Users\victim\AppData\Roaming\evil.exe | 1.08x | MFT created 14:10:05Z vs MFT modified 14:02:05Z |

Both anomalies are consistent with timestomping — an attacker modifying the MFT creation timestamp to obscure the true file origin.

### MITRE ATT&CK Sequence Recommendations

| Gap Type | Target Claim | Missing Tactics | Recommended Tools |
|----------|-------------|----------------|-------------------|
| missing_preceding_behavior_for_command_and_control | evil.exe C2 claim | Execution | disk_prefetch, disk_amcache, memory_psscan, windows_evtx |
| missing_preceding_behavior_for_command_and_control | unknown.exe C2 claim | Execution | disk_prefetch, disk_amcache, memory_psscan, windows_evtx |

These gaps prompted the agent to deploy disk investigation tools in Iteration 2, which provided the execution evidence needed to upgrade the evil.exe C2 claim to CONFIRMED.

---

### Counterfactual Falsification

ProofSIFT runs active missing-evidence checks before escalation. For a C2 claim, the critic expects execution-cache and filesystem side effects such as Shimcache, Amcache, Prefetch, Event ID 4688, MFT, or USN records.

The weak `unknown.exe` network-only claim produces:

```text
[COUNTERFACTUAL FAILURE] Denied escalation - Expected execution artifact in Shimcache/AppCompatCache entry, Amcache program inventory, Prefetch execution cache, Security.evtx Event ID 4688 missing.
```

This keeps the claim inferred even though the IP is suspicious.

### Bayesian Forensic Calculus

Confidence scores are recalculated from a reproducible probability matrix:

```text
P(H|E) = P(E|H) * P(H) / P(E)
```

Isolated network evidence remains low-confidence. Multi-source evidence such as netscan plus Prefetch, Amcache, MFT, Event ID 4688, and anti-forensics anomalies converges toward a confirmed critical posterior.

### Merkle-DAG Integrity Seal

The evidence graph can be independently verified:

```bash
proofsift verify-integrity --graph cases/demo_case/outputs/evidence_graph.sqlite
```

The command returns one `sha256:<root>` seal over tool runs, artifact content hashes, observations, claims, signed claim-evidence relationship blocks, corrections, Bayesian scores, and counterfactual checks.

---

## Self-Correction Summary

The agent recorded **23 self-correction events** across 3 iterations:

| Iteration | Corrections | Description |
|-----------|-------------|-------------|
| 1 | 8 | 2 C2 claims downgraded to INFERRED, 2 MITRE sequence gaps detected, 2 counterfactual failures logged, and Bayesian posterior recalculations recorded |
| 2 | 14 | 1 claim upgraded to CONFIRMED, anti-forensics context added, clock drift normalized, counterfactual checks rerun, and Bayesian posterior recalculations recorded |
| 3 | 1 | Confidence adjustment carried forward |

---

## Evidence Integrity Verification

| Test | Result |
|------|--------|
| SHA-256 evidence hashing before analysis | ✅ 11 evidence files hashed |
| Spoliation probe (evidence write blocked) | ✅ Write rejection confirmed |
| Read policy enforcement | ✅ All reads within evidence root |
| Write policy enforcement | ✅ All writes to output directory |
| SQLite provenance graph | ✅ Commands, artifacts, claims, corrections linked |

---

## Reproducibility

Run the exact same benchmark:

```bash
proofsift benchmark --case cases/demo_case/case.json --ground-truth cases/demo_case/ground_truth.json --max-iterations 3
```

Results are deterministic — identical evidence always produces identical claims, corrections, and scores.
