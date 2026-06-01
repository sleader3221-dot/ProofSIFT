# ProofSIFT — Judge Run Instructions

## Repository

**URL:** https://github.com/sleader3221-dot/ProofSIFT

## Prerequisites

- **Python 3.10 or later** installed on any system (Windows, macOS, Linux)
- No additional dependencies required for demo mode (uses Python standard library only)
- No SIFT VM, Docker, or cloud services needed

## Step 1: Clone or Download

```bash
git clone https://github.com/sleader3221-dot/ProofSIFT.git
cd ProofSIFT
```

Or download and extract the ZIP from the GitHub repository page.

## Step 2: Install (One-Time)

```bash
python -m pip install -e .
```

This installs the `proofsift` CLI command in editable mode.

If the install step fails, use the module entry point instead (skip install):

```bash
# Windows PowerShell:
$env:PYTHONPATH="src"; python -m proofsift run --case cases/demo_case/case.json

# macOS / Linux:
PYTHONPATH=src python -m proofsift run --case cases/demo_case/case.json
```

## Step 3: Run Autonomous Investigation

```bash
proofsift run --case cases/demo_case/case.json --max-iterations 3
```

**What you will see in the terminal:**

```
======================================================================
  PROOFSIFT AUTONOMOUS DFIR ENGINE - Case: proofsift-demo-001
======================================================================

  [PHASE 1: INGESTION]
  Verifying forensic integrity hashes for case: proofsift-demo-001... [OK]

  [PHASE 2: INVESTIGATE]
  Investigator spawned. Running triage across memory and disk artifacts...

  [CLAIM DOWNGRADE] Claim clm-xxx: downgraded to INFERRED - disk evidence missing
  [CRITIC ALERT] MitreSequenceValidator flagged a structural gap!
  [TOOL] disk_prefetch: Prefetch execution artifacts parsed
  [CLOCK DRIFT] evtx normalized against netscan with 120s offset
  [CLAIM ESCALATION] Claim clm-xxx upgraded to [CONFIRMED - CRITICAL]
  [CRITIC REVIEW] Anomaly: mft_creation_postdates_prefetch_execution (1.12x multiplier)
  [OK] Negative controls verified - benign processes retained as context

======================================================================
  INVESTIGATION COMPLETE - 6 claims, 14 corrections, 7 reports generated
======================================================================
```

**Output generated in** `cases/demo_case/outputs/`:
- `report.md` — Markdown investigation report
- `report_2.md` — Strict-review copy of the report
- `report.html` — HTML investigation report
- `evidence_graph.sqlite` — Full SQLite provenance database
- `execution_log.jsonl` — Timestamped JSONL audit trail
- `trace_index.json` — Claim-to-evidence provenance mapping

## Step 4: Run Benchmark Against Ground Truth

```bash
proofsift benchmark --case cases/demo_case/case.json --ground-truth cases/demo_case/ground_truth.json --max-iterations 3
```

**Expected terminal output:**

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

## Step 5: Run Unit Tests

```bash
python -m unittest discover -s tests -v
```

**Expected output:** All 9 tests pass (OK).

## Step 6: Trace a Specific Claim

```bash
proofsift trace --graph cases/demo_case/outputs/evidence_graph.sqlite --claim-id <claim-id>
```

Replace `<claim-id>` with an ID from the investigation report (e.g., `clm-xxx`).

## Step 7: Validate Submission Assets

```bash
proofsift validate-submission --root .
```

This checks that all required hackathon submission files are present.

## SIFT Workstation Setup (Optional)

If running on a SIFT Workstation Linux environment, use the automated installer:

```bash
chmod +x setup_sift.sh
./setup_sift.sh
```

This installs system dependencies, creates a Python virtual environment, installs ProofSIFT, and validates the submission.

## Demo Case Structure

```
cases/demo_case/
  case.json               Case configuration (C2 IPs, benign processes, keywords)
  ground_truth.json        Expected findings, forbidden confirmations, anomalies, drifts
  evidence/
    processes.csv          Process listings (pslist + psscan)
    netscan.csv            Network connections
    malfind.csv            Injected memory regions
    prefetch.csv           Prefetch execution artifacts
    amcache.csv            Amcache program inventory
    shimcache.csv          Shimcache/AppCompatCache
    autoruns.csv           Registry persistence
    mft.csv                MFT filesystem timeline
    usn.csv                USN journal
    evtx.csv               Windows Event Logs (4624, 4688, 7045)
    payload_notes.txt      Recovered IOC strings
```

## What the Agent Does Automatically

1. **Hashes all evidence** (SHA-256) and probes that writes to evidence are blocked
2. **Ingests memory artifacts** — process lists, hidden processes, network connections, injected memory
3. **Generates C2 hypotheses** — matches network connections against configured C2 IPs
4. **Validates MITRE ATT&CK sequence** — detects missing prerequisite tactics
5. **Runs disk investigation** — Prefetch, Amcache, Shimcache, autoruns, MFT, USN, EVTX, PowerShell logs, YARA keyword scan
6. **Normalizes clock drift** — discovers EVTX is +120s behind netscan via shared IP anchor
7. **Detects anti-forensics** — flags MFT timestomping on evil.exe
8. **Correlates cross-source** — upgrades claims with >=3 independent artifact kinds
9. **Applies negative controls** — verifies benign processes are not escalated
10. **Generates reports** — Markdown, HTML, trace index, execution log, accuracy report
