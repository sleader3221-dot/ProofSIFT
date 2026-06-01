# Demo Video Script

Target length: under five minutes.

## 0:00 - 0:30 Opening

Show the terminal and say:

> This is ProofSIFT, a self-correcting DFIR agent for SANS SIFT. It does not confirm findings unless it can prove them with traceable artifact evidence.

## 0:30 - 1:15 Run The Agent

```bash
python -m pip install -e .
proofsift run --case cases/demo_case/case.json --max-iterations 3
```

Call out:

- Evidence is hashed.
- Evidence write probe is blocked.
- Memory and network triage runs first.

## 1:15 - 2:15 Show Self-Correction

Open `cases/demo_case/outputs/report.md`.

Point out:

- The agent initially sees C2-looking network activity.
- It downgrades weak claims when disk evidence is missing.
- It reruns disk, registry, timeline, event-log, and IOC scans.
- It upgrades `evil.exe` only after corroboration.

## 2:15 - 3:15 Trace A Finding

```bash
proofsift trace --graph cases/demo_case/outputs/evidence_graph.sqlite --claim-id <confirmed-claim-id>
```

Show that the claim links to process, network, prefetch, amcache, MFT, EVTX, USN, and keyword evidence.

## 3:15 - 4:15 Benchmark

```bash
proofsift benchmark --case cases/demo_case/case.json --ground-truth cases/demo_case/ground_truth.json
```

Show:

- Precision.
- Recall.
- False positives.
- Hallucinated confirmed claims.

## 4:15 - 5:00 Close

Say:

> The core idea is evidence discipline at machine speed. ProofSIFT catches its own weak claims, preserves provenance, and gives judges a traceable audit trail for every finding.

