# Accuracy Report

This template is replaced by `proofsift benchmark` for a specific run.

## Required Command

```bash
proofsift benchmark --case cases/demo_case/case.json --ground-truth cases/demo_case/ground_truth.json
```

## What Is Measured

- Expected confirmed findings matched.
- Expected findings missed.
- Forbidden confirmed findings.
- Confirmed claims with no linked evidence.
- Self-corrections recorded.
- Precision and recall.
- Clock-drift detection.
- Anti-forensics anomaly detection.
- MITRE sequence recommendation generation.

## Evidence Integrity Test

ProofSIFT records a `spoliation_probe` tool result. The probe attempts to validate a write path inside the evidence root. The correct result is rejection by `SafePathPolicy`.

## Honesty Policy

If a claim is supported by only one evidence family, ProofSIFT should mark it `INFERRED` or `POSSIBLE`, not `CONFIRMED`.
