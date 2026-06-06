# Accuracy Report: proofsift-demo-001

## Summary

- Passed benchmark: `True`
- Precision: `1.0`
- Recall: `1.0`
- Confirmed claims: `2`
- Self-corrections: `31`
- Clock drifts: `1`
- Anti-forensics anomalies: `3`
- MITRE sequence recommendations: `2`
- Counterfactual checks: `8`
- Counterfactual denied escalations: `4`
- Bayesian scores: `15`
- BMC timeline contradictions: `3`
- MFT entropy anomalies: `1`
- Ephemeral MCP tool authorizations: `16 / 16`
- Z3 unsatisfiable proofs: `3`
- NetworkX graph metrics: `34`
- Collector capability checks: `2`
- Explainable provenance traces: `6`
- Generate-only remediation playbooks: `2`
- Merkle-DAG integrity ok: `True`
- Cryptographic root seal: `sha256:19bfc734783dc4ffa43f1cceeb3fe079e1388dde4ef9a372b9f37598878e5045`

## Expected Findings Matched

```json
[
  {
    "expected": {
      "contains": "evil.exe communicated with known C2 indicator 203.0.113.50",
      "why": "Memory network data, process data, prefetch, amcache, MFT, EVTX, USN, and keyword scan all corroborate the executable."
    },
    "claim_id": "clm-a3e20d29ed1a"
  },
  {
    "expected": {
      "contains": "evil.exe established user-level persistence",
      "why": "Autorun registry artifact points to the same evil.exe path corroborated by execution artifacts."
    },
    "claim_id": "clm-2d40f3d29d12"
  }
]
```

## Missed Expected Findings

```json
[]
```

## False Positives

```json
[]
```

## Hallucinated Confirmed Claims

```json
[]
```

## Missed Expected Anomalies

```json
[]
```

## Missed Expected Clock Drifts

```json
[]
```

## Evidence Integrity

ProofSIFT hashes evidence before analysis, writes only to the output directory, stores command provenance in SQLite, and records the spoliation probe in the execution log.
