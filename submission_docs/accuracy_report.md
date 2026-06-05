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
- Merkle-DAG integrity ok: `True`
- Cryptographic root seal: `sha256:3ac7d3e11efd441a3cb96b1e0b3e77ff07cacba5fceb332d30aff087fdaf172e`

## Expected Findings Matched

```json
[
  {
    "expected": {
      "contains": "evil.exe communicated with known C2 indicator 203.0.113.50",
      "why": "Memory network data, process data, prefetch, amcache, MFT, EVTX, USN, and keyword scan all corroborate the executable."
    },
    "claim_id": "clm-65ec35afbefb"
  },
  {
    "expected": {
      "contains": "evil.exe established user-level persistence",
      "why": "Autorun registry artifact points to the same evil.exe path corroborated by execution artifacts."
    },
    "claim_id": "clm-7034870b772f"
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
