# Accuracy Report: proofsift-demo-001

## Summary

- Passed benchmark: `True`
- Precision: `1.0`
- Recall: `1.0`
- Confirmed claims: `2`
- Self-corrections: `14`
- Clock drifts: `1`
- Anti-forensics anomalies: `2`
- MITRE sequence recommendations: `2`

## Expected Findings Matched

```json
[
  {
    "expected": {
      "contains": "evil.exe communicated with known C2 indicator 203.0.113.50",
      "why": "Memory network data, process data, prefetch, amcache, MFT, EVTX, USN, and keyword scan all corroborate the executable."
    },
    "claim_id": "clm-7ea4cb0a9b8e"
  },
  {
    "expected": {
      "contains": "evil.exe established user-level persistence",
      "why": "Autorun registry artifact points to the same evil.exe path corroborated by execution artifacts."
    },
    "claim_id": "clm-6e22d0d90e54"
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
