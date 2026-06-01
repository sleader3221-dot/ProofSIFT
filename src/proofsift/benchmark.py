from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .agent import SelfCorrectingInvestigator, load_case_config


def run_benchmark(case_path: Path, ground_truth_path: Path, output_dir: Path | None = None, max_iterations: int | None = None) -> dict[str, Any]:
    config = load_case_config(case_path, output_override=output_dir, max_iterations=max_iterations)
    result = SelfCorrectingInvestigator(config).run()
    truth = json.loads(ground_truth_path.read_text(encoding="utf-8"))
    claims = result["claims"]
    confirmed = [claim for claim in claims if claim["status"] == "CONFIRMED"]
    expected = truth.get("expected_confirmed", [])
    forbidden = truth.get("forbidden_confirmed", [])
    expected_anomalies = truth.get("expected_anomalies", [])
    expected_clock_drifts = truth.get("expected_clock_drifts", [])
    matched_expected = []
    missed_expected = []
    for item in expected:
        needle = item["contains"].lower()
        match = next((claim for claim in confirmed if needle in claim["statement"].lower()), None)
        if match:
            matched_expected.append({"expected": item, "claim_id": match["claim_id"]})
        else:
            missed_expected.append(item)
    false_positives = []
    for item in forbidden:
        needle = item["contains"].lower()
        for claim in confirmed:
            if needle in claim["statement"].lower():
                false_positives.append({"forbidden": item, "claim_id": claim["claim_id"], "statement": claim["statement"]})
    hallucinated = [claim for claim in confirmed if _claim_evidence_count(config.output_dir, claim["claim_id"]) == 0]
    detected_anomalies = result.get("anomalies", [])
    detected_drifts = result.get("clock_drifts", [])
    missed_anomalies = _missed_expected_records(expected_anomalies, detected_anomalies)
    missed_clock_drifts = _missed_expected_records(expected_clock_drifts, detected_drifts)
    score = {
        "case_id": config.case_id,
        "confirmed_claims": len(confirmed),
        "expected_confirmed": len(expected),
        "matched_expected": matched_expected,
        "missed_expected": missed_expected,
        "false_positives": false_positives,
        "hallucinated_confirmed_claims": hallucinated,
        "self_corrections": len(result["corrections"]),
        "clock_drifts": len(detected_drifts),
        "anti_forensics_anomalies": len(detected_anomalies),
        "sequence_recommendations": len(result.get("sequence_recommendations", [])),
        "missed_expected_anomalies": missed_anomalies,
        "missed_expected_clock_drifts": missed_clock_drifts,
        "precision": _safe_div(len(matched_expected), len(matched_expected) + len(false_positives)),
        "recall": _safe_div(len(matched_expected), len(expected)),
        "passed": not missed_expected and not false_positives and not hallucinated and not missed_anomalies and not missed_clock_drifts,
    }
    output = Path(config.output_dir)
    (output / "benchmark.json").write_text(json.dumps(score, indent=2, sort_keys=True), encoding="utf-8")
    (output / "accuracy_report.md").write_text(_accuracy_markdown(score), encoding="utf-8")
    return score


def _claim_evidence_count(output_dir: str, claim_id: str) -> int:
    trace_path = Path(output_dir) / "trace_index.json"
    if not trace_path.exists():
        return 0
    trace = json.loads(trace_path.read_text(encoding="utf-8"))
    return len(trace.get(claim_id, {}).get("evidence", []))


def _safe_div(numerator: int, denominator: int) -> float:
    if denominator == 0:
        return 1.0
    return round(numerator / denominator, 4)


def _missed_expected_records(
    expected: list[dict[str, Any]],
    detected: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    missed = []
    haystack = "\n".join(json.dumps(item, sort_keys=True).lower() for item in detected)
    for item in expected:
        needle = item.get("contains", "").lower()
        if needle and needle not in haystack:
            missed.append(item)
    return missed


def _accuracy_markdown(score: dict[str, Any]) -> str:
    return f"""# Accuracy Report: {score['case_id']}

## Summary

- Passed benchmark: `{score['passed']}`
- Precision: `{score['precision']}`
- Recall: `{score['recall']}`
- Confirmed claims: `{score['confirmed_claims']}`
- Self-corrections: `{score['self_corrections']}`
- Clock drifts: `{score['clock_drifts']}`
- Anti-forensics anomalies: `{score['anti_forensics_anomalies']}`
- MITRE sequence recommendations: `{score['sequence_recommendations']}`

## Expected Findings Matched

```json
{json.dumps(score['matched_expected'], indent=2)}
```

## Missed Expected Findings

```json
{json.dumps(score['missed_expected'], indent=2)}
```

## False Positives

```json
{json.dumps(score['false_positives'], indent=2)}
```

## Hallucinated Confirmed Claims

```json
{json.dumps(score['hallucinated_confirmed_claims'], indent=2)}
```

## Missed Expected Anomalies

```json
{json.dumps(score['missed_expected_anomalies'], indent=2)}
```

## Missed Expected Clock Drifts

```json
{json.dumps(score['missed_expected_clock_drifts'], indent=2)}
```

## Evidence Integrity

ProofSIFT hashes evidence before analysis, writes only to the output directory, stores command provenance in SQLite, and records the spoliation probe in the execution log.
"""
