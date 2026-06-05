from __future__ import annotations

import json
import math
from pathlib import PureWindowsPath
from typing import Any

from .audit import AuditLogger
from .graph import EvidenceGraph
from .models import EntropyAnalysis, Severity
from .time_utils import parse_utc, seconds_between


class MftEntropyAnalyzer:
    """Structural MFT sequence and timestamp entropy analyzer."""

    def __init__(self, graph: EvidenceGraph, audit: AuditLogger):
        self.graph = graph
        self.audit = audit

    def analyze(self) -> list[EntropyAnalysis]:
        mft = sorted(self._artifacts("mft"), key=lambda item: _entry_number(item["fields"]))
        prefetch = self._artifacts("prefetch")
        amcache = self._artifacts("amcache")
        usn = self._artifacts("usn")
        analyses: list[EntropyAnalysis] = []
        if len(mft) < 2:
            self.audit.event("mft_entropy", "insufficient_baseline", {"mft_records": len(mft)})
            return []

        for index, artifact in enumerate(mft):
            path = artifact["fields"].get("path", "")
            if not _looks_executable(path):
                continue
            neighbor = mft[index - 1] if index > 0 else mft[index + 1]
            entry_gap = abs(_entry_number(artifact["fields"]) - _entry_number(neighbor["fields"])) or 1
            created = parse_utc(artifact["fields"].get("created_utc"))
            neighbor_created = parse_utc(neighbor["fields"].get("created_utc"))
            if not created or not neighbor_created:
                continue

            baseline_seconds_per_record = abs(seconds_between(created, neighbor_created)) / entry_gap
            executable = PureWindowsPath(path).name.lower()
            execution_times = _execution_times(executable, prefetch, amcache)
            usn_times = [
                parse_utc(row["fields"].get("time_utc"))
                for row in usn
                if _same_path(path, row["fields"].get("path", ""))
            ]
            execution_deltas = [abs(seconds_between(created, ts)) for ts in execution_times if ts]
            usn_deltas = [abs(seconds_between(created, ts)) for ts in usn_times if ts]
            target_delta = max([0.0, *execution_deltas, *usn_deltas]) / entry_gap
            components = [
                max(baseline_seconds_per_record, 0.001),
                max(target_delta, 0.001),
                max(float(entry_gap), 0.001),
            ]
            entropy_bits = _entropy_bits(components)
            contradiction_signals = []
            if execution_deltas and max(execution_deltas) > 300:
                contradiction_signals.append("execution_timestamp_diverges_from_mft_creation")
            if usn_deltas and max(usn_deltas) > 300:
                contradiction_signals.append("usn_activity_diverges_from_mft_creation")
            if target_delta > max(5.0, baseline_seconds_per_record * 0.75):
                contradiction_signals.append("high_temporal_density_delta")
            verdict = "ANOMALOUS_MALICIOUS_TIMESTOMPING" if contradiction_signals else "VALIDATED_BASELINE"
            severity = Severity.HIGH if contradiction_signals else Severity.INFO
            analysis = EntropyAnalysis(
                target_path=path,
                verdict=verdict,
                severity=severity,
                entropy_bits=round(entropy_bits, 4),
                baseline_delta_seconds_per_record=round(baseline_seconds_per_record, 4),
                target_delta_seconds_per_record=round(target_delta, 4),
                evidence_ids=sorted(
                    {
                        artifact["artifact_id"],
                        neighbor["artifact_id"],
                        *[
                            row["artifact_id"]
                            for row in [*prefetch, *amcache, *usn]
                            if executable in json.dumps(row["fields"]).lower()
                            or _same_path(path, row["fields"].get("path", ""))
                        ],
                    }
                ),
                details={
                    "mft_entry": artifact["fields"].get("entry"),
                    "neighbor_entry": neighbor["fields"].get("entry"),
                    "signals": contradiction_signals,
                    "mft_created_utc": artifact["fields"].get("created_utc"),
                    "linear_record_gap": entry_gap,
                    "interpretation": (
                        "MFT record-number progression and timestamp deltas form a high-entropy "
                        "metadata alignment spike consistent with timestomping."
                        if contradiction_signals
                        else "MFT record-number progression and timestamps fit the local baseline."
                    ),
                },
            )
            analysis_id = self.graph.add_entropy_analysis(analysis)
            analyses.append(analysis)
            self.audit.event(
                "mft_entropy",
                "analysis.completed",
                {
                    "analysis_id": analysis_id,
                    "target_path": analysis.target_path,
                    "verdict": analysis.verdict,
                    "entropy_bits": analysis.entropy_bits,
                    "baseline_delta_seconds_per_record": analysis.baseline_delta_seconds_per_record,
                    "target_delta_seconds_per_record": analysis.target_delta_seconds_per_record,
                    "signals": contradiction_signals,
                },
            )
        return analyses

    def _artifacts(self, kind: str) -> list[dict[str, Any]]:
        return [{**dict(row), "fields": json.loads(row["fields_json"])} for row in self.graph.artifacts(kind)]


def _entry_number(fields: dict[str, Any]) -> int:
    try:
        return int(fields.get("entry", 0))
    except (TypeError, ValueError):
        return 0


def _execution_times(executable: str, prefetch: list[dict[str, Any]], amcache: list[dict[str, Any]]) -> list[Any]:
    times = []
    for artifact in [*prefetch, *amcache]:
        row_text = json.dumps(artifact["fields"]).lower()
        if executable not in row_text:
            continue
        for field in ("last_run_utc", "first_run_utc"):
            parsed = parse_utc(artifact["fields"].get(field))
            if parsed:
                times.append(parsed)
    return times


def _entropy_bits(values: list[float]) -> float:
    total = sum(values)
    if total <= 0:
        return 0.0
    entropy = 0.0
    for value in values:
        probability = value / total
        entropy -= probability * math.log2(probability)
    return entropy


def _looks_executable(path: str) -> bool:
    return path.lower().endswith((".exe", ".dll", ".sys", ".scr", ".bat", ".cmd", ".ps1"))


def _same_path(left: str, right: str) -> bool:
    return left.strip().lower().replace("/", "\\") == right.strip().lower().replace("/", "\\")
