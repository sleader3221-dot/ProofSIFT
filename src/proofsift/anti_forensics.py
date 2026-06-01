from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import PureWindowsPath
from typing import Any

from .audit import AuditLogger
from .graph import EvidenceGraph
from .models import AntiForensicsAnomaly, Severity
from .time_utils import parse_utc, seconds_between


@dataclass(frozen=True)
class AntiForensicsThresholds:
    max_creation_to_execution_skew_seconds: int = 300
    max_mft_to_usn_skew_seconds: int = 300


class AntiForensicsDetector:
    """Differential timestomping detector across MFT, USN, and Prefetch."""

    def __init__(self, graph: EvidenceGraph, audit: AuditLogger, thresholds: AntiForensicsThresholds | None = None):
        self.graph = graph
        self.audit = audit
        self.thresholds = thresholds or AntiForensicsThresholds()

    def detect(self) -> list[AntiForensicsAnomaly]:
        mft = self._artifacts("mft")
        usn = self._artifacts("usn")
        prefetch = self._artifacts("prefetch")
        anomalies: list[AntiForensicsAnomaly] = []
        for mft_artifact in mft:
            path = mft_artifact["fields"].get("path", "")
            if not _looks_executable(path):
                continue
            executable = PureWindowsPath(path).name.lower()
            mft_created = parse_utc(mft_artifact["fields"].get("created_utc"))
            mft_modified = parse_utc(mft_artifact["fields"].get("modified_utc"))
            if not mft_created:
                continue
            matching_prefetch = [
                artifact for artifact in prefetch
                if executable in json.dumps(artifact["fields"]).lower()
            ]
            matching_usn = [
                artifact for artifact in usn
                if path.lower() in json.dumps(artifact["fields"]).lower()
            ]
            for pf in matching_prefetch:
                execution_time = parse_utc(pf["fields"].get("last_run_utc") or pf["fields"].get("first_run_utc"))
                if not execution_time:
                    continue
                skew = seconds_between(mft_created, execution_time)
                if skew > self.thresholds.max_creation_to_execution_skew_seconds:
                    anomalies.append(
                        AntiForensicsAnomaly(
                            target_path=path,
                            anomaly_type="mft_creation_postdates_prefetch_execution",
                            confidence_multiplier=1.12,
                            severity=Severity.HIGH,
                            evidence_ids=[mft_artifact["artifact_id"], pf["artifact_id"]],
                            details={
                                "mft_created_utc": mft_artifact["fields"].get("created_utc"),
                                "prefetch_execution_utc": pf["fields"].get("last_run_utc"),
                                "skew_seconds": skew,
                                "interpretation": "MFT creation time occurs after observed execution, consistent with timestomping or metadata manipulation.",
                            },
                        )
                    )
            if mft_modified and mft_created > mft_modified:
                anomalies.append(
                    AntiForensicsAnomaly(
                        target_path=path,
                        anomaly_type="mft_created_after_modified",
                        confidence_multiplier=1.08,
                        severity=Severity.MEDIUM,
                        evidence_ids=[mft_artifact["artifact_id"]],
                        details={
                            "mft_created_utc": mft_artifact["fields"].get("created_utc"),
                            "mft_modified_utc": mft_artifact["fields"].get("modified_utc"),
                            "interpretation": "Creation timestamp occurs after modification timestamp.",
                        },
                    )
                )
            for usn_artifact in matching_usn:
                usn_time = parse_utc(usn_artifact["fields"].get("time_utc"))
                if not usn_time:
                    continue
                skew = seconds_between(mft_created, usn_time)
                if skew > self.thresholds.max_mft_to_usn_skew_seconds:
                    anomalies.append(
                        AntiForensicsAnomaly(
                            target_path=path,
                            anomaly_type="mft_creation_postdates_usn_activity",
                            confidence_multiplier=1.10,
                            severity=Severity.HIGH,
                            evidence_ids=[mft_artifact["artifact_id"], usn_artifact["artifact_id"]],
                            details={
                                "mft_created_utc": mft_artifact["fields"].get("created_utc"),
                                "usn_time_utc": usn_artifact["fields"].get("time_utc"),
                                "skew_seconds": skew,
                                "interpretation": "USN activity predates MFT creation metadata for the same executable.",
                            },
                        )
                    )
        stored: list[AntiForensicsAnomaly] = []
        seen: set[tuple[str, str]] = set()
        for anomaly in anomalies:
            key = (anomaly.target_path.lower(), anomaly.anomaly_type)
            if key in seen:
                continue
            seen.add(key)
            anomaly_id = self.graph.add_anomaly(anomaly)
            stored.append(anomaly)
            self.audit.event(
                "anti_forensics",
                "anomaly.detected",
                {
                    "anomaly_id": anomaly_id,
                    "target_path": anomaly.target_path,
                    "anomaly_type": anomaly.anomaly_type,
                    "confidence_multiplier": anomaly.confidence_multiplier,
                    "evidence_ids": anomaly.evidence_ids,
                    "details": anomaly.details,
                },
            )
        return stored

    def _artifacts(self, kind: str) -> list[dict[str, Any]]:
        rows = self.graph.artifacts(kind)
        return [{**dict(row), "fields": json.loads(row["fields_json"])} for row in rows]


def _looks_executable(path: str) -> bool:
    lowered = path.lower()
    return lowered.endswith((".exe", ".dll", ".sys", ".scr", ".bat", ".cmd", ".ps1"))

