from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from .audit import AuditLogger
from .graph import EvidenceGraph
from .models import ClockDrift
from .time_utils import parse_utc, seconds_between


@dataclass(frozen=True)
class DriftSearchBoundary:
    source: str
    timestamp_field: str | None = None
    kind: str | None = None


class ClockDriftNormalizer:
    """Discover and apply source-level timestamp drift using shared anchors."""

    def __init__(self, graph: EvidenceGraph, audit: AuditLogger):
        self.graph = graph
        self.audit = audit

    def discover_and_apply(
        self,
        reference: DriftSearchBoundary,
        candidate: DriftSearchBoundary,
        max_abs_delta_seconds: int = 900,
    ) -> ClockDrift | None:
        anchor = self._find_anchor(reference, candidate)
        if not anchor:
            self.audit.event(
                "clock_drift",
                "anchor.not_found",
                {"reference": reference.__dict__, "candidate": candidate.__dict__},
            )
            return None
        reference_time = parse_utc(anchor["reference"]["normalized_utc"])
        candidate_time = parse_utc(anchor["candidate"]["normalized_utc"])
        if not reference_time or not candidate_time:
            return None
        delta_seconds = seconds_between(reference_time, candidate_time)
        if abs(delta_seconds) > max_abs_delta_seconds:
            self.audit.event(
                "clock_drift",
                "anchor.rejected",
                {
                    "reason": "delta exceeds bound",
                    "delta_seconds": delta_seconds,
                    "max_abs_delta_seconds": max_abs_delta_seconds,
                    "reference_observation_id": anchor["reference"]["observation_id"],
                    "candidate_observation_id": anchor["candidate"]["observation_id"],
                },
            )
            return None
        drift = ClockDrift(
            source=candidate.source,
            reference_source=reference.source,
            delta_seconds=delta_seconds,
            anchor_observation_id=anchor["candidate"]["observation_id"],
            reference_observation_id=anchor["reference"]["observation_id"],
            confidence=anchor["confidence"],
            reason=anchor["reason"],
        )
        drift_id = self.graph.add_clock_drift(drift)
        updated = self.graph.apply_clock_drift(candidate.source, delta_seconds)
        self.audit.event(
            "clock_drift",
            "drift.applied",
            {
                "drift_id": drift_id,
                "source": drift.source,
                "reference_source": drift.reference_source,
                "delta_seconds": delta_seconds,
                "updated_observations": updated,
                "reason": drift.reason,
            },
        )
        return drift

    def _find_anchor(
        self,
        reference: DriftSearchBoundary,
        candidate: DriftSearchBoundary,
    ) -> dict[str, Any] | None:
        reference_rows = [dict(row) for row in self.graph.observations(reference.source)]
        candidate_rows = [dict(row) for row in self.graph.observations(candidate.source)]
        reference_artifacts = self._artifact_map(reference_rows)
        candidate_artifacts = self._artifact_map(candidate_rows)
        for ref in reference_rows:
            if not self._matches_boundary(ref, reference):
                continue
            ref_artifact = reference_artifacts.get(ref["artifact_id"], {})
            ref_fields = ref_artifact.get("fields", {})
            remote_ip = ref_fields.get("remote_ip")
            process = (ref_fields.get("process") or ref_fields.get("name") or "").lower()
            for cand in candidate_rows:
                if not self._matches_boundary(cand, candidate):
                    continue
                cand_artifact = candidate_artifacts.get(cand["artifact_id"], {})
                cand_fields = cand_artifact.get("fields", {})
                message = json.dumps(cand_fields).lower()
                event_id = str(cand_fields.get("event_id", ""))
                if remote_ip and remote_ip in message:
                    return {
                        "reference": ref,
                        "candidate": cand,
                        "confidence": 0.92 if event_id == "4624" else 0.82,
                        "reason": f"shared anchor matched remote IP {remote_ip} across {reference.source} and {candidate.source}",
                    }
                if process and process in message and event_id in {"4688", "1"}:
                    return {
                        "reference": ref,
                        "candidate": cand,
                        "confidence": 0.78,
                        "reason": f"shared anchor matched process {process} across {reference.source} and {candidate.source}",
                    }
        return None

    def _artifact_map(self, observations: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
        artifact_ids = sorted({row["artifact_id"] for row in observations})
        if not artifact_ids:
            return {}
        placeholders = ",".join("?" for _ in artifact_ids)
        rows = self.graph.conn.execute(
            f"select * from artifacts where artifact_id in ({placeholders})",
            artifact_ids,
        ).fetchall()
        return {
            row["artifact_id"]: {**dict(row), "fields": json.loads(row["fields_json"])}
            for row in rows
        }

    @staticmethod
    def _matches_boundary(row: dict[str, Any], boundary: DriftSearchBoundary) -> bool:
        if boundary.timestamp_field and row["timestamp_field"] != boundary.timestamp_field:
            return False
        if boundary.kind and row["kind"] != boundary.kind:
            return False
        return True

