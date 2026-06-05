from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import PureWindowsPath
from typing import Any

from .audit import AuditLogger
from .graph import EvidenceGraph
from .models import BmcResult, Severity
from .time_utils import parse_utc, seconds_between


@dataclass(frozen=True)
class BmcThresholds:
    max_execution_before_mft_creation_seconds: int = 300
    max_usn_before_mft_creation_seconds: int = 300
    max_amcache_to_prefetch_inversion_seconds: int = 30


class TimelineConstraintEngine:
    """Bounded model checker for Windows timeline causality constraints.

    ProofSIFT models a bounded sequence of OS observations and checks that the
    satisfiability set is non-empty. A contradiction does not erase the
    compromise finding; it proves the specific metadata timeline is physically
    invalid and should be treated as anti-forensics.
    """

    def __init__(self, graph: EvidenceGraph, audit: AuditLogger, thresholds: BmcThresholds | None = None):
        self.graph = graph
        self.audit = audit
        self.thresholds = thresholds or BmcThresholds()

    def verify(self) -> list[BmcResult]:
        results: list[BmcResult] = []
        mft_rows = self._artifacts("mft")
        prefetch_rows = self._artifacts("prefetch")
        amcache_rows = self._artifacts("amcache")
        usn_rows = self._artifacts("usn")

        for mft in mft_rows:
            path = mft["fields"].get("path", "")
            if not _looks_executable(path):
                continue
            executable = PureWindowsPath(path).name.lower()
            created = parse_utc(mft["fields"].get("created_utc"))
            if not created:
                continue
            matching_prefetch = [row for row in prefetch_rows if executable in json.dumps(row["fields"]).lower()]
            matching_amcache = [row for row in amcache_rows if executable in json.dumps(row["fields"]).lower()]
            matching_usn = [row for row in usn_rows if _same_path(path, row["fields"].get("path", ""))]

            for prefetch in matching_prefetch:
                last_run = parse_utc(prefetch["fields"].get("last_run_utc"))
                if last_run and seconds_between(created, last_run) > self.thresholds.max_execution_before_mft_creation_seconds:
                    results.append(
                        self._contradiction(
                            check_name="mft_creation_must_not_postdate_prefetch_execution",
                            target=path,
                            evidence_ids=[mft["artifact_id"], prefetch["artifact_id"]],
                            contradiction="Prefetch execution predates MFT creation beyond bounded OS causality tolerance.",
                            details={
                                "mft_created_utc": mft["fields"].get("created_utc"),
                                "prefetch_last_run_utc": prefetch["fields"].get("last_run_utc"),
                                "constraint": "created_utc <= prefetch.last_run_utc + tolerance",
                                "satisfiability": "empty",
                            },
                        )
                    )

            for amcache in matching_amcache:
                first_run = parse_utc(amcache["fields"].get("first_run_utc"))
                if first_run and seconds_between(created, first_run) > self.thresholds.max_execution_before_mft_creation_seconds:
                    results.append(
                        self._contradiction(
                            check_name="mft_creation_must_not_postdate_amcache_first_run",
                            target=path,
                            evidence_ids=[mft["artifact_id"], amcache["artifact_id"]],
                            contradiction="Amcache first-run observation predates MFT creation beyond bounded OS causality tolerance.",
                            details={
                                "mft_created_utc": mft["fields"].get("created_utc"),
                                "amcache_first_run_utc": amcache["fields"].get("first_run_utc"),
                                "constraint": "created_utc <= amcache.first_run_utc + tolerance",
                                "satisfiability": "empty",
                            },
                        )
                    )
                for prefetch in matching_prefetch:
                    last_run = parse_utc(prefetch["fields"].get("last_run_utc"))
                    if first_run and last_run and seconds_between(first_run, last_run) < -self.thresholds.max_amcache_to_prefetch_inversion_seconds:
                        results.append(
                            self._contradiction(
                                check_name="prefetch_must_not_significantly_predate_amcache_first_run",
                                target=path,
                                evidence_ids=[prefetch["artifact_id"], amcache["artifact_id"]],
                                contradiction="Prefetch last-run materially predates Amcache first-run for the same executable.",
                                details={
                                    "prefetch_last_run_utc": prefetch["fields"].get("last_run_utc"),
                                    "amcache_first_run_utc": amcache["fields"].get("first_run_utc"),
                                    "constraint": "prefetch.last_run_utc >= amcache.first_run_utc - tolerance",
                                    "satisfiability": "empty",
                                },
                            )
                        )

            for usn in matching_usn:
                usn_time = parse_utc(usn["fields"].get("time_utc"))
                if usn_time and seconds_between(created, usn_time) > self.thresholds.max_usn_before_mft_creation_seconds:
                    results.append(
                        self._contradiction(
                            check_name="usn_activity_must_not_predate_mft_creation",
                            target=path,
                            evidence_ids=[mft["artifact_id"], usn["artifact_id"]],
                            contradiction="USN record sequence violates causal time-density bounds.",
                            details={
                                "mft_created_utc": mft["fields"].get("created_utc"),
                                "usn_time_utc": usn["fields"].get("time_utc"),
                                "usn_reason": usn["fields"].get("reason"),
                                "constraint": "created_utc <= usn.time_utc + tolerance",
                                "satisfiability": "empty",
                            },
                        )
                    )

        stored: list[BmcResult] = []
        seen: set[tuple[str, str]] = set()
        for result in results:
            key = (result.check_name, result.target.lower())
            if key in seen:
                continue
            seen.add(key)
            result_id = self.graph.add_bmc_result(result)
            stored.append(result)
            self.audit.event(
                "bmc_solver",
                "contradiction.detected",
                {
                    "result_id": result_id,
                    "check_name": result.check_name,
                    "target": result.target,
                    "timeline_validity": result.timeline_validity,
                    "contradiction": result.contradiction,
                    "details": result.details,
                },
            )
        if not stored:
            self.audit.event("bmc_solver", "constraints.satisfied", {"result_count": 0})
        return stored

    def _artifacts(self, kind: str) -> list[dict[str, Any]]:
        return [{**dict(row), "fields": json.loads(row["fields_json"])} for row in self.graph.artifacts(kind)]

    @staticmethod
    def _contradiction(
        check_name: str,
        target: str,
        evidence_ids: list[str],
        contradiction: str,
        details: dict[str, Any],
    ) -> BmcResult:
        return BmcResult(
            check_name=check_name,
            status="CONTRADICTION",
            severity=Severity.CRITICAL,
            target=target,
            timeline_validity=0.0,
            evidence_ids=evidence_ids,
            contradiction=contradiction,
            details=details,
        )


def _looks_executable(path: str) -> bool:
    return path.lower().endswith((".exe", ".dll", ".sys", ".scr", ".bat", ".cmd", ".ps1"))


def _same_path(left: str, right: str) -> bool:
    return left.strip().lower().replace("/", "\\") == right.strip().lower().replace("/", "\\")
