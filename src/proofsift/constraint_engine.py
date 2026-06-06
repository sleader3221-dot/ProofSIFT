from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import PureWindowsPath
from typing import Any

import z3

from .audit import AuditLogger
from .graph import EvidenceGraph
from .models import BmcResult, Severity
from .time_utils import parse_utc


@dataclass(frozen=True)
class BmcThresholds:
    max_execution_before_mft_creation_seconds: int = 300
    max_usn_before_mft_creation_seconds: int = 300
    max_amcache_to_prefetch_inversion_seconds: int = 30


class TimelineConstraintEngine:
    """Use Z3 to prove whether observed Windows timeline facts are satisfiable."""

    def __init__(
        self,
        graph: EvidenceGraph,
        audit: AuditLogger,
        thresholds: BmcThresholds | None = None,
    ):
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
            created = parse_utc(mft["fields"].get("created_utc"))
            if not _looks_executable(path) or not created:
                continue
            executable = PureWindowsPath(path).name.lower()
            matching_prefetch = [
                row for row in prefetch_rows
                if executable in json.dumps(row["fields"]).lower()
            ]
            matching_amcache = [
                row for row in amcache_rows
                if executable in json.dumps(row["fields"]).lower()
            ]
            matching_usn = [
                row for row in usn_rows
                if _same_path(path, row["fields"].get("path", ""))
            ]

            for prefetch in matching_prefetch:
                last_run = parse_utc(prefetch["fields"].get("last_run_utc"))
                if last_run:
                    result = self._solve_pair(
                        check_name="mft_creation_must_not_postdate_prefetch_execution",
                        target=path,
                        left_name="mft_created",
                        left_time=created,
                        right_name="prefetch_last_run",
                        right_time=last_run,
                        tolerance=self.thresholds.max_execution_before_mft_creation_seconds,
                        relation="left_le_right_plus_tolerance",
                        evidence_ids=[mft["artifact_id"], prefetch["artifact_id"]],
                        contradiction=(
                            "Prefetch execution predates MFT creation beyond bounded OS "
                            "causality tolerance."
                        ),
                    )
                    if result:
                        results.append(result)

            for amcache in matching_amcache:
                first_run = parse_utc(amcache["fields"].get("first_run_utc"))
                if first_run:
                    result = self._solve_pair(
                        check_name="mft_creation_must_not_postdate_amcache_first_run",
                        target=path,
                        left_name="mft_created",
                        left_time=created,
                        right_name="amcache_first_run",
                        right_time=first_run,
                        tolerance=self.thresholds.max_execution_before_mft_creation_seconds,
                        relation="left_le_right_plus_tolerance",
                        evidence_ids=[mft["artifact_id"], amcache["artifact_id"]],
                        contradiction=(
                            "Amcache first-run observation predates MFT creation beyond "
                            "bounded OS causality tolerance."
                        ),
                    )
                    if result:
                        results.append(result)
                for prefetch in matching_prefetch:
                    last_run = parse_utc(prefetch["fields"].get("last_run_utc"))
                    if first_run and last_run:
                        result = self._solve_pair(
                            check_name=(
                                "prefetch_must_not_significantly_predate_amcache_first_run"
                            ),
                            target=path,
                            left_name="prefetch_last_run",
                            left_time=last_run,
                            right_name="amcache_first_run",
                            right_time=first_run,
                            tolerance=self.thresholds.max_amcache_to_prefetch_inversion_seconds,
                            relation="left_ge_right_minus_tolerance",
                            evidence_ids=[prefetch["artifact_id"], amcache["artifact_id"]],
                            contradiction=(
                                "Prefetch last-run materially predates Amcache first-run for "
                                "the same executable."
                            ),
                        )
                        if result:
                            results.append(result)

            for usn in matching_usn:
                usn_time = parse_utc(usn["fields"].get("time_utc"))
                if usn_time:
                    result = self._solve_pair(
                        check_name="usn_activity_must_not_predate_mft_creation",
                        target=path,
                        left_name="mft_created",
                        left_time=created,
                        right_name="usn_activity",
                        right_time=usn_time,
                        tolerance=self.thresholds.max_usn_before_mft_creation_seconds,
                        relation="left_le_right_plus_tolerance",
                        evidence_ids=[mft["artifact_id"], usn["artifact_id"]],
                        contradiction="USN record sequence violates causal time-density bounds.",
                    )
                    if result:
                        results.append(result)

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
                "z3_solver",
                "unsat.proven",
                {
                    "result_id": result_id,
                    "check_name": result.check_name,
                    "target": result.target,
                    "solver": result.details["solver"],
                    "solver_status": result.details["solver_status"],
                    "unsat_core": result.details["unsat_core"],
                    "contradiction": result.contradiction,
                },
            )
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
            self.audit.event(
                "z3_solver",
                "constraints.satisfied",
                {"result_count": 0, "solver": f"Z3 {z3.get_version_string()}"},
            )
        return stored

    def _solve_pair(
        self,
        *,
        check_name: str,
        target: str,
        left_name: str,
        left_time: datetime,
        right_name: str,
        right_time: datetime,
        tolerance: int,
        relation: str,
        evidence_ids: list[str],
        contradiction: str,
    ) -> BmcResult | None:
        left = z3.Int(left_name)
        right = z3.Int(right_name)
        solver = z3.Solver()
        solver.set(unsat_core=True)
        solver.assert_and_track(left == int(left_time.timestamp()), f"observed_{left_name}")
        solver.assert_and_track(right == int(right_time.timestamp()), f"observed_{right_name}")
        if relation == "left_le_right_plus_tolerance":
            causal = left <= right + tolerance
            constraint_text = f"{left_name} <= {right_name} + {tolerance}"
        elif relation == "left_ge_right_minus_tolerance":
            causal = left >= right - tolerance
            constraint_text = f"{left_name} >= {right_name} - {tolerance}"
        else:
            raise ValueError(f"unknown temporal relation: {relation}")
        solver.assert_and_track(causal, f"causal_{check_name}")
        smt2 = solver.to_smt2()
        status = solver.check()
        if status != z3.unsat:
            return None
        return BmcResult(
            check_name=check_name,
            status="CONTRADICTION",
            severity=Severity.CRITICAL,
            target=target,
            timeline_validity=0.0,
            evidence_ids=evidence_ids,
            contradiction=contradiction,
            details={
                "solver": f"Z3 {z3.get_version_string()}",
                "solver_status": str(status),
                "unsat_core": [str(item) for item in solver.unsat_core()],
                "constraint": constraint_text,
                "left_observed_utc": left_time.isoformat(),
                "right_observed_utc": right_time.isoformat(),
                "tolerance_seconds": tolerance,
                "smt2": smt2,
            },
        )

    def _artifacts(self, kind: str) -> list[dict[str, Any]]:
        return [
            {**dict(row), "fields": json.loads(row["fields_json"])}
            for row in self.graph.artifacts(kind)
        ]


def _looks_executable(path: str) -> bool:
    return path.lower().endswith((".exe", ".dll", ".sys", ".scr", ".bat", ".cmd", ".ps1"))


def _same_path(left: str, right: str) -> bool:
    return left.strip().lower().replace("/", "\\") == right.strip().lower().replace("/", "\\")
