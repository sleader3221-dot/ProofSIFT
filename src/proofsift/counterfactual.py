from __future__ import annotations

import json
from typing import Any

from .audit import AuditLogger
from .graph import EvidenceGraph
from .models import ClaimStatus, CounterfactualCheck


EXECUTION_ARTIFACTS = {
    "prefetch": "Prefetch execution cache",
    "amcache": "Amcache program inventory",
    "shimcache": "Shimcache/AppCompatCache entry",
    "process_creation": "Security.evtx Event ID 4688",
}
PERSISTENCE_ARTIFACTS = {
    "autorun": "Registry autorun entry",
}
TIMELINE_ARTIFACTS = {
    "mft": "$MFT timeline entry",
    "usn": "$UsnJrnl file transition",
}


class CounterfactualFalsifier:
    """Active negative-evidence checks for claims that imply OS mechanics."""

    def __init__(self, graph: EvidenceGraph, audit: AuditLogger):
        self.graph = graph
        self.audit = audit

    def evaluate(self) -> list[CounterfactualCheck]:
        checks: list[CounterfactualCheck] = []
        for row in self.graph.claims():
            evidence_ids = self._claim_evidence(row["claim_id"])
            evidence_kinds = self._evidence_kinds(evidence_ids)
            statement = row["statement"].lower()
            if "known c2 indicator" in statement:
                checks.append(
                    self._build_check(
                        row,
                        hypothesis="command_and_control_requires_execution_cache_and_timeline_alibi",
                        evidence_kinds=evidence_kinds,
                        required={**EXECUTION_ARTIFACTS, **TIMELINE_ARTIFACTS},
                        require_any_groups=[EXECUTION_ARTIFACTS, TIMELINE_ARTIFACTS],
                    )
                )
            if "persistence" in statement or "autorun" in statement:
                checks.append(
                    self._build_check(
                        row,
                        hypothesis="registry_persistence_requires_prior_execution_alibi",
                        evidence_kinds=evidence_kinds,
                        required={**PERSISTENCE_ARTIFACTS, **EXECUTION_ARTIFACTS},
                        require_any_groups=[PERSISTENCE_ARTIFACTS, EXECUTION_ARTIFACTS],
                    )
                )
            if "credential" in statement:
                checks.append(
                    self._build_check(
                        row,
                        hypothesis="credential_access_requires_execution_alibi",
                        evidence_kinds=evidence_kinds,
                        required=EXECUTION_ARTIFACTS,
                        require_any_groups=[EXECUTION_ARTIFACTS],
                    )
                )

        recorded: list[CounterfactualCheck] = []
        for check in checks:
            check_id = self.graph.add_counterfactual_check(check)
            self.audit.event(
                "counterfactual",
                "check.completed" if check.status == "PASS" else "failure.denied_escalation",
                {
                    "check_id": check_id,
                    "claim_id": check.claim_id,
                    "hypothesis": check.hypothesis,
                    "status": check.status,
                    "required_artifacts": check.required_artifacts,
                    "present_artifacts": check.present_artifacts,
                    "missing_artifacts": check.missing_artifacts,
                    "action": check.action,
                    "terminal_message": self.terminal_message(check) if check.status == "FAIL" else "",
                },
            )
            recorded.append(check)
        return recorded

    @staticmethod
    def terminal_message(check: CounterfactualCheck) -> str:
        missing = ", ".join(check.missing_artifacts)
        return f"[COUNTERFACTUAL FAILURE] Denied escalation - Expected execution artifact in {missing} missing."

    @staticmethod
    def failing(checks: list[CounterfactualCheck]) -> list[CounterfactualCheck]:
        return [check for check in checks if check.status == "FAIL"]

    def _build_check(
        self,
        row: Any,
        hypothesis: str,
        evidence_kinds: set[str],
        required: dict[str, str],
        require_any_groups: list[dict[str, str]],
    ) -> CounterfactualCheck:
        missing: list[str] = []
        for group in require_any_groups:
            if evidence_kinds.isdisjoint(group.keys()):
                missing.extend(group.values())
        present = [label for kind, label in required.items() if kind in evidence_kinds]
        status = "PASS" if not missing else "FAIL"
        action = "allow_escalation" if status == "PASS" else "denied_escalation"
        if status == "FAIL" and row["status"] == ClaimStatus.CONFIRMED.value:
            action = "downgrade_confirmed_claim"
        reason = (
            "Counterfactual alibi satisfied by expected OS artifacts."
            if status == "PASS"
            else "Claim cannot escalate because required operating-system side effects are absent."
        )
        return CounterfactualCheck(
            claim_id=row["claim_id"],
            hypothesis=hypothesis,
            status=status,
            required_artifacts=list(required.values()),
            present_artifacts=present,
            missing_artifacts=sorted(set(missing)),
            action=action,
            reason=reason,
        )

    def _claim_evidence(self, claim_id: str) -> list[str]:
        rows = self.graph.conn.execute("select artifact_id from claim_evidence where claim_id = ?", (claim_id,)).fetchall()
        return [row["artifact_id"] for row in rows]

    def _evidence_kinds(self, evidence_ids: list[str]) -> set[str]:
        if not evidence_ids:
            return set()
        placeholders = ",".join("?" for _ in evidence_ids)
        rows = self.graph.conn.execute(f"select distinct kind from artifacts where artifact_id in ({placeholders})", evidence_ids).fetchall()
        return {row["kind"] for row in rows}

    def _artifacts(self, evidence_ids: list[str]) -> list[dict[str, Any]]:
        if not evidence_ids:
            return []
        placeholders = ",".join("?" for _ in evidence_ids)
        rows = self.graph.conn.execute(
            f"select artifact_id, kind, fields_json from artifacts where artifact_id in ({placeholders})",
            evidence_ids,
        ).fetchall()
        return [{**dict(row), "fields": json.loads(row["fields_json"] or "{}")} for row in rows]
