from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from .audit import AuditLogger
from .graph import EvidenceGraph
from .models import SequenceRecommendation, Severity
from .time_utils import parse_utc


TACTIC_BY_TECHNIQUE = {
    "T1059": "Execution",
    "T1059.001": "Execution",
    "T1059.003": "Execution",
    "T1204": "Execution",
    "T1055": "Defense Evasion",
    "T1547.001": "Persistence",
    "T1060": "Persistence",
    "T1003": "Credential Access",
    "T1003.001": "Credential Access",
    "T1071": "Command and Control",
    "T1071.001": "Command and Control",
}

TACTIC_ORDER = [
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]

HIGH_IMPACT_TACTICS = {"Credential Access", "Command and Control", "Exfiltration", "Impact"}
PRECEDING_REQUIREMENTS = {
    "Command and Control": {"Execution"},
    "Credential Access": {"Execution"},
    "Exfiltration": {"Execution", "Command and Control"},
    "Impact": {"Execution"},
}


@dataclass(frozen=True)
class SequencedClaim:
    claim_id: str
    statement: str
    status: str
    tactics: set[str]
    first_seen_utc: str | None


class MitreSequenceValidator:
    """State machine for ATT&CK behavioral progression."""

    def __init__(self, graph: EvidenceGraph, audit: AuditLogger):
        self.graph = graph
        self.audit = audit

    def validate(self) -> list[SequenceRecommendation]:
        claims = self._claims()
        present_tactics = set().union(*(claim.tactics for claim in claims)) if claims else set()
        recommendations: list[SequenceRecommendation] = []
        for claim in claims:
            for tactic in sorted(claim.tactics & HIGH_IMPACT_TACTICS):
                missing = PRECEDING_REQUIREMENTS.get(tactic, set()) - present_tactics
                if not missing:
                    continue
                recommendation = self._recommendation(claim, tactic, sorted(missing))
                recommendation_id = self.graph.add_sequence_recommendation(recommendation)
                recommendations.append(recommendation)
                self.audit.event(
                    "mitre_sequence",
                    "gap.detected",
                    {
                        "recommendation_id": recommendation_id,
                        "target_claim_id": claim.claim_id,
                        "gap_type": recommendation.gap_type,
                        "required_tactics": recommendation.required_tactics,
                        "recommended_tools": recommendation.recommended_tools,
                        "recommended_paths": recommendation.recommended_paths,
                    },
                )
        if not recommendations:
            self.audit.event("mitre_sequence", "sequence.valid", {"claim_count": len(claims), "tactics": sorted(present_tactics)})
        return recommendations

    def _claims(self) -> list[SequencedClaim]:
        sequenced: list[SequencedClaim] = []
        for row in self.graph.claims():
            mitre = json.loads(row["mitre_json"] or "[]")
            tactics = {TACTIC_BY_TECHNIQUE[technique] for technique in mitre if technique in TACTIC_BY_TECHNIQUE}
            first_seen = self._claim_first_seen(row["claim_id"])
            sequenced.append(
                SequencedClaim(
                    claim_id=row["claim_id"],
                    statement=row["statement"],
                    status=row["status"],
                    tactics=tactics,
                    first_seen_utc=first_seen,
                )
            )
        return sorted(sequenced, key=lambda claim: claim.first_seen_utc or "9999-12-31T23:59:59Z")

    def _claim_first_seen(self, claim_id: str) -> str | None:
        row = self.graph.conn.execute(
            """
            select min(o.normalized_utc) as first_seen
            from claim_evidence ce
            join observations o on ce.artifact_id = o.artifact_id
            where ce.claim_id = ?
            """,
            (claim_id,),
        ).fetchone()
        if not row or not row["first_seen"]:
            return None
        parsed = parse_utc(row["first_seen"])
        return row["first_seen"] if parsed else None

    @staticmethod
    def _recommendation(claim: SequencedClaim, tactic: str, missing: list[str]) -> SequenceRecommendation:
        tools = []
        paths = []
        if "Execution" in missing:
            tools.extend(["disk_prefetch", "disk_amcache", "windows_evtx", "memory_psscan"])
            paths.extend([
                "C:\\Windows\\Prefetch\\*.pf",
                "Amcache.hve program entries",
                "Security.evtx Event ID 4688",
                "memory process listings for hidden or terminated processes",
            ])
        if "Persistence" in missing:
            tools.extend(["registry_autoruns", "timeline_mft", "timeline_usn"])
            paths.extend([
                "HKCU/HKLM Run and RunOnce keys",
                "Startup folders",
                "MFT/USN entries for suspicious executables",
            ])
        return SequenceRecommendation(
            gap_type=f"missing_preceding_behavior_for_{tactic.lower().replace(' ', '_')}",
            reason=(
                f"{tactic} claim `{claim.claim_id}` exists without preceding "
                f"{', '.join(missing)} evidence in the current ATT&CK sequence."
            ),
            target_claim_id=claim.claim_id,
            required_tactics=missing,
            recommended_tools=sorted(set(tools)),
            recommended_paths=sorted(set(paths)),
            priority=Severity.HIGH,
        )
