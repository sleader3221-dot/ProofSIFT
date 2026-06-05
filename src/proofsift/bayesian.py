from __future__ import annotations

import json
from typing import Any

from .audit import AuditLogger
from .graph import EvidenceGraph
from .models import BayesianScore


LIKELIHOODS: dict[str, tuple[float, float]] = {
    "network": (0.62, 0.38),
    "process": (0.70, 0.65),
    "prefetch": (0.86, 0.03),
    "amcache": (0.88, 0.025),
    "shimcache": (0.80, 0.05),
    "process_creation": (0.90, 0.025),
    "powershell_log": (0.70, 0.18),
    "mft": (0.78, 0.08),
    "usn": (0.74, 0.10),
    "autorun": (0.92, 0.04),
    "malfind": (0.93, 0.015),
    "yara_match": (0.84, 0.06),
    "guardrail_test": (0.50, 0.50),
    "evidence_hash": (0.50, 0.50),
    "parser_anomaly": (0.45, 0.45),
}

ANOMALY_LIKELIHOODS: dict[str, tuple[float, float]] = {
    "mft_creation_postdates_prefetch_execution": (0.94, 0.001),
    "mft_created_after_modified": (0.91, 0.004),
    "mft_usn_basic_info_change_after_execution": (0.89, 0.006),
}


class BayesianScorer:
    """Formal confidence scoring for forensic hypotheses."""

    def __init__(self, graph: EvidenceGraph, audit: AuditLogger):
        self.graph = graph
        self.audit = audit

    def score_claim(
        self,
        claim_id: str,
        statement: str,
        evidence_ids: list[str],
        anomaly_types: list[str] | None = None,
    ) -> BayesianScore:
        artifacts = self._artifacts(evidence_ids)
        evidence_kinds = sorted({artifact["kind"] for artifact in artifacts})
        signals = evidence_kinds + sorted(set(anomaly_types or []))
        prior = self._prior(statement)
        likelihood_h = 1.0
        likelihood_not_h = 1.0

        for kind in evidence_kinds:
            h, not_h = LIKELIHOODS.get(kind, (0.55, 0.45))
            likelihood_h *= h
            likelihood_not_h *= not_h
        for anomaly_type in sorted(set(anomaly_types or [])):
            h, not_h = ANOMALY_LIKELIHOODS.get(anomaly_type, (0.75, 0.10))
            likelihood_h *= h
            likelihood_not_h *= not_h

        if not signals:
            likelihood_h = 0.10
            likelihood_not_h = 0.90

        # Bayes: P(H|E) = P(E|H) * P(H) / P(E), where P(E) marginalizes H and not-H.
        evidence_probability = (likelihood_h * prior) + (likelihood_not_h * (1.0 - prior))
        posterior = (likelihood_h * prior / evidence_probability) if evidence_probability else 0.0
        score = BayesianScore(
            claim_id=claim_id,
            prior=round(prior, 6),
            likelihood_given_h=round(likelihood_h, 10),
            likelihood_given_not_h=round(likelihood_not_h, 10),
            evidence_probability=round(evidence_probability, 10),
            posterior=round(min(max(posterior, 0.0), 0.9999), 4),
            evidence_kinds=evidence_kinds,
            signals=signals,
            explanation=(
                "Naive Bayesian forensic calculus over independent artifact classes "
                f"and anomaly signals: {', '.join(signals) or 'no forensic signal'}."
            ),
        )
        score_id = self.graph.add_bayesian_score(score)
        self.audit.event(
            "bayesian",
            "score.computed",
            {
                "score_id": score_id,
                "claim_id": claim_id,
                "prior": score.prior,
                "likelihood_given_h": score.likelihood_given_h,
                "likelihood_given_not_h": score.likelihood_given_not_h,
                "evidence_probability": score.evidence_probability,
                "posterior": score.posterior,
                "evidence_kinds": score.evidence_kinds,
                "signals": score.signals,
                "formula": "P(H|E)=P(E|H)*P(H)/P(E)",
            },
        )
        return score

    def _artifacts(self, evidence_ids: list[str]) -> list[dict[str, Any]]:
        if not evidence_ids:
            return []
        placeholders = ",".join("?" for _ in evidence_ids)
        rows = self.graph.conn.execute(
            f"select artifact_id, kind, source, fields_json from artifacts where artifact_id in ({placeholders})",
            evidence_ids,
        ).fetchall()
        return [
            {
                "artifact_id": row["artifact_id"],
                "kind": row["kind"],
                "source": row["source"],
                "fields": json.loads(row["fields_json"] or "{}"),
            }
            for row in rows
        ]

    @staticmethod
    def _prior(statement: str) -> float:
        lowered = statement.lower()
        if "not escalated" in lowered or "negative control" in lowered:
            return 0.03
        if "known c2 indicator" in lowered or "command and control" in lowered:
            return 0.10
        if "persistence" in lowered or "autorun" in lowered or "runonce" in lowered:
            return 0.12
        if "powershell" in lowered or "process creation" in lowered or "execution" in lowered:
            return 0.18
        if "injected code" in lowered or "executable memory" in lowered:
            return 0.16
        return 0.08
