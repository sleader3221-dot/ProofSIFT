from __future__ import annotations

import json
from typing import Any

from .audit import AuditLogger
from .graph import EvidenceGraph
from .models import ProvenanceTrace


REASONING_POLICY = (
    "Evidence-and-rule provenance only. Hidden model chain-of-thought, private scratchpads, "
    "and raw critic prompts are neither requested nor stored."
)


class ProvenanceEngine:
    """Create judge-readable explanations from durable evidence and verifier outputs."""

    def __init__(self, graph: EvidenceGraph, audit: AuditLogger):
        self.graph = graph
        self.audit = audit

    def generate(self) -> list[ProvenanceTrace]:
        traces: list[ProvenanceTrace] = []
        for claim in self.graph.claims():
            claim_id = claim["claim_id"]
            evidence_ids = [
                row["artifact_id"]
                for row in self.graph.conn.execute(
                    "select artifact_id from claim_evidence where claim_id = ?",
                    (claim_id,),
                )
            ]
            kinds = [
                row["kind"]
                for row in self.graph.conn.execute(
                    "select distinct kind from artifacts where artifact_id in "
                    f"({','.join('?' for _ in evidence_ids)})",
                    evidence_ids,
                )
            ] if evidence_ids else []
            latest_bayes = self.graph.conn.execute(
                "select * from bayesian_scores where claim_id = ? order by rowid desc limit 1",
                (claim_id,),
            ).fetchone()
            counterfactuals = [
                dict(row)
                for row in self.graph.conn.execute(
                    "select status, action, missing_artifacts_json from counterfactual_checks "
                    "where claim_id = ? order by check_id",
                    (claim_id,),
                )
            ]
            rules = [
                "confirmed claims require at least two independent artifact kinds",
                "counterfactual OS side effects must be present or escalation is denied",
                "timestamps must satisfy Z3 causal constraints after drift normalization",
            ]
            calculations: dict[str, Any] = {
                "independent_artifact_kinds": sorted(kinds),
                "artifact_kind_count": len(set(kinds)),
                "counterfactual_checks": counterfactuals,
            }
            if latest_bayes:
                calculations["bayesian"] = {
                    "prior": latest_bayes["prior"],
                    "likelihood_given_h": latest_bayes["likelihood_given_h"],
                    "likelihood_given_not_h": latest_bayes["likelihood_given_not_h"],
                    "posterior": latest_bayes["posterior"],
                    "formula": "P(H|E)=P(E|H)*P(H)/P(E)",
                }
            trace = ProvenanceTrace(
                claim_id=claim_id,
                verdict=claim["status"],
                evidence_ids=sorted(evidence_ids),
                rules=rules,
                calculations=calculations,
                explanation=(
                    f"{claim['status']} at {float(claim['confidence']):.2%}: "
                    f"{len(set(kinds))} independent artifact kinds were evaluated under "
                    "corroboration, counterfactual, Bayesian, and temporal rules."
                ),
                reasoning_policy=REASONING_POLICY,
            )
            trace_id = self.graph.add_provenance_trace(trace)
            traces.append(trace)
            self.audit.event(
                "provenance",
                "trace.generated",
                {
                    "trace_id": trace_id,
                    "claim_id": claim_id,
                    "verdict": claim["status"],
                    "evidence_count": len(evidence_ids),
                    "rule_count": len(rules),
                },
            )
        return traces
