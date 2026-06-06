from __future__ import annotations

import json
from collections import defaultdict
from pathlib import PureWindowsPath
from typing import Any

import networkx as nx

from .audit import AuditLogger
from .graph import EvidenceGraph
from .models import GraphMetric, KnowledgeEdge, KnowledgeNode


class AttackKnowledgeGraph:
    """Build typed attack relationships and calculate evidence-backed centrality."""

    def __init__(self, graph: EvidenceGraph, audit: AuditLogger):
        self.graph = graph
        self.audit = audit

    def analyze(self) -> list[GraphMetric]:
        directed = nx.DiGraph()
        evidence_by_entity: dict[tuple[str, str], set[str]] = defaultdict(set)
        attributes_by_entity: dict[tuple[str, str], dict[str, Any]] = defaultdict(dict)

        for row in self.graph.artifacts():
            fields = json.loads(row["fields_json"] or "{}")
            entities = _entities(fields)
            for entity_type, entity_key, label, attributes in entities:
                key = (entity_type, entity_key)
                evidence_by_entity[key].add(row["artifact_id"])
                attributes_by_entity[key].update(attributes)
                directed.add_node(key, label=label, entity_type=entity_type)
            for left, right in zip(entities, entities[1:]):
                source = (left[0], left[1])
                target = (right[0], right[1])
                current = directed.get_edge_data(source, target, {}).get("weight", 0.0)
                directed.add_edge(source, target, relation="observed_with", weight=current + 1.0)

        for claim in self.graph.claims():
            claim_key = ("claim", claim["claim_id"])
            directed.add_node(claim_key, label=claim["statement"], entity_type="claim")
            for artifact_id in self._claim_evidence(claim["claim_id"]):
                artifact = self.graph.conn.execute(
                    "select fields_json from artifacts where artifact_id = ?",
                    (artifact_id,),
                ).fetchone()
                if not artifact:
                    continue
                for entity_type, entity_key, _label, _attributes in _entities(
                    json.loads(artifact["fields_json"] or "{}")
                ):
                    directed.add_edge(
                        (entity_type, entity_key),
                        claim_key,
                        relation="supports_claim",
                        weight=max(float(claim["confidence"]), 0.1),
                    )
                    evidence_by_entity[claim_key].add(artifact_id)

        if not directed:
            self.audit.event("knowledge_graph", "analysis.empty", {})
            return []

        node_ids: dict[tuple[str, str], str] = {}
        malicious_terms = ("evil", "203.0.113.50", "c2", "malfind", "autorun")
        for key, data in directed.nodes(data=True):
            evidence_ids = sorted(evidence_by_entity.get(key, set()))
            label = str(data.get("label") or key[1])
            risk_score = min(
                1.0,
                0.15
                + (0.18 * len(evidence_ids))
                + (0.35 if any(term in label.lower() for term in malicious_terms) else 0.0),
            )
            node = KnowledgeNode(
                entity_type=key[0],
                entity_key=key[1],
                label=label,
                risk_score=round(risk_score, 4),
                evidence_ids=evidence_ids,
                attributes=attributes_by_entity.get(key, {}),
            )
            node_ids[key] = self.graph.add_knowledge_node(node)

        for source, target, data in directed.edges(data=True):
            evidence_ids = sorted(
                evidence_by_entity.get(source, set()).intersection(
                    evidence_by_entity.get(target, set())
                )
            )
            self.graph.add_knowledge_edge(
                KnowledgeEdge(
                    source_node_id=node_ids[source],
                    target_node_id=node_ids[target],
                    relation=str(data.get("relation", "related_to")),
                    weight=float(data.get("weight", 1.0)),
                    evidence_ids=evidence_ids,
                )
            )

        try:
            scores = nx.pagerank(directed, weight="weight", max_iter=200, tol=1.0e-8)
        except nx.PowerIterationFailedConvergence:
            scores = nx.pagerank(directed, weight=None, max_iter=500)

        ordered = sorted(scores.items(), key=lambda item: (-item[1], item[0]))
        metrics: list[GraphMetric] = []
        for rank, (key, score) in enumerate(ordered, start=1):
            descendants = nx.descendants(directed, key)
            metric = GraphMetric(
                algorithm="pagerank-v1",
                subject_node_id=node_ids[key],
                score=round(float(score), 8),
                rank=rank,
                details={
                    "blast_radius_nodes": len(descendants),
                    "in_degree": directed.in_degree(key),
                    "out_degree": directed.out_degree(key),
                    "center_of_gravity": rank == 1,
                    "networkx_version": nx.__version__,
                },
            )
            self.graph.add_graph_metric(metric)
            metrics.append(metric)

        top = metrics[0]
        self.audit.event(
            "knowledge_graph",
            "pagerank.completed",
            {
                "node_count": directed.number_of_nodes(),
                "edge_count": directed.number_of_edges(),
                "center_of_gravity_node_id": top.subject_node_id,
                "center_of_gravity_score": top.score,
            },
        )
        return metrics

    def _claim_evidence(self, claim_id: str) -> list[str]:
        return [
            row["artifact_id"]
            for row in self.graph.conn.execute(
                "select artifact_id from claim_evidence where claim_id = ?",
                (claim_id,),
            )
        ]


def _entities(fields: dict[str, Any]) -> list[tuple[str, str, str, dict[str, Any]]]:
    entities: list[tuple[str, str, str, dict[str, Any]]] = []
    process = str(fields.get("process") or fields.get("name") or fields.get("executable") or "").strip()
    path = str(fields.get("path") or fields.get("image") or "").strip()
    remote_ip = str(fields.get("remote_ip") or "").strip()
    registry_key = str(fields.get("registry_key") or fields.get("key") or "").strip()

    if process:
        process_name = PureWindowsPath(process).name.lower()
        entities.append(("process", process_name, process_name, {"pid": fields.get("pid")}))
    if path:
        normalized_path = path.replace("/", "\\").lower()
        entities.append(("file", normalized_path, path, {}))
    if remote_ip:
        entities.append(
            (
                "ip",
                remote_ip.lower(),
                remote_ip,
                {"remote_port": fields.get("remote_port")},
            )
        )
    if registry_key:
        entities.append(("registry", registry_key.lower(), registry_key, {}))
    return entities
