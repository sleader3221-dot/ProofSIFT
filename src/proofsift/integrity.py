from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .graph import EvidenceGraph


MERKLE_VERSION = "proofsift-merkle-dag-v1"


@dataclass(frozen=True)
class MerkleNode:
    node_id: str
    node_type: str
    record_id: str
    parent_ids: list[str]
    data: dict[str, Any]


def canonical_json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)


def sha256_json(data: Any) -> str:
    return hashlib.sha256(canonical_json(data).encode("utf-8")).hexdigest()


def artifact_content_hash(kind: str, source: str, command_id: str, fields: dict[str, Any]) -> str:
    return sha256_json(
        {
            "version": MERKLE_VERSION,
            "node_type": "artifact_content",
            "kind": kind,
            "source": source,
            "command_id": command_id,
            "fields": fields,
        }
    )


def relationship_signature(data: dict[str, Any], parent_ids: list[str]) -> str:
    return sha256_json(
        {
            "version": MERKLE_VERSION,
            "signature_domain": "claim_artifact_relationship",
            "data": data,
            "parents": sorted(parent_ids),
        }
    )


def merkle_node(node_type: str, record_id: str, parent_ids: list[str], data: dict[str, Any]) -> MerkleNode:
    parents = sorted(parent_ids)
    node_id = sha256_json(
        {
            "version": MERKLE_VERSION,
            "node_type": node_type,
            "record_id": record_id,
            "parent_ids": parents,
            "data": data,
        }
    )
    return MerkleNode(node_id=node_id, node_type=node_type, record_id=record_id, parent_ids=parents, data=data)


def calculate_integrity_seal(graph: EvidenceGraph) -> dict[str, Any]:
    """Build a deterministic Merkle-DAG over every graph row and return the root seal."""

    nodes: list[MerkleNode] = []
    broken_parent_links: list[dict[str, str]] = []
    artifact_hash_mismatches: list[dict[str, str]] = []

    tool_nodes: dict[str, str] = {}
    artifact_nodes: dict[str, str] = {}
    claim_nodes: dict[str, str] = {}
    observation_nodes: dict[str, str] = {}

    def add(node: MerkleNode) -> None:
        nodes.append(node)

    for row in graph.conn.execute("select * from tool_runs order by command_id"):
        data = dict(row)
        node = merkle_node("tool_run", row["command_id"], [], data)
        tool_nodes[row["command_id"]] = node.node_id
        add(node)

    for row in graph.conn.execute("select * from artifacts order by artifact_id"):
        fields = json.loads(row["fields_json"] or "{}")
        stored_hash = row["content_sha256"] if "content_sha256" in row.keys() else ""
        recomputed_hash = artifact_content_hash(row["kind"], row["source"], row["command_id"], fields)
        if stored_hash and stored_hash != recomputed_hash:
            artifact_hash_mismatches.append(
                {
                    "artifact_id": row["artifact_id"],
                    "stored": stored_hash,
                    "recomputed": recomputed_hash,
                }
            )
        parent = tool_nodes.get(row["command_id"])
        parents = [parent] if parent else []
        if not parent:
            broken_parent_links.append({"record": row["artifact_id"], "missing_parent": row["command_id"]})
        data = {
            "artifact_id": row["artifact_id"],
            "kind": row["kind"],
            "source": row["source"],
            "command_id": row["command_id"],
            "fields": fields,
            "content_sha256": stored_hash or recomputed_hash,
        }
        node = merkle_node("artifact", row["artifact_id"], parents, data)
        artifact_nodes[row["artifact_id"]] = node.node_id
        add(node)

    for row in graph.conn.execute("select * from observations order by observation_id"):
        parent = artifact_nodes.get(row["artifact_id"])
        parents = [parent] if parent else []
        if not parent:
            broken_parent_links.append({"record": row["observation_id"], "missing_parent": row["artifact_id"]})
        node = merkle_node("observation", row["observation_id"], parents, dict(row))
        observation_nodes[row["observation_id"]] = node.node_id
        add(node)

    evidence_by_claim = _claim_evidence(graph)
    for row in graph.conn.execute("select * from claims order by claim_id"):
        parent_ids = []
        for artifact_id in evidence_by_claim.get(row["claim_id"], []):
            parent = artifact_nodes.get(artifact_id)
            if parent:
                parent_ids.append(parent)
            else:
                broken_parent_links.append({"record": row["claim_id"], "missing_parent": artifact_id})
        node = merkle_node("claim", row["claim_id"], parent_ids, dict(row))
        claim_nodes[row["claim_id"]] = node.node_id
        add(node)

    relationship_count = 0
    for row in graph.conn.execute("select * from claim_evidence order by claim_id, artifact_id"):
        data = {
            "relationship": "supports",
            "claim_id": row["claim_id"],
            "artifact_id": row["artifact_id"],
        }
        parents = [parent for parent in [claim_nodes.get(row["claim_id"]), artifact_nodes.get(row["artifact_id"])] if parent]
        if len(parents) != 2:
            broken_parent_links.append({"record": f"{row['claim_id']}->{row['artifact_id']}", "missing_parent": "claim_or_artifact"})
        signed_data = {**data, "relationship_signature": relationship_signature(data, parents)}
        add(merkle_node("claim_evidence", f"{row['claim_id']}->{row['artifact_id']}", parents, signed_data))
        relationship_count += 1

    for row in graph.conn.execute("select * from corrections order by correction_id"):
        parent = claim_nodes.get(row["claim_id"]) if row["claim_id"] else None
        add(merkle_node("correction", row["correction_id"], [parent] if parent else [], dict(row)))

    for row in graph.conn.execute("select * from clock_drifts order by drift_id"):
        parents = [
            parent
            for parent in [
                observation_nodes.get(row["anchor_observation_id"]),
                observation_nodes.get(row["reference_observation_id"]),
            ]
            if parent
        ]
        if len(parents) != 2:
            broken_parent_links.append({"record": row["drift_id"], "missing_parent": "anchor_or_reference_observation"})
        add(merkle_node("clock_drift", row["drift_id"], parents, dict(row)))

    for row in graph.conn.execute("select * from anomalies order by anomaly_id"):
        evidence_ids = json.loads(row["evidence_json"] or "[]")
        parents = [artifact_nodes[evidence_id] for evidence_id in evidence_ids if evidence_id in artifact_nodes]
        if len(parents) != len(evidence_ids):
            broken_parent_links.append({"record": row["anomaly_id"], "missing_parent": "anomaly_evidence"})
        add(merkle_node("anomaly", row["anomaly_id"], parents, dict(row)))

    for row in graph.conn.execute("select * from sequence_recommendations order by recommendation_id"):
        parent = claim_nodes.get(row["target_claim_id"])
        if not parent:
            broken_parent_links.append({"record": row["recommendation_id"], "missing_parent": row["target_claim_id"]})
        add(merkle_node("sequence_recommendation", row["recommendation_id"], [parent] if parent else [], dict(row)))

    for row in _optional_rows(graph, "bayesian_scores", "score_id"):
        parent = claim_nodes.get(row["claim_id"])
        if not parent:
            broken_parent_links.append({"record": row["score_id"], "missing_parent": row["claim_id"]})
        add(merkle_node("bayesian_score", row["score_id"], [parent] if parent else [], dict(row)))

    for row in _optional_rows(graph, "counterfactual_checks", "check_id"):
        parent = claim_nodes.get(row["claim_id"])
        if not parent:
            broken_parent_links.append({"record": row["check_id"], "missing_parent": row["claim_id"]})
        add(merkle_node("counterfactual_check", row["check_id"], [parent] if parent else [], dict(row)))

    for row in _optional_rows(graph, "bmc_results", "result_id"):
        evidence_ids = json.loads(row["evidence_json"] or "[]")
        parents = [artifact_nodes[evidence_id] for evidence_id in evidence_ids if evidence_id in artifact_nodes]
        if len(parents) != len(evidence_ids):
            broken_parent_links.append({"record": row["result_id"], "missing_parent": "bmc_evidence"})
        add(merkle_node("bmc_result", row["result_id"], parents, dict(row)))

    for row in _optional_rows(graph, "entropy_analyses", "analysis_id"):
        evidence_ids = json.loads(row["evidence_json"] or "[]")
        parents = [artifact_nodes[evidence_id] for evidence_id in evidence_ids if evidence_id in artifact_nodes]
        if len(parents) != len(evidence_ids):
            broken_parent_links.append({"record": row["analysis_id"], "missing_parent": "entropy_evidence"})
        add(merkle_node("entropy_analysis", row["analysis_id"], parents, dict(row)))

    for row in _optional_rows(graph, "tool_authorizations", "authorization_id"):
        parent = tool_nodes.get(row["command_id"])
        if not parent:
            broken_parent_links.append({"record": row["authorization_id"], "missing_parent": row["command_id"]})
        add(merkle_node("tool_authorization", row["authorization_id"], [parent] if parent else [], dict(row)))

    knowledge_nodes: dict[str, str] = {}
    for row in _optional_rows(graph, "knowledge_nodes", "node_id"):
        evidence_ids = json.loads(row["evidence_json"] or "[]")
        parents = [artifact_nodes[evidence_id] for evidence_id in evidence_ids if evidence_id in artifact_nodes]
        if len(parents) != len(evidence_ids):
            broken_parent_links.append({"record": row["node_id"], "missing_parent": "knowledge_node_evidence"})
        node = merkle_node("knowledge_node", row["node_id"], parents, dict(row))
        knowledge_nodes[row["node_id"]] = node.node_id
        add(node)

    for row in _optional_rows(graph, "knowledge_edges", "edge_id"):
        parents = [
            parent
            for parent in [
                knowledge_nodes.get(row["source_node_id"]),
                knowledge_nodes.get(row["target_node_id"]),
            ]
            if parent
        ]
        if len(parents) != 2:
            broken_parent_links.append({"record": row["edge_id"], "missing_parent": "knowledge_edge_node"})
        add(merkle_node("knowledge_edge", row["edge_id"], parents, dict(row)))
        relationship_count += 1

    for row in _optional_rows(graph, "graph_metrics", "metric_id"):
        parent = knowledge_nodes.get(row["subject_node_id"])
        if not parent:
            broken_parent_links.append({"record": row["metric_id"], "missing_parent": row["subject_node_id"]})
        add(merkle_node("graph_metric", row["metric_id"], [parent] if parent else [], dict(row)))

    for row in _optional_rows(graph, "capability_checks", "check_id"):
        add(merkle_node("capability_check", row["check_id"], [], dict(row)))

    for row in _optional_rows(graph, "provenance_traces", "trace_id"):
        parent_ids = []
        claim_parent = claim_nodes.get(row["claim_id"])
        if claim_parent:
            parent_ids.append(claim_parent)
        else:
            broken_parent_links.append({"record": row["trace_id"], "missing_parent": row["claim_id"]})
        evidence_ids = json.loads(row["evidence_json"] or "[]")
        for evidence_id in evidence_ids:
            parent = artifact_nodes.get(evidence_id)
            if parent:
                parent_ids.append(parent)
            else:
                broken_parent_links.append({"record": row["trace_id"], "missing_parent": evidence_id})
        add(merkle_node("provenance_trace", row["trace_id"], parent_ids, dict(row)))

    for row in _optional_rows(graph, "remediation_playbooks", "playbook_id"):
        parent = claim_nodes.get(row["claim_id"])
        if not parent:
            broken_parent_links.append({"record": row["playbook_id"], "missing_parent": row["claim_id"]})
        add(merkle_node("remediation_playbook", row["playbook_id"], [parent] if parent else [], dict(row)))

    node_ids = sorted(node.node_id for node in nodes)
    root = sha256_json({"version": MERKLE_VERSION, "node_ids": node_ids})
    counts: dict[str, int] = {}
    for node in nodes:
        counts[node.node_type] = counts.get(node.node_type, 0) + 1

    return {
        "ok": not artifact_hash_mismatches and not broken_parent_links,
        "version": MERKLE_VERSION,
        "root_seal": f"sha256:{root}",
        "node_count": len(nodes),
        "relationship_block_count": relationship_count,
        "nodes_by_type": dict(sorted(counts.items())),
        "artifact_hash_mismatches": artifact_hash_mismatches,
        "broken_parent_links": broken_parent_links,
    }


def _claim_evidence(graph: EvidenceGraph) -> dict[str, list[str]]:
    by_claim: dict[str, list[str]] = {}
    for row in graph.conn.execute("select claim_id, artifact_id from claim_evidence order by claim_id, artifact_id"):
        by_claim.setdefault(row["claim_id"], []).append(row["artifact_id"])
    return by_claim


def _optional_rows(graph: EvidenceGraph, table: str, order_column: str) -> list[Any]:
    exists = graph.conn.execute(
        "select name from sqlite_master where type = 'table' and name = ?",
        (table,),
    ).fetchone()
    if not exists:
        return []
    return list(graph.conn.execute(f"select * from {table} order by {order_column}"))
