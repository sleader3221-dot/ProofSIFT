from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

from .graph import EvidenceGraph
from .integrity import calculate_integrity_seal
from .models import CaseConfig


def write_reports(config: CaseConfig, graph: EvidenceGraph, output_dir: Path) -> dict[str, str]:
    markdown = output_dir / "report.md"
    markdown_2 = output_dir / "report_2.md"
    html_path = output_dir / "report.html"
    accuracy_stub = output_dir / "accuracy_report.md"
    trace_index = output_dir / "trace_index.json"
    claims = [dict(row) for row in graph.claims()]
    corrections = [dict(row) for row in graph.corrections()]
    clock_drifts = [dict(row) for row in graph.clock_drifts()]
    anomalies = [dict(row) for row in graph.anomalies()]
    sequence_recommendations = [dict(row) for row in graph.sequence_recommendations()]
    bayesian_scores = [dict(row) for row in graph.bayesian_scores()]
    counterfactual_checks = [dict(row) for row in graph.counterfactual_checks()]
    integrity_seal = calculate_integrity_seal(graph)
    traces: dict[str, Any] = {}
    for claim in claims:
        traces[claim["claim_id"]] = graph.trace_claim(claim["claim_id"])
    trace_index.write_text(json.dumps(traces, indent=2, sort_keys=True), encoding="utf-8")
    markdown_text = _markdown(
        config,
        claims,
        corrections,
        traces,
        clock_drifts,
        anomalies,
        sequence_recommendations,
        bayesian_scores,
        counterfactual_checks,
        integrity_seal,
    )
    markdown.write_text(markdown_text, encoding="utf-8")
    markdown_2.write_text(markdown_text, encoding="utf-8")
    html_path.write_text(
        _html(
            config,
            claims,
            corrections,
            traces,
            clock_drifts,
            anomalies,
            sequence_recommendations,
            bayesian_scores,
            counterfactual_checks,
            integrity_seal,
        ),
        encoding="utf-8",
    )
    if not accuracy_stub.exists():
        accuracy_stub.write_text(_accuracy_stub(config), encoding="utf-8")
    return {
        "markdown": str(markdown),
        "markdown_2": str(markdown_2),
        "html": str(html_path),
        "accuracy_report": str(accuracy_stub),
        "trace_index": str(trace_index),
        "evidence_graph": str(output_dir / "evidence_graph.sqlite"),
        "execution_log": str(output_dir / "execution_log.jsonl"),
        "integrity_root_seal": integrity_seal["root_seal"],
    }


def _markdown(
    config: CaseConfig,
    claims: list[dict[str, Any]],
    corrections: list[dict[str, Any]],
    traces: dict[str, Any],
    clock_drifts: list[dict[str, Any]],
    anomalies: list[dict[str, Any]],
    sequence_recommendations: list[dict[str, Any]],
    bayesian_scores: list[dict[str, Any]],
    counterfactual_checks: list[dict[str, Any]],
    integrity_seal: dict[str, Any],
) -> str:
    lines = [
        f"# ProofSIFT Investigation Report: {config.name}",
        "",
        "## Executive Summary",
        "",
        f"- Case ID: `{config.case_id}`",
        f"- Evidence directory: `{config.evidence_dir}`",
        f"- Claims produced: `{len(claims)}`",
        f"- Self-corrections recorded: `{len(corrections)}`",
        f"- Clock drift adjustments: `{len(clock_drifts)}`",
        f"- Anti-forensics anomalies: `{len(anomalies)}`",
        f"- MITRE sequence recommendations: `{len(sequence_recommendations)}`",
        f"- Counterfactual checks: `{len(counterfactual_checks)}`",
        f"- Merkle-DAG root seal: `{integrity_seal['root_seal']}`",
        "",
        "## Findings",
        "",
    ]
    for claim in claims:
        lines.extend(
            [
                f"### {claim['claim_id']} - {claim['status']} - {claim['severity']}",
                "",
                claim["statement"],
                "",
                f"- Confidence: `{claim['confidence']:.2f}`",
                f"- Rationale: {claim['rationale'] or 'No rationale recorded.'}",
                f"- MITRE: `{', '.join(json.loads(claim['mitre_json'] or '[]')) or 'n/a'}`",
                f"- Trace: `proofsift trace --graph outputs/evidence_graph.sqlite --claim-id {claim['claim_id']}`",
                "",
                "| Evidence ID | Kind | Source | Tool | Key Fields |",
                "| --- | --- | --- | --- | --- |",
            ]
        )
        for evidence in traces[claim["claim_id"]]["evidence"]:
            key_fields = _compact_fields(evidence["fields"])
            lines.append(f"| `{evidence['artifact_id']}` | `{evidence['kind']}` | `{evidence['source']}` | `{evidence['tool_name']}` | {key_fields} |")
        lines.append("")
    lines.extend(["## Self-Corrections", ""])
    if not corrections:
        lines.append("No corrections were required.")
    for correction in corrections:
        lines.extend(
            [
                f"- Iteration `{correction['iteration']}` corrected `{correction['claim_id']}`: {correction['reason']}",
            ]
        )
    lines.extend(["", "## Clock Drift Normalization", ""])
    if not clock_drifts:
        lines.append("No source clock drift was detected.")
    for drift in clock_drifts:
        lines.append(
            f"- `{drift['source']}` normalized against `{drift['reference_source']}` "
            f"with `{drift['delta_seconds']}` second offset; confidence `{drift['confidence']:.2f}`. "
            f"Reason: {drift['reason']}"
        )
    lines.extend(["", "## Anti-Forensics Anomalies", ""])
    if not anomalies:
        lines.append("No timestomping or anti-forensics anomalies were detected.")
    for anomaly in anomalies:
        details = json.loads(anomaly["details_json"])
        evidence = ", ".join(json.loads(anomaly["evidence_json"]))
        lines.append(
            f"- `{details.get('type')}` on `{anomaly['target']}` "
            f"({anomaly['severity']}, multiplier `{anomaly['confidence_multiplier']}`), "
            f"evidence `{evidence}`. {details.get('interpretation', '')}"
        )
    lines.extend(["", "## MITRE ATT&CK Sequence Recommendations", ""])
    if not sequence_recommendations:
        lines.append("No missing behavioral sequence links were detected.")
    for recommendation in sequence_recommendations:
        tools = ", ".join(json.loads(recommendation["recommended_tools_json"]))
        paths = "; ".join(json.loads(recommendation["recommended_paths_json"]))
        lines.append(
            f"- `{recommendation['gap_type']}` for claim `{recommendation['target_claim_id']}`: "
            f"{recommendation['reason']} Tools: `{tools}`. Paths: {paths}"
        )
    lines.extend(["", "## Counterfactual Falsification", ""])
    if not counterfactual_checks:
        lines.append("No counterfactual alibi checks were required.")
    for check in counterfactual_checks:
        missing = ", ".join(json.loads(check["missing_artifacts_json"]))
        present = ", ".join(json.loads(check["present_artifacts_json"]))
        lines.append(
            f"- `{check['status']}` `{check['hypothesis']}` for claim `{check['claim_id']}`. "
            f"Present: {present or 'none'}. Missing: {missing or 'none'}. Action: `{check['action']}`."
        )
    lines.extend(["", "## Bayesian Forensic Calculus", ""])
    lines.append("Formula: `P(H|E) = P(E|H) * P(H) / P(E)`.")
    latest_scores = _latest_bayesian_scores(bayesian_scores)
    if not latest_scores:
        lines.append("No Bayesian scores were recorded.")
    for score in latest_scores:
        lines.append(
            f"- Claim `{score['claim_id']}` posterior `{score['posterior']:.4f}` "
            f"from prior `{score['prior']:.4f}`, P(E|H) `{score['likelihood_given_h']:.6f}`, "
            f"P(E|not H) `{score['likelihood_given_not_h']:.6f}`. "
            f"Signals: `{', '.join(json.loads(score['signals_json'])) or 'none'}`."
        )
    lines.extend(
        [
            "",
            "## Evidence Integrity",
            "",
            "- Evidence files were hashed before analysis.",
            f"- Merkle-DAG root seal: `{integrity_seal['root_seal']}`.",
            f"- Merkle-DAG nodes: `{integrity_seal['node_count']}` total; relationship blocks: `{integrity_seal['relationship_block_count']}`.",
            f"- Merkle-DAG verification status: `{integrity_seal['ok']}`.",
            "- The path policy allowed reads from registered evidence roots only.",
            "- The spoliation probe verified that writes into the evidence root are blocked.",
            "- Report, graph, and logs are written only under the configured output directory.",
            "- Re-verify with: `proofsift verify-integrity --graph outputs/evidence_graph.sqlite`.",
            "",
            "## Reproducibility",
            "",
            "Run the same case with:",
            "",
            "```bash",
            "proofsift run --case cases/demo_case/case.json --max-iterations 3",
            "proofsift benchmark --case cases/demo_case/case.json --ground-truth cases/demo_case/ground_truth.json",
            "```",
            "",
        ]
    )
    return "\n".join(lines)


def _html(
    config: CaseConfig,
    claims: list[dict[str, Any]],
    corrections: list[dict[str, Any]],
    traces: dict[str, Any],
    clock_drifts: list[dict[str, Any]],
    anomalies: list[dict[str, Any]],
    sequence_recommendations: list[dict[str, Any]],
    bayesian_scores: list[dict[str, Any]],
    counterfactual_checks: list[dict[str, Any]],
    integrity_seal: dict[str, Any],
) -> str:
    body = [
        "<!doctype html><html><head><meta charset='utf-8'>",
        "<title>ProofSIFT Report</title>",
        "<style>body{font-family:Arial,sans-serif;max-width:1100px;margin:40px auto;line-height:1.45;color:#17202a}code{background:#eef2f6;padding:2px 4px;border-radius:4px}table{border-collapse:collapse;width:100%}td,th{border:1px solid #d8dee6;padding:6px;text-align:left}.CONFIRMED{color:#0b6b2b}.INFERRED{color:#8a5a00}.POSSIBLE{color:#4a5568}.CRITICAL{font-weight:700}</style>",
        "</head><body>",
        f"<h1>ProofSIFT Investigation Report: {html.escape(config.name)}</h1>",
        f"<p><strong>Case:</strong> <code>{html.escape(config.case_id)}</code> | <strong>Claims:</strong> {len(claims)} | <strong>Corrections:</strong> {len(corrections)}</p>",
        f"<p><strong>Merkle-DAG Root Seal:</strong> <code>{html.escape(integrity_seal['root_seal'])}</code></p>",
    ]
    for claim in claims:
        body.append(f"<h2 class='{html.escape(claim['status'])}'>{html.escape(claim['claim_id'])} - {html.escape(claim['status'])} - {html.escape(claim['severity'])}</h2>")
        body.append(f"<p>{html.escape(claim['statement'])}</p>")
        body.append(f"<p><strong>Confidence:</strong> {claim['confidence']:.2f}<br><strong>Rationale:</strong> {html.escape(claim['rationale'] or '')}</p>")
        body.append("<table><tr><th>Evidence ID</th><th>Kind</th><th>Source</th><th>Tool</th><th>Key Fields</th></tr>")
        for evidence in traces[claim["claim_id"]]["evidence"]:
            body.append(
                "<tr>"
                f"<td><code>{html.escape(evidence['artifact_id'])}</code></td>"
                f"<td>{html.escape(evidence['kind'])}</td>"
                f"<td>{html.escape(evidence['source'])}</td>"
                f"<td>{html.escape(str(evidence['tool_name']))}</td>"
                f"<td>{html.escape(_compact_fields(evidence['fields']))}</td>"
                "</tr>"
            )
        body.append("</table>")
    body.append("<h2>Self-Corrections</h2><ul>")
    for correction in corrections:
        body.append(f"<li>Iteration <code>{correction['iteration']}</code>: {html.escape(correction['reason'])}</li>")
    body.append("</ul><h2>Clock Drift Normalization</h2><ul>")
    for drift in clock_drifts:
        body.append(
            f"<li><code>{html.escape(drift['source'])}</code> offset by "
            f"<code>{drift['delta_seconds']}</code> seconds against "
            f"<code>{html.escape(drift['reference_source'])}</code>: "
            f"{html.escape(drift['reason'])}</li>"
        )
    body.append("</ul><h2>Anti-Forensics Anomalies</h2><ul>")
    for anomaly in anomalies:
        details = json.loads(anomaly["details_json"])
        body.append(
            f"<li><code>{html.escape(details.get('type', 'unknown'))}</code> on "
            f"<code>{html.escape(anomaly['target'])}</code>: "
            f"{html.escape(details.get('interpretation', ''))}</li>"
        )
    body.append("</ul><h2>MITRE ATT&CK Sequence Recommendations</h2><ul>")
    for recommendation in sequence_recommendations:
        tools = ", ".join(json.loads(recommendation["recommended_tools_json"]))
        body.append(
            f"<li>{html.escape(recommendation['reason'])} "
            f"Tools: <code>{html.escape(tools)}</code></li>"
        )
    body.append("</ul><h2>Counterfactual Falsification</h2><ul>")
    for check in counterfactual_checks:
        body.append(
            f"<li><code>{html.escape(check['status'])}</code> "
            f"{html.escape(check['hypothesis'])} for "
            f"<code>{html.escape(check['claim_id'])}</code>: "
            f"{html.escape(check['action'])}</li>"
        )
    body.append("</ul><h2>Bayesian Forensic Calculus</h2><ul>")
    for score in _latest_bayesian_scores(bayesian_scores):
        body.append(
            f"<li>Claim <code>{html.escape(score['claim_id'])}</code> posterior "
            f"<code>{score['posterior']:.4f}</code> via "
            f"<code>P(H|E)=P(E|H)*P(H)/P(E)</code></li>"
        )
    body.append("</ul></body></html>")
    return "\n".join(body)


def _compact_fields(fields: dict[str, Any]) -> str:
    priority = ["name", "process", "pid", "path", "executable", "remote_ip", "remote_port", "time_utc", "last_run_utc", "sha256", "registry_key", "keyword"]
    selected = {key: fields[key] for key in priority if key in fields and fields[key]}
    if not selected:
        selected = dict(list(fields.items())[:4])
    return "`" + json.dumps(selected, sort_keys=True) + "`"


def _latest_bayesian_scores(scores: list[dict[str, Any]]) -> list[dict[str, Any]]:
    latest: dict[str, dict[str, Any]] = {}
    for score in scores:
        latest[score["claim_id"]] = score
    return sorted(latest.values(), key=lambda item: item["claim_id"])


def _accuracy_stub(config: CaseConfig) -> str:
    return f"""# Accuracy Report: {config.name}

Run `proofsift benchmark --case <case.json> --ground-truth <ground_truth.json>` to replace this template with measured results.

## Evidence Integrity Approach

- Evidence reads are limited to the configured evidence root.
- Writes are limited to the configured output directory.
- SHA-256 hashes are recorded before analysis.
- `proofsift verify-integrity --graph <graph.sqlite>` returns a Merkle-DAG root seal over tools, artifacts, claims, and relationship blocks.
- A spoliation probe attempts to validate a write inside the evidence root and must be rejected.

## Known Limitations

- Demo mode uses normalized CSV/text exports so the repository is runnable without a full SIFT VM.
- On SIFT, replace fixture parsers with the typed command adapters documented in `docs/sift_integration.md`.
"""
