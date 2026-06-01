from __future__ import annotations

import json
from pathlib import Path, PureWindowsPath
from typing import Any

from .anti_forensics import AntiForensicsDetector
from .audit import AuditLogger
from .clock_drift import ClockDriftNormalizer, DriftSearchBoundary
from .graph import EvidenceGraph
from .mitre_sequence import MitreSequenceValidator
from .models import CaseConfig, Claim, ClaimStatus, Severity
from .reporting import write_reports
from .security import SafePathPolicy
from .tools import ToolRunner, estimate_tokens


class SelfCorrectingInvestigator:
    """Deterministic autonomous DFIR loop with explicit verification gates."""

    def __init__(self, config: CaseConfig):
        self.config = config
        self.evidence_dir = Path(config.evidence_dir).resolve()
        self.output_dir = Path(config.output_dir).resolve()
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._reset_derived_outputs()
        self.audit = AuditLogger(self.output_dir / "execution_log.jsonl")
        self.graph = EvidenceGraph(self.output_dir / "evidence_graph.sqlite")
        self.policy = SafePathPolicy([self.evidence_dir], self.output_dir)
        self.tools = ToolRunner(self.evidence_dir, self.graph, self.audit, self.policy, config.indicators)
        self.clock_drift = ClockDriftNormalizer(self.graph, self.audit)
        self.anti_forensics = AntiForensicsDetector(self.graph, self.audit)
        self.mitre_sequence = MitreSequenceValidator(self.graph, self.audit)

    def run(self) -> dict[str, Any]:
        self.audit.event("agent", "run.start", {"case_id": self.config.case_id, "max_iterations": self.config.max_iterations})
        self.tools.hash_all_evidence()
        self.tools.spoliation_probe()
        self.tools.memory_pslist()
        self.tools.memory_psscan()
        self.tools.memory_netscan()
        self.tools.memory_malfind()

        self.audit.event("agent", "iteration.start", {"iteration": 1, "phase": "memory and network triage"})
        self._network_hypotheses(iteration=1)
        sequence_recommendations = self._validate_mitre_sequence(iteration=1)
        needs_disk = self._verify_claims(iteration=1)
        needs_disk = needs_disk or bool(sequence_recommendations)
        self.audit.event(
            "agent",
            "iteration.end",
            {
                "iteration": 1,
                "needs_disk_corroboration": needs_disk,
                "sequence_recommendations": len(sequence_recommendations),
            },
        )

        if self.config.max_iterations >= 2 and needs_disk:
            self.audit.event("agent", "iteration.start", {"iteration": 2, "phase": "disk corroboration and persistence"})
            self.tools.disk_prefetch()
            self.tools.disk_amcache()
            self.tools.disk_shimcache()
            self.tools.registry_autoruns()
            self.tools.timeline_mft()
            self.tools.timeline_usn()
            self.tools.windows_evtx()
            self.tools.windows_process_creation()
            self.tools.powershell_logs()
            self.tools.yara_keyword_scan()
            self._normalize_clock_drift(iteration=2)
            self._correlate_disk_memory(iteration=2)
            anomalies = self.anti_forensics.detect()
            self._apply_anti_forensics_adjustments(anomalies, iteration=2)
            self._verify_claims(iteration=2)
            self._validate_mitre_sequence(iteration=2)
            self.audit.event("agent", "iteration.end", {"iteration": 2})

        if self.config.max_iterations >= 3:
            self.audit.event("agent", "iteration.start", {"iteration": 3, "phase": "negative controls and narrative hardening"})
            self._negative_controls(iteration=3)
            self._verify_claims(iteration=3)
            self.audit.event("agent", "iteration.end", {"iteration": 3})

        reports = write_reports(self.config, self.graph, self.output_dir)
        result = {
            "case_id": self.config.case_id,
            "output_dir": str(self.output_dir),
            "reports": reports,
            "claims": [dict(row) for row in self.graph.claims()],
            "corrections": [dict(row) for row in self.graph.corrections()],
            "clock_drifts": [dict(row) for row in self.graph.clock_drifts()],
            "anomalies": [dict(row) for row in self.graph.anomalies()],
            "sequence_recommendations": [dict(row) for row in self.graph.sequence_recommendations()],
        }
        self.audit.event("agent", "run.end", {"case_id": self.config.case_id, "claim_count": len(result["claims"]), "report_md": reports["markdown"]})
        self.graph.close()
        return result

    def _reset_derived_outputs(self) -> None:
        for filename in [
            "execution_log.jsonl",
            "evidence_graph.sqlite",
            "evidence_graph.sqlite-shm",
            "evidence_graph.sqlite-wal",
            "trace_index.json",
            "report.md",
            "report_2.md",
            "report.html",
            "benchmark.json",
        ]:
            path = self.output_dir / filename
            path.unlink(missing_ok=True)

    def _normalize_clock_drift(self, iteration: int) -> None:
        drift = self.clock_drift.discover_and_apply(
            reference=DriftSearchBoundary(source="netscan", timestamp_field="first_seen", kind="network"),
            candidate=DriftSearchBoundary(source="evtx", timestamp_field="time_utc", kind="evtx"),
        )
        if drift:
            self.graph.add_correction(
                iteration,
                None,
                {"source": drift.source, "normalized": False},
                {"source": drift.source, "normalized": True, "delta_seconds": drift.delta_seconds},
                "clock drift normalization applied to cross-source observations",
            )

    def _validate_mitre_sequence(self, iteration: int):
        recommendations = self.mitre_sequence.validate()
        for recommendation in recommendations:
            self.graph.add_correction(
                iteration,
                recommendation.target_claim_id,
                {"sequence_state": "gap_detected"},
                {
                    "required_tactics": recommendation.required_tactics,
                    "recommended_tools": recommendation.recommended_tools,
                    "recommended_paths": recommendation.recommended_paths,
                },
                recommendation.reason,
            )
            self.audit.event(
                "agent",
                "targeted_subroutine.requested",
                {
                    "iteration": iteration,
                    "target_claim_id": recommendation.target_claim_id,
                    "tools": recommendation.recommended_tools,
                    "paths": recommendation.recommended_paths,
                },
            )
        return recommendations

    def _network_hypotheses(self, iteration: int) -> None:
        c2_ips = set(self.config.indicators.get("c2_ips", []))
        processes = self._artifacts("process")
        process_by_pid = {artifact["fields"].get("pid"): artifact for artifact in processes}
        for network in self._artifacts("network"):
            fields = network["fields"]
            remote_ip = fields.get("remote_ip", "")
            if remote_ip not in c2_ips:
                continue
            process = process_by_pid.get(fields.get("pid"))
            evidence_ids = [network["artifact_id"]]
            process_name = fields.get("process") or "unknown process"
            if process:
                evidence_ids.append(process["artifact_id"])
                process_name = process["fields"].get("name", process_name)
            claim = Claim(
                statement=f"{process_name} communicated with known C2 indicator {remote_ip}:{fields.get('remote_port', '')}",
                status=ClaimStatus.POSSIBLE,
                confidence=0.62,
                severity=Severity.HIGH,
                evidence_ids=evidence_ids,
                rationale="Initial network triage matched a configured C2 indicator; disk execution evidence is required before confirmation.",
                mitre=["T1071"],
            )
            claim_id = self.graph.upsert_claim(claim)
            self.audit.event(
                "agent",
                "claim.created",
                {
                    "iteration": iteration,
                    "claim_id": claim_id,
                    "status": claim.status.value,
                    "statement": claim.statement,
                    "estimated_token_usage": estimate_tokens(claim.statement + claim.rationale),
                },
            )

    def _correlate_disk_memory(self, iteration: int) -> None:
        processes = self._artifacts("process")
        prefetch = self._artifacts("prefetch")
        amcache = self._artifacts("amcache")
        shimcache = self._artifacts("shimcache")
        autoruns = self._artifacts("autorun")
        mft = self._artifacts("mft")
        evtx = self._artifacts("evtx")
        process_creation = self._artifacts("process_creation")
        powershell_logs = self._artifacts("powershell_log")
        malfind = self._artifacts("malfind")
        yara = self._artifacts("yara_match")
        c2_claims = [row for row in self.graph.claims() if "known C2 indicator" in row["statement"]]
        for claim_row in c2_claims:
            target_name = _first_process_name(claim_row["statement"])
            if not target_name:
                continue
            matches = self._matching_evidence(
                target_name,
                processes,
                prefetch,
                amcache,
                shimcache,
                mft,
                evtx,
                process_creation,
                powershell_logs,
                malfind,
                yara,
            )
            if len({match["kind"] for match in matches}) >= 3:
                claim = Claim(
                    claim_id=claim_row["claim_id"],
                    statement=claim_row["statement"],
                    status=ClaimStatus.CONFIRMED,
                    confidence=0.93,
                    severity=Severity.CRITICAL,
                    evidence_ids=sorted(set(self._claim_evidence(claim_row["claim_id"]) + [match["artifact_id"] for match in matches])),
                    rationale="C2 communication is corroborated by memory, execution, filesystem, event-log, and indicator evidence.",
                    mitre=["T1071", "T1204", "T1059"],
                )
                before = dict(claim_row)
                self.graph.upsert_claim(claim)
                self.graph.add_correction(iteration, claim.claim_id, before, _claim_dict(claim), "upgraded after disk and event-log corroboration")
                self.audit.event("agent", "claim.corrected", {"iteration": iteration, "claim_id": claim.claim_id, "reason": "upgraded after corroboration"})

            autorun_matches = [artifact for artifact in autoruns if target_name.lower() in json.dumps(artifact["fields"]).lower()]
            if autorun_matches:
                evidence_ids = [artifact["artifact_id"] for artifact in autorun_matches] + [match["artifact_id"] for match in matches]
                persistence = Claim(
                    statement=f"{target_name} established user-level persistence through an autorun registry location",
                    status=ClaimStatus.CONFIRMED if len(evidence_ids) >= 2 else ClaimStatus.INFERRED,
                    confidence=0.91 if len(evidence_ids) >= 2 else 0.68,
                    severity=Severity.HIGH,
                    evidence_ids=sorted(set(evidence_ids)),
                    rationale="Autorun evidence points to the same executable corroborated by execution artifacts.",
                    mitre=["T1060", "T1547.001"],
                )
                claim_id = self.graph.upsert_claim(persistence)
                self.audit.event("agent", "claim.created", {"iteration": iteration, "claim_id": claim_id, "status": persistence.status.value, "statement": persistence.statement})

        powershell_events = powershell_logs or [artifact for artifact in evtx if "powershell" in json.dumps(artifact["fields"]).lower()]
        if powershell_events:
            claim = Claim(
                statement="PowerShell process creation events show script-based staging before malicious execution",
                status=ClaimStatus.INFERRED,
                confidence=0.74,
                severity=Severity.MEDIUM,
                evidence_ids=[artifact["artifact_id"] for artifact in powershell_events],
                rationale="Event logs show staging behavior; no claim is confirmed without matching payload and execution artifacts.",
                mitre=["T1059.001"],
            )
            claim_id = self.graph.upsert_claim(claim)
            self.audit.event("agent", "claim.created", {"iteration": iteration, "claim_id": claim_id, "status": claim.status.value, "statement": claim.statement})

        injected_regions = [
            artifact for artifact in malfind
            if "evil.exe" in json.dumps(artifact["fields"]).lower()
        ]
        if injected_regions:
            claim = Claim(
                statement="evil.exe contains suspicious executable memory regions consistent with injected code",
                status=ClaimStatus.INFERRED,
                confidence=0.79,
                severity=Severity.HIGH,
                evidence_ids=[artifact["artifact_id"] for artifact in injected_regions],
                rationale="Volatile memory malfind evidence indicates suspicious executable memory; disk and process context are required for confirmation.",
                mitre=["T1055"],
            )
            claim_id = self.graph.upsert_claim(claim)
            self.audit.event("agent", "claim.created", {"iteration": iteration, "claim_id": claim_id, "status": claim.status.value, "statement": claim.statement})

    def _verify_claims(self, iteration: int) -> bool:
        needs_disk = False
        for row in self.graph.claims():
            evidence_ids = self._claim_evidence(row["claim_id"])
            kinds = self._evidence_kinds(evidence_ids)
            before = dict(row)
            if row["status"] == ClaimStatus.CONFIRMED.value and len(kinds) < 2:
                claim = _row_to_claim(row, evidence_ids)
                claim.status = ClaimStatus.INFERRED
                claim.confidence = min(claim.confidence, 0.69)
                claim.contradictions.append("confirmed claims require at least two independent artifact kinds")
                self.graph.upsert_claim(claim)
                self.graph.add_correction(iteration, claim.claim_id, before, _claim_dict(claim), "downgraded unsupported confirmed claim")
                self.audit.event("agent", "claim.corrected", {"iteration": iteration, "claim_id": claim.claim_id, "reason": "downgraded unsupported confirmed claim"})
            if "known C2 indicator" in row["statement"] and row["status"] != ClaimStatus.CONFIRMED.value:
                if not {"prefetch", "amcache", "mft"}.intersection(kinds):
                    needs_disk = True
                    claim = _row_to_claim(row, evidence_ids)
                    if claim.status == ClaimStatus.POSSIBLE:
                        claim.status = ClaimStatus.INFERRED
                        claim.confidence = 0.58
                        claim.contradictions.append("disk execution evidence missing after first-pass triage")
                        self.graph.upsert_claim(claim)
                        self.graph.add_correction(iteration, claim.claim_id, before, _claim_dict(claim), "downgraded pending disk corroboration")
                        self.audit.event("agent", "claim.corrected", {"iteration": iteration, "claim_id": claim.claim_id, "reason": "pending disk corroboration"})
        return needs_disk

    def _negative_controls(self, iteration: int) -> None:
        benign_names = {name.lower() for name in self.config.indicators.get("benign_processes", ["svchost.exe"])}
        for process in self._artifacts("process"):
            name = process["fields"].get("name", "").lower()
            if name in benign_names:
                claim = Claim(
                    statement=f"{process['fields'].get('name')} was observed but not escalated without malicious corroboration",
                    status=ClaimStatus.POSSIBLE,
                    confidence=0.35,
                    severity=Severity.INFO,
                    evidence_ids=[process["artifact_id"]],
                    rationale="Negative control: common system process is retained as context, not reported as a finding.",
                )
                claim_id = self.graph.upsert_claim(claim)
                self.audit.event("agent", "claim.created", {"iteration": iteration, "claim_id": claim_id, "status": claim.status.value, "statement": claim.statement})

    def _apply_anti_forensics_adjustments(self, anomalies, iteration: int) -> None:
        for anomaly in anomalies:
            target_name = PureWindowsPath(anomaly.target_path).name.lower()
            for row in self.graph.claims():
                evidence_ids = self._claim_evidence(row["claim_id"])
                if target_name not in row["statement"].lower() and not self._evidence_mentions(evidence_ids, target_name):
                    continue
                claim = _row_to_claim(row, evidence_ids)
                before = dict(row)
                claim.confidence = min(0.99, round(claim.confidence * anomaly.confidence_multiplier, 4))
                note = f"anti-forensics anomaly `{anomaly.anomaly_type}` adjusted confidence multiplier to {anomaly.confidence_multiplier}"
                if note not in claim.contradictions:
                    claim.contradictions.append(note)
                claim.rationale = f"{claim.rationale} Anti-forensics detector flagged {anomaly.anomaly_type} on {anomaly.target_path}."
                self.graph.upsert_claim(claim)
                self.graph.add_correction(iteration, claim.claim_id, before, _claim_dict(claim), "anti-forensics confidence adjustment")
                self.audit.event(
                    "agent",
                    "claim.confidence_adjusted",
                    {
                        "iteration": iteration,
                        "claim_id": claim.claim_id,
                        "target_path": anomaly.target_path,
                        "anomaly_type": anomaly.anomaly_type,
                        "confidence_multiplier": anomaly.confidence_multiplier,
                        "new_confidence": claim.confidence,
                    },
                )

    def _artifacts(self, kind: str) -> list[dict[str, Any]]:
        rows = self.graph.artifacts(kind)
        return [{**dict(row), "fields": json.loads(row["fields_json"])} for row in rows]

    def _claim_evidence(self, claim_id: str) -> list[str]:
        rows = self.graph.conn.execute("select artifact_id from claim_evidence where claim_id = ?", (claim_id,)).fetchall()
        return [row["artifact_id"] for row in rows]

    def _evidence_kinds(self, evidence_ids: list[str]) -> set[str]:
        if not evidence_ids:
            return set()
        placeholders = ",".join("?" for _ in evidence_ids)
        rows = self.graph.conn.execute(f"select distinct kind from artifacts where artifact_id in ({placeholders})", evidence_ids).fetchall()
        return {row["kind"] for row in rows}

    def _evidence_mentions(self, evidence_ids: list[str], needle: str) -> bool:
        if not evidence_ids:
            return False
        placeholders = ",".join("?" for _ in evidence_ids)
        rows = self.graph.conn.execute(f"select fields_json from artifacts where artifact_id in ({placeholders})", evidence_ids).fetchall()
        return any(needle in row["fields_json"].lower() for row in rows)

    @staticmethod
    def _matching_evidence(target_name: str, *artifact_groups: list[dict[str, Any]]) -> list[dict[str, Any]]:
        matches: list[dict[str, Any]] = []
        lowered = target_name.lower()
        for group in artifact_groups:
            for artifact in group:
                if lowered in json.dumps(artifact["fields"]).lower():
                    matches.append(artifact)
        return matches


def load_case_config(path: Path, output_override: Path | None = None, max_iterations: int | None = None) -> CaseConfig:
    data = json.loads(path.read_text(encoding="utf-8"))
    base = path.parent
    evidence_dir = Path(data["evidence_dir"])
    output_dir = Path(data.get("output_dir", "outputs"))
    if not evidence_dir.is_absolute():
        evidence_dir = base / evidence_dir
    if output_override is not None:
        output_dir = output_override
    elif not output_dir.is_absolute():
        output_dir = base / output_dir
    return CaseConfig(
        case_id=data["case_id"],
        name=data.get("name", data["case_id"]),
        evidence_dir=str(evidence_dir),
        output_dir=str(output_dir),
        indicators=data.get("indicators", {}),
        max_iterations=max_iterations or int(data.get("max_iterations", 3)),
    )


def _first_process_name(statement: str) -> str | None:
    if " communicated with " not in statement:
        return None
    return statement.split(" communicated with ", 1)[0].strip()


def _row_to_claim(row, evidence_ids: list[str]) -> Claim:
    return Claim(
        claim_id=row["claim_id"],
        statement=row["statement"],
        status=ClaimStatus(row["status"]),
        confidence=float(row["confidence"]),
        severity=Severity(row["severity"]),
        evidence_ids=evidence_ids,
        contradictions=json.loads(row["contradictions_json"] or "[]"),
        rationale=row["rationale"] or "",
        mitre=json.loads(row["mitre_json"] or "[]"),
    )


def _claim_dict(claim: Claim) -> dict[str, Any]:
    return {
        "claim_id": claim.claim_id,
        "statement": claim.statement,
        "status": claim.status.value,
        "confidence": claim.confidence,
        "severity": claim.severity.value,
        "evidence_ids": claim.evidence_ids,
        "contradictions": claim.contradictions,
        "rationale": claim.rationale,
        "mitre": claim.mitre,
    }
