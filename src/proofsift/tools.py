from __future__ import annotations

import csv
import json
import time
from pathlib import Path
from uuid import uuid4

from .audit import AuditLogger
from .graph import EvidenceGraph
from .models import Artifact, ToolResult
from .security import SafePathPolicy, file_mode, sha256_file


class ToolRunner:
    """Typed, read-only forensic tool facade.

    The demo parsers consume normalized CSV/text exports so the project is
    runnable anywhere. On SIFT, these same methods are the stable contract for
    wrapping real tools such as Volatility, Plaso, RegRipper, EvtxECmd, MFTECmd,
    AmcacheParser, and YARA.
    """

    def __init__(self, evidence_dir: Path, graph: EvidenceGraph, audit: AuditLogger, policy: SafePathPolicy, indicators: dict[str, list[str]] | None = None):
        self.evidence_dir = evidence_dir
        self.graph = graph
        self.audit = audit
        self.policy = policy
        self.indicators = indicators or {}

    def catalog(self) -> list[dict[str, str]]:
        return [
            {"name": "hash_all_evidence", "guardrail": "read-only hashing of registered evidence"},
            {"name": "spoliation_probe", "guardrail": "proves evidence-root writes are blocked"},
            {"name": "memory_pslist", "guardrail": "typed process artifacts"},
            {"name": "memory_psscan", "guardrail": "typed hidden-process artifacts"},
            {"name": "memory_netscan", "guardrail": "typed network artifacts"},
            {"name": "memory_malfind", "guardrail": "typed injected-memory artifacts"},
            {"name": "disk_prefetch", "guardrail": "typed execution artifacts"},
            {"name": "disk_amcache", "guardrail": "typed program inventory artifacts"},
            {"name": "disk_shimcache", "guardrail": "typed application-compatibility execution artifacts"},
            {"name": "registry_autoruns", "guardrail": "typed persistence artifacts"},
            {"name": "timeline_mft", "guardrail": "typed filesystem timeline artifacts"},
            {"name": "timeline_usn", "guardrail": "typed filesystem journal artifacts"},
            {"name": "windows_evtx", "guardrail": "typed event-log artifacts"},
            {"name": "windows_process_creation", "guardrail": "typed Security 4688 process-creation artifacts"},
            {"name": "powershell_logs", "guardrail": "typed PowerShell activity artifacts"},
            {"name": "yara_keyword_scan", "guardrail": "read-only textual IOC scanner"},
        ]

    def hash_all_evidence(self) -> ToolResult:
        command_id = self._command_id("hash_all_evidence")
        started = time.perf_counter()
        artifacts: list[Artifact] = []
        warnings: list[str] = []
        for path in sorted(p for p in self.evidence_dir.rglob("*") if p.is_file()):
            safe = self.policy.validate_read(path)
            artifacts.append(
                Artifact(
                    kind="evidence_hash",
                    source="hash_all_evidence",
                    command_id=command_id,
                    fields={
                        "path": str(safe),
                        "relative_path": str(safe.relative_to(self.evidence_dir.resolve())),
                        "size_bytes": safe.stat().st_size,
                        "sha256": sha256_file(safe),
                        "mode": file_mode(safe),
                    },
                )
            )
        if not artifacts:
            warnings.append("no evidence files found")
        return self._store(ToolResult(command_id, "hash_all_evidence", True, artifacts, f"hashed {len(artifacts)} evidence files", warnings, duration_ms=self._elapsed(started)))

    def spoliation_probe(self) -> ToolResult:
        command_id = self._command_id("spoliation_probe")
        started = time.perf_counter()
        ok = self.policy.assert_no_evidence_write()
        artifact = Artifact(
            kind="guardrail_test",
            source="spoliation_probe",
            command_id=command_id,
            fields={"evidence_writes_blocked": ok, "control": "attempted write validation inside evidence root"},
        )
        return self._store(ToolResult(command_id, "spoliation_probe", ok, [artifact], "evidence write probe blocked", duration_ms=self._elapsed(started)))

    def memory_pslist(self) -> ToolResult:
        return self._csv("processes.csv", "memory_pslist", "process", "pslist", ["pid", "name", "image_path"], source_filter={"source": "pslist"})

    def memory_psscan(self) -> ToolResult:
        return self._csv("processes.csv", "memory_psscan", "process", "psscan", ["pid", "name", "image_path"], source_filter={"source": "psscan"})

    def memory_netscan(self) -> ToolResult:
        return self._csv("netscan.csv", "memory_netscan", "network", "netscan", ["pid", "process", "remote_ip"])

    def memory_malfind(self) -> ToolResult:
        return self._csv("malfind.csv", "memory_malfind", "malfind", "malfind", ["pid", "process", "vad_start", "protection"])

    def disk_prefetch(self) -> ToolResult:
        return self._csv("prefetch.csv", "disk_prefetch", "prefetch", "prefetch", ["executable", "last_run_utc"])

    def disk_amcache(self) -> ToolResult:
        return self._csv("amcache.csv", "disk_amcache", "amcache", "amcache", ["file_name", "path", "sha256"])

    def disk_shimcache(self) -> ToolResult:
        return self._csv("shimcache.csv", "disk_shimcache", "shimcache", "shimcache", ["file_path", "last_modified_utc"])

    def registry_autoruns(self) -> ToolResult:
        return self._csv("autoruns.csv", "registry_autoruns", "autorun", "autoruns", ["name", "path", "registry_key"])

    def timeline_mft(self) -> ToolResult:
        return self._csv("mft.csv", "timeline_mft", "mft", "mft", ["path", "created_utc"])

    def timeline_usn(self) -> ToolResult:
        return self._csv("usn.csv", "timeline_usn", "usn", "usn", ["path", "reason", "time_utc"])

    def windows_evtx(self) -> ToolResult:
        return self._csv("evtx.csv", "windows_evtx", "evtx", "evtx", ["event_id", "time_utc", "message"])

    def windows_process_creation(self) -> ToolResult:
        return self._csv(
            "evtx.csv",
            "windows_process_creation",
            "process_creation",
            "security_4688",
            ["event_id", "time_utc", "message"],
            source_filter={"event_id": "4688"},
        )

    def powershell_logs(self) -> ToolResult:
        return self._csv(
            "evtx.csv",
            "powershell_logs",
            "powershell_log",
            "powershell",
            ["event_id", "time_utc", "message"],
            contains_any=["powershell"],
        )

    def yara_keyword_scan(self) -> ToolResult:
        command_id = self._command_id("yara_keyword_scan")
        started = time.perf_counter()
        keywords = [k.lower() for k in self.indicators.get("yara_keywords", ["mimikatz", "credential", "c2"])]
        artifacts: list[Artifact] = []
        for path in sorted(p for p in self.evidence_dir.rglob("*") if p.is_file() and p.suffix.lower() in {".txt", ".log", ".csv"}):
            safe = self.policy.validate_read(path)
            try:
                text = safe.read_text(encoding="utf-8", errors="ignore")
            except OSError as exc:
                return self._store(ToolResult(command_id, "yara_keyword_scan", False, error=str(exc), duration_ms=self._elapsed(started)))
            lowered = text.lower()
            for keyword in keywords:
                if keyword in lowered:
                    artifacts.append(
                        Artifact(
                            kind="yara_match",
                            source="keyword_yara",
                            command_id=command_id,
                            fields={"path": str(safe), "keyword": keyword, "rule": f"keyword_{keyword.replace(' ', '_')}"},
                        )
                    )
        return self._store(ToolResult(command_id, "yara_keyword_scan", True, artifacts, f"matched {len(artifacts)} keyword indicators", duration_ms=self._elapsed(started)))

    def _csv(
        self,
        filename: str,
        tool_name: str,
        kind: str,
        source: str,
        required_fields: list[str],
        source_filter: dict[str, str] | None = None,
        contains_any: list[str] | None = None,
    ) -> ToolResult:
        command_id = self._command_id(tool_name)
        started = time.perf_counter()
        path = self.evidence_dir / filename
        warnings: list[str] = []
        artifacts: list[Artifact] = []
        try:
            safe = self.policy.validate_read(path)
        except Exception as exc:
            return self._store(ToolResult(command_id, tool_name, False, error=str(exc), duration_ms=self._elapsed(started)))
        try:
            with safe.open("r", encoding="utf-8", newline="") as handle:
                reader = csv.DictReader(handle)
                missing = [field for field in required_fields if field not in (reader.fieldnames or [])]
                if missing:
                    artifacts.append(self._parser_anomaly(command_id, tool_name, safe, f"missing required fields: {missing}"))
                    return self._store(ToolResult(command_id, tool_name, False, artifacts, error=f"missing required fields: {missing}", duration_ms=self._elapsed(started)))
                for line_number, row in enumerate(reader, start=2):
                    if None in row:
                        warning = f"extra unnamed columns at line {line_number}"
                        warnings.append(warning)
                        artifacts.append(self._parser_anomaly(command_id, tool_name, safe, warning, line_number))
                        row.pop(None, None)
                    row_missing = [field for field in required_fields if not row.get(field)]
                    if row_missing:
                        warning = f"missing row values {row_missing} at line {line_number}"
                        warnings.append(warning)
                        artifacts.append(self._parser_anomaly(command_id, tool_name, safe, warning, line_number))
                        continue
                    if source_filter and any(row.get(key) != value for key, value in source_filter.items()):
                        continue
                    normalized = {key: (value or "").strip() for key, value in row.items()}
                    if contains_any:
                        row_text = json.dumps(normalized).lower()
                        if not any(needle.lower() in row_text for needle in contains_any):
                            continue
                    normalized["source_file"] = str(safe)
                    normalized["source_line"] = line_number
                    artifacts.append(Artifact(kind=kind, source=source, command_id=command_id, fields=normalized))
        except (csv.Error, OSError, UnicodeError) as exc:
            artifacts.append(self._parser_anomaly(command_id, tool_name, safe, str(exc)))
            return self._store(ToolResult(command_id, tool_name, False, artifacts, error=str(exc), duration_ms=self._elapsed(started)))
        if not artifacts:
            warnings.append(f"{filename} produced no {kind} artifacts")
        return self._store(ToolResult(command_id, tool_name, True, artifacts, f"parsed {len(artifacts)} {kind} artifacts from {filename}", warnings, duration_ms=self._elapsed(started)))

    @staticmethod
    def _parser_anomaly(command_id: str, tool_name: str, path: Path, message: str, line_number: int | None = None) -> Artifact:
        fields = {
            "tool_name": tool_name,
            "path": str(path),
            "message": message,
            "line_number": line_number,
        }
        return Artifact(kind="parser_anomaly", source=tool_name, command_id=command_id, fields=fields)

    def _store(self, result: ToolResult) -> ToolResult:
        artifact_ids = self.graph.record_tool_result(result)
        self.audit.event(
            "tool",
            "tool_result",
            {
                "command_id": result.command_id,
                "tool_name": result.tool_name,
                "ok": result.ok,
                "artifact_count": len(result.artifacts),
                "artifact_ids": artifact_ids,
                "summary": result.summary,
                "warnings": result.warnings,
                "error": result.error,
                "duration_ms": result.duration_ms,
                "estimated_token_usage": estimate_tokens(json.dumps(result.summary) + json.dumps(result.warnings)),
            },
        )
        return result

    @staticmethod
    def _command_id(tool_name: str) -> str:
        return f"cmd-{tool_name}-{uuid4().hex[:8]}"

    @staticmethod
    def _elapsed(started: float) -> int:
        return int((time.perf_counter() - started) * 1000)


def estimate_tokens(text: str) -> int:
    return max(1, len(text) // 4)
