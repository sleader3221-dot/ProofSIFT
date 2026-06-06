from __future__ import annotations

import json
import os
import platform
import shutil
from pathlib import Path

from .audit import AuditLogger
from .graph import EvidenceGraph
from .models import Artifact, CapabilityCheck, ToolResult


class AdvancedCollectorRegistry:
    """Capability-gated adapters for optional native forensic platforms."""

    def __init__(
        self,
        evidence_dir: Path,
        output_dir: Path,
        graph: EvidenceGraph,
        audit: AuditLogger,
    ):
        self.evidence_dir = evidence_dir
        self.output_dir = output_dir
        self.graph = graph
        self.audit = audit

    def inspect(self) -> list[CapabilityCheck]:
        checks = [self._ghidra_capability(), self._ebpf_capability()]
        for check in checks:
            self.graph.add_capability_check(check)
            self.audit.event(
                "advanced_collector",
                "capability.checked",
                {
                    "capability": check.capability,
                    "status": check.status,
                    "provider": check.provider,
                    "mode": check.mode,
                    "details": check.details,
                },
            )
        self._import_ebpf_fixture()
        return checks

    def _ghidra_capability(self) -> CapabilityCheck:
        ghidra_home = os.environ.get("GHIDRA_HOME", "")
        candidates = []
        if ghidra_home:
            candidates.extend(
                [
                    Path(ghidra_home) / "support" / "analyzeHeadless",
                    Path(ghidra_home) / "support" / "analyzeHeadless.bat",
                ]
            )
        path_match = shutil.which("analyzeHeadless") or shutil.which("analyzeHeadless.bat")
        executable = next((str(path) for path in candidates if path.exists()), path_match or "")
        available = bool(executable)
        return CapabilityCheck(
            capability="ghidra_headless",
            status="AVAILABLE" if available else "UNAVAILABLE",
            provider="Ghidra analyzeHeadless",
            executable=executable,
            mode="manual_opt_in_read_only",
            details={
                "automatic_execution": False,
                "reason": (
                    "Adapter detected; binary analysis requires explicit analyst opt-in."
                    if available
                    else "Set GHIDRA_HOME or place analyzeHeadless on PATH."
                ),
                "output_boundary": str(self.output_dir / "ghidra"),
            },
        )

    def _ebpf_capability(self) -> CapabilityCheck:
        executable = shutil.which("bpftool") or ""
        linux = platform.system().lower() == "linux"
        available = linux and bool(executable)
        return CapabilityCheck(
            capability="ebpf_telemetry",
            status="AVAILABLE" if available else "UNAVAILABLE",
            provider="Linux bpftool",
            executable=executable,
            mode="read_only_import",
            details={
                "kernel_program_loading": False,
                "reason": (
                    "bpftool detected; ProofSIFT imports pre-collected telemetry only."
                    if available
                    else "Requires Linux with bpftool; Windows runs degrade gracefully."
                ),
                "fixture": str(self.evidence_dir / "ebpf_events.jsonl"),
            },
        )

    def _import_ebpf_fixture(self) -> None:
        fixture = self.evidence_dir / "ebpf_events.jsonl"
        if not fixture.exists():
            return
        artifacts: list[Artifact] = []
        lines = fixture.read_text(encoding="utf-8").splitlines()
        for line_number, line in enumerate(lines, 1):
            try:
                fields = json.loads(line)
            except json.JSONDecodeError as exc:
                fields = {"line_number": line_number, "parser_error": str(exc), "raw": line}
            artifacts.append(
                Artifact(
                    kind="ebpf_telemetry",
                    source="ebpf_import",
                    fields=fields,
                    command_id="advanced-collector-ebpf-import",
                )
            )
        self.graph.record_tool_result(
            ToolResult(
                command_id="advanced-collector-ebpf-import",
                tool_name="ebpf_telemetry_import",
                ok=True,
                artifacts=artifacts,
                summary="Imported pre-collected eBPF JSONL telemetry without loading a kernel program.",
            )
        )
        self.audit.event(
            "advanced_collector",
            "ebpf.imported",
            {
                "records": len(artifacts),
                "source": str(fixture),
                "kernel_program_loading": False,
            },
        )
