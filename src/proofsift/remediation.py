from __future__ import annotations

import re

from .audit import AuditLogger
from .graph import EvidenceGraph
from .models import RemediationPlaybook


class RemediationOrchestrator:
    """Generate analyst-reviewed containment playbooks without executing commands."""

    def __init__(self, graph: EvidenceGraph, audit: AuditLogger):
        self.graph = graph
        self.audit = audit

    def generate(self) -> list[RemediationPlaybook]:
        playbooks: list[RemediationPlaybook] = []
        for claim in self.graph.claims():
            if claim["status"] != "CONFIRMED":
                continue
            statement = claim["statement"]
            steps = self._steps(statement)
            if not steps:
                continue
            playbook = RemediationPlaybook(
                claim_id=claim["claim_id"],
                title=f"Containment playbook for {claim['claim_id']}",
                execution_mode="generate_only",
                requires_approval=True,
                steps=steps,
                validation=[
                    "Verify the indicator and host scope against the evidence trace.",
                    "Run commands in a controlled incident-response session with change approval.",
                    "Re-collect volatile and persistence artifacts after containment.",
                ],
                rollback=[
                    "Remove temporary firewall rules after eradication validation.",
                    "Restore registry values only from a trusted pre-incident baseline.",
                ],
            )
            playbook_id = self.graph.add_remediation_playbook(playbook)
            playbooks.append(playbook)
            self.audit.event(
                "remediation",
                "playbook.generated",
                {
                    "playbook_id": playbook_id,
                    "claim_id": claim["claim_id"],
                    "execution_mode": "generate_only",
                    "requires_approval": True,
                    "step_count": len(steps),
                },
            )
        return playbooks

    @staticmethod
    def _steps(statement: str) -> list[dict[str, object]]:
        steps: list[dict[str, object]] = []
        ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", statement)
        exe_match = re.search(r"\b[\w.-]+\.exe\b", statement, re.IGNORECASE)
        if ip_match:
            ip = ip_match.group(0)
            steps.append(
                {
                    "order": len(steps) + 1,
                    "action": "isolate_network_indicator",
                    "command": (
                        "New-NetFirewallRule -DisplayName 'ProofSIFT Temporary IOC Block' "
                        f"-Direction Outbound -RemoteAddress {ip} -Action Block"
                    ),
                    "destructive": False,
                    "requires_approval": True,
                }
            )
        if exe_match:
            executable = exe_match.group(0)
            steps.append(
                {
                    "order": len(steps) + 1,
                    "action": "inspect_process_before_containment",
                    "command": f"Get-Process -Name '{executable[:-4]}' -ErrorAction SilentlyContinue",
                    "destructive": False,
                    "requires_approval": True,
                }
            )
            steps.append(
                {
                    "order": len(steps) + 1,
                    "action": "stop_confirmed_process",
                    "command": (
                        f"Stop-Process -Name '{executable[:-4]}' -Force "
                        "-WhatIf"
                    ),
                    "destructive": True,
                    "requires_approval": True,
                    "safety": "WhatIf is retained; remove it only after analyst approval.",
                }
            )
        if "autorun" in statement.lower() or "persistence" in statement.lower():
            steps.append(
                {
                    "order": len(steps) + 1,
                    "action": "inspect_autorun",
                    "command": (
                        "Get-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'"
                    ),
                    "destructive": False,
                    "requires_approval": True,
                }
            )
        return steps
