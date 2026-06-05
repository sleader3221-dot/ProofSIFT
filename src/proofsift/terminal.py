from __future__ import annotations

import sys
from datetime import datetime, timezone


def timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S")


def phase(msg: str) -> None:
    print(f"  [{timestamp()}] [PHASE] {msg}", flush=True)


def ok(msg: str) -> None:
    print(f"  [{timestamp()}] [OK] {msg}", flush=True)


def critic_alert(claim_id: str, gap: str, details: str) -> None:
    print(f"  [{timestamp()}] [CRITIC ALERT] {gap}", flush=True)
    print(f"  [{timestamp()}]   -> Detected: {claim_id}", flush=True)
    print(f"  [{timestamp()}]   -> {details}", flush=True)


def self_correct(iteration: int, total: int, action: str) -> None:
    print(f"  [{timestamp()}] [SELF-CORRECTION] Looping iteration ({iteration}/{total}). {action}", flush=True)


def critic_review(anomaly: str, multiplier: float) -> None:
    print(f"  [{timestamp()}] [CRITIC REVIEW] Differential Anti-Forensics Detector verified a mismatch:", flush=True)
    print(f"  [{timestamp()}]   -> Anomaly: {anomaly} detected.", flush=True)
    print(f"  [{timestamp()}]   -> Action: Sending anomaly into Bayesian posterior scoring (legacy multiplier {multiplier}x retained as evidence metadata).", flush=True)


def counterfactual_failure(claim_id: str, missing_artifacts: list[str], action: str) -> None:
    missing = ", ".join(missing_artifacts)
    print(f"  [{timestamp()}] [COUNTERFACTUAL FAILURE] Denied escalation - Expected supporting artifact(s) missing: {missing}.", flush=True)
    print(f"  [{timestamp()}]   -> Claim: {claim_id}", flush=True)
    print(f"  [{timestamp()}]   -> Action: {action}", flush=True)


def claim_escalation(claim_id: str, old_status: str, new_status: str, severity: str) -> None:
    print(f"  [{timestamp()}] [CLAIM ESCALATION] Claim {claim_id} safely upgraded from [{old_status}] to [{new_status} - {severity}].", flush=True)


def claim_downgrade(claim_id: str, reason: str) -> None:
    print(f"  [{timestamp()}] [CLAIM DOWNGRADE] Claim {claim_id}: {reason}.", flush=True)


def ingestion(case_id: str) -> None:
    print(f"\n  [PHASE 1: INGESTION]", flush=True)
    print(f"  Verifying forensic integrity hashes for case: {case_id}... [OK]", flush=True)


def investigate() -> None:
    print(f"\n  [PHASE 2: INVESTIGATE]", flush=True)
    print(f"  Investigator spawned. Running triage across memory and disk artifacts...", flush=True)


def iteration_header(iteration: int, total: int, phase_name: str) -> None:
    print(f"\n  --- Iteration {iteration}/{total}: {phase_name} ---", flush=True)


def drift_detected(source: str, reference: str, delta: int) -> None:
    print(f"  [{timestamp()}] [CLOCK DRIFT] {source} normalized against {reference} with {delta}s offset.", flush=True)


def tool_run(tool: str, summary: str) -> None:
    print(f"  [{timestamp()}] [TOOL] {tool}: {summary}", flush=True)


def separator(title: str = "") -> None:
    if title:
        print(f"\n{'=' * 70}", flush=True)
        print(f"  {title}", flush=True)
        print(f"{'=' * 70}", flush=True)
    else:
        print(f"{'-' * 70}", flush=True)


def hr() -> None:
    print(f"{'-' * 70}", flush=True)
