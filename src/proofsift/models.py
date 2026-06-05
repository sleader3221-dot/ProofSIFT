from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ClaimStatus(str, Enum):
    POSSIBLE = "POSSIBLE"
    INFERRED = "INFERRED"
    CONFIRMED = "CONFIRMED"
    CONTRADICTED = "CONTRADICTED"


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AnomalyKind(str, Enum):
    CLOCK_DRIFT = "CLOCK_DRIFT"
    ANTI_FORENSICS = "ANTI_FORENSICS"
    PARSER = "PARSER"
    SEQUENCE_GAP = "SEQUENCE_GAP"
    COUNTERFACTUAL = "COUNTERFACTUAL"
    BMC_CONSTRAINT = "BMC_CONSTRAINT"
    MFT_ENTROPY = "MFT_ENTROPY"


@dataclass(frozen=True)
class Artifact:
    kind: str
    source: str
    fields: dict[str, Any]
    command_id: str
    artifact_id: str | None = None


@dataclass
class Claim:
    statement: str
    status: ClaimStatus
    confidence: float
    severity: Severity
    evidence_ids: list[str] = field(default_factory=list)
    contradictions: list[str] = field(default_factory=list)
    rationale: str = ""
    mitre: list[str] = field(default_factory=list)
    claim_id: str | None = None


@dataclass(frozen=True)
class ClockDrift:
    source: str
    reference_source: str
    delta_seconds: int
    anchor_observation_id: str
    reference_observation_id: str
    confidence: float
    reason: str
    drift_id: str | None = None


@dataclass(frozen=True)
class AntiForensicsAnomaly:
    target_path: str
    anomaly_type: str
    confidence_multiplier: float
    severity: Severity
    evidence_ids: list[str]
    details: dict[str, Any]
    anomaly_id: str | None = None


@dataclass(frozen=True)
class SequenceRecommendation:
    gap_type: str
    reason: str
    target_claim_id: str
    required_tactics: list[str]
    recommended_tools: list[str]
    recommended_paths: list[str]
    priority: Severity
    recommendation_id: str | None = None


@dataclass(frozen=True)
class BayesianScore:
    claim_id: str
    prior: float
    likelihood_given_h: float
    likelihood_given_not_h: float
    evidence_probability: float
    posterior: float
    evidence_kinds: list[str]
    signals: list[str]
    explanation: str
    model_version: str = "bayesian-forensic-calculus-v1"
    score_id: str | None = None


@dataclass(frozen=True)
class CounterfactualCheck:
    claim_id: str
    hypothesis: str
    status: str
    required_artifacts: list[str]
    present_artifacts: list[str]
    missing_artifacts: list[str]
    action: str
    reason: str
    check_id: str | None = None


@dataclass(frozen=True)
class BmcResult:
    check_name: str
    status: str
    severity: Severity
    target: str
    timeline_validity: float
    evidence_ids: list[str]
    contradiction: str
    details: dict[str, Any]
    result_id: str | None = None


@dataclass(frozen=True)
class EntropyAnalysis:
    target_path: str
    verdict: str
    severity: Severity
    entropy_bits: float
    baseline_delta_seconds_per_record: float
    target_delta_seconds_per_record: float
    evidence_ids: list[str]
    details: dict[str, Any]
    analysis_id: str | None = None


@dataclass(frozen=True)
class ToolAuthorization:
    command_id: str
    tool_name: str
    nonce_hash: str
    payload_hash: str
    signature: str
    status: str
    schema_valid: bool
    issued_at_utc: str
    expires_at_utc: str
    authorization_id: str | None = None


@dataclass(frozen=True)
class ToolResult:
    command_id: str
    tool_name: str
    ok: bool
    artifacts: list[Artifact] = field(default_factory=list)
    summary: str = ""
    warnings: list[str] = field(default_factory=list)
    error: str | None = None
    duration_ms: int = 0


@dataclass(frozen=True)
class CaseConfig:
    case_id: str
    name: str
    evidence_dir: str
    output_dir: str
    indicators: dict[str, list[str]] = field(default_factory=dict)
    max_iterations: int = 3
