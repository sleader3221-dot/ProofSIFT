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
