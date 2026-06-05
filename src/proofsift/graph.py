from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any
from uuid import uuid4

from .integrity import artifact_content_hash
from .models import (
    AntiForensicsAnomaly,
    Artifact,
    BayesianScore,
    BmcResult,
    Claim,
    ClaimStatus,
    ClockDrift,
    CounterfactualCheck,
    EntropyAnalysis,
    SequenceRecommendation,
    Severity,
    ToolAuthorization,
    ToolResult,
)
from .time_utils import TIMESTAMP_FIELDS, format_utc, parse_utc


class EvidenceGraph:
    """SQLite-backed provenance graph for commands, artifacts, claims, and corrections."""

    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self._init()

    def close(self) -> None:
        self.conn.close()

    def _init(self) -> None:
        self.conn.executescript(
            """
            create table if not exists tool_runs (
                command_id text primary key,
                tool_name text not null,
                ok integer not null,
                summary text,
                warnings_json text,
                error text,
                duration_ms integer not null
            );
            create table if not exists artifacts (
                artifact_id text primary key,
                kind text not null,
                source text not null,
                command_id text not null,
                fields_json text not null,
                content_sha256 text
            );
            create table if not exists claims (
                claim_id text primary key,
                statement text not null,
                status text not null,
                confidence real not null,
                severity text not null,
                rationale text,
                contradictions_json text,
                mitre_json text
            );
            create table if not exists claim_evidence (
                claim_id text not null,
                artifact_id text not null,
                primary key (claim_id, artifact_id)
            );
            create table if not exists corrections (
                correction_id text primary key,
                iteration integer not null,
                claim_id text,
                before_json text,
                after_json text,
                reason text not null
            );
            create table if not exists observations (
                observation_id text primary key,
                artifact_id text not null,
                kind text not null,
                source text not null,
                timestamp_field text not null,
                observed_utc text not null,
                normalized_utc text not null,
                drift_seconds integer not null default 0,
                confidence real not null,
                notes text
            );
            create table if not exists clock_drifts (
                drift_id text primary key,
                source text not null,
                reference_source text not null,
                delta_seconds integer not null,
                anchor_observation_id text not null,
                reference_observation_id text not null,
                confidence real not null,
                reason text not null
            );
            create table if not exists anomalies (
                anomaly_id text primary key,
                kind text not null,
                target text not null,
                severity text not null,
                confidence_multiplier real not null,
                evidence_json text not null,
                details_json text not null
            );
            create table if not exists sequence_recommendations (
                recommendation_id text primary key,
                gap_type text not null,
                reason text not null,
                target_claim_id text not null,
                required_tactics_json text not null,
                recommended_tools_json text not null,
                recommended_paths_json text not null,
                priority text not null
            );
            create table if not exists bayesian_scores (
                score_id text primary key,
                claim_id text not null,
                prior real not null,
                likelihood_given_h real not null,
                likelihood_given_not_h real not null,
                evidence_probability real not null,
                posterior real not null,
                evidence_kinds_json text not null,
                signals_json text not null,
                explanation text not null,
                model_version text not null
            );
            create table if not exists counterfactual_checks (
                check_id text primary key,
                claim_id text not null,
                hypothesis text not null,
                status text not null,
                required_artifacts_json text not null,
                present_artifacts_json text not null,
                missing_artifacts_json text not null,
                action text not null,
                reason text not null
            );
            create table if not exists bmc_results (
                result_id text primary key,
                check_name text not null,
                status text not null,
                severity text not null,
                target text not null,
                timeline_validity real not null,
                evidence_json text not null,
                contradiction text not null,
                details_json text not null
            );
            create table if not exists entropy_analyses (
                analysis_id text primary key,
                target_path text not null,
                verdict text not null,
                severity text not null,
                entropy_bits real not null,
                baseline_delta_seconds_per_record real not null,
                target_delta_seconds_per_record real not null,
                evidence_json text not null,
                details_json text not null
            );
            create table if not exists tool_authorizations (
                authorization_id text primary key,
                command_id text not null,
                tool_name text not null,
                nonce_hash text not null,
                payload_hash text not null,
                signature text not null,
                status text not null,
                schema_valid integer not null,
                issued_at_utc text not null,
                expires_at_utc text not null
            );
            create index if not exists idx_observations_source_normalized
                on observations(source, normalized_utc);
            create index if not exists idx_observations_artifact
                on observations(artifact_id);
            """
        )
        self._migrate_schema()
        self.conn.commit()

    def _migrate_schema(self) -> None:
        artifact_columns = {row["name"] for row in self.conn.execute("pragma table_info(artifacts)")}
        if "content_sha256" not in artifact_columns:
            self.conn.execute("alter table artifacts add column content_sha256 text")

    def record_tool_result(self, result: ToolResult) -> list[str]:
        self.conn.execute(
            """
            insert or replace into tool_runs
            values (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                result.command_id,
                result.tool_name,
                1 if result.ok else 0,
                result.summary,
                json.dumps(result.warnings),
                result.error,
                result.duration_ms,
            ),
        )
        artifact_ids = [self.add_artifact(artifact) for artifact in result.artifacts]
        self.conn.commit()
        return artifact_ids

    def add_artifact(self, artifact: Artifact) -> str:
        artifact_id = artifact.artifact_id or f"art-{uuid4().hex[:12]}"
        content_hash = artifact_content_hash(artifact.kind, artifact.source, artifact.command_id, artifact.fields)
        self.conn.execute(
            """
            insert or replace into artifacts
            (artifact_id, kind, source, command_id, fields_json, content_sha256)
            values (?, ?, ?, ?, ?, ?)
            """,
            (
                artifact_id,
                artifact.kind,
                artifact.source,
                artifact.command_id,
                json.dumps(artifact.fields, sort_keys=True),
                content_hash,
            ),
        )
        self._add_observations(artifact_id, artifact)
        return artifact_id

    def upsert_claim(self, claim: Claim) -> str:
        claim_id = claim.claim_id or f"clm-{uuid4().hex[:12]}"
        claim.claim_id = claim_id
        self.conn.execute(
            """
            insert or replace into claims
            values (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                claim_id,
                claim.statement,
                claim.status.value if isinstance(claim.status, ClaimStatus) else claim.status,
                claim.confidence,
                claim.severity.value if isinstance(claim.severity, Severity) else claim.severity,
                claim.rationale,
                json.dumps(claim.contradictions),
                json.dumps(claim.mitre),
            ),
        )
        self.conn.execute("delete from claim_evidence where claim_id = ?", (claim_id,))
        for artifact_id in claim.evidence_ids:
            self.conn.execute(
                "insert or ignore into claim_evidence values (?, ?)",
                (claim_id, artifact_id),
            )
        self.conn.commit()
        return claim_id

    def add_correction(self, iteration: int, claim_id: str | None, before: dict[str, Any], after: dict[str, Any], reason: str) -> str:
        correction_id = f"cor-{uuid4().hex[:12]}"
        self.conn.execute(
            "insert into corrections values (?, ?, ?, ?, ?, ?)",
            (correction_id, iteration, claim_id, json.dumps(before, sort_keys=True), json.dumps(after, sort_keys=True), reason),
        )
        self.conn.commit()
        return correction_id

    def add_clock_drift(self, drift: ClockDrift) -> str:
        drift_id = drift.drift_id or f"drift-{uuid4().hex[:12]}"
        self.conn.execute(
            "insert or replace into clock_drifts values (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                drift_id,
                drift.source,
                drift.reference_source,
                drift.delta_seconds,
                drift.anchor_observation_id,
                drift.reference_observation_id,
                drift.confidence,
                drift.reason,
            ),
        )
        self.conn.commit()
        return drift_id

    def apply_clock_drift(self, source: str, delta_seconds: int) -> int:
        rows = self.conn.execute(
            "select observation_id, observed_utc from observations where source = ?",
            (source,),
        ).fetchall()
        updated = 0
        for row in rows:
            observed = parse_utc(row["observed_utc"])
            if not observed:
                continue
            normalized = observed.timestamp() + delta_seconds
            normalized_dt = parse_utc(format_utc_from_timestamp(normalized))
            if not normalized_dt:
                continue
            self.conn.execute(
                """
                update observations
                set normalized_utc = ?, drift_seconds = ?
                where observation_id = ?
                """,
                (format_utc(normalized_dt), delta_seconds, row["observation_id"]),
            )
            updated += 1
        self.conn.commit()
        return updated

    def add_anomaly(self, anomaly: AntiForensicsAnomaly, kind: str = "ANTI_FORENSICS") -> str:
        anomaly_id = anomaly.anomaly_id or f"anom-{uuid4().hex[:12]}"
        self.conn.execute(
            "insert or replace into anomalies values (?, ?, ?, ?, ?, ?, ?)",
            (
                anomaly_id,
                kind,
                anomaly.target_path,
                anomaly.severity.value if isinstance(anomaly.severity, Severity) else anomaly.severity,
                anomaly.confidence_multiplier,
                json.dumps(anomaly.evidence_ids, sort_keys=True),
                json.dumps({"type": anomaly.anomaly_type, **anomaly.details}, sort_keys=True),
            ),
        )
        self.conn.commit()
        return anomaly_id

    def add_sequence_recommendation(self, recommendation: SequenceRecommendation) -> str:
        recommendation_id = recommendation.recommendation_id or f"seq-{uuid4().hex[:12]}"
        self.conn.execute(
            "insert or replace into sequence_recommendations values (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                recommendation_id,
                recommendation.gap_type,
                recommendation.reason,
                recommendation.target_claim_id,
                json.dumps(recommendation.required_tactics, sort_keys=True),
                json.dumps(recommendation.recommended_tools, sort_keys=True),
                json.dumps(recommendation.recommended_paths, sort_keys=True),
                recommendation.priority.value if isinstance(recommendation.priority, Severity) else recommendation.priority,
            ),
        )
        self.conn.commit()
        return recommendation_id

    def add_bayesian_score(self, score: BayesianScore) -> str:
        score_id = score.score_id or f"bayes-{uuid4().hex[:12]}"
        self.conn.execute(
            "insert or replace into bayesian_scores values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                score_id,
                score.claim_id,
                score.prior,
                score.likelihood_given_h,
                score.likelihood_given_not_h,
                score.evidence_probability,
                score.posterior,
                json.dumps(score.evidence_kinds, sort_keys=True),
                json.dumps(score.signals, sort_keys=True),
                score.explanation,
                score.model_version,
            ),
        )
        self.conn.commit()
        return score_id

    def add_counterfactual_check(self, check: CounterfactualCheck) -> str:
        check_id = check.check_id or f"cf-{uuid4().hex[:12]}"
        self.conn.execute(
            "insert or replace into counterfactual_checks values (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                check_id,
                check.claim_id,
                check.hypothesis,
                check.status,
                json.dumps(check.required_artifacts, sort_keys=True),
                json.dumps(check.present_artifacts, sort_keys=True),
                json.dumps(check.missing_artifacts, sort_keys=True),
                check.action,
                check.reason,
            ),
        )
        self.conn.commit()
        return check_id

    def add_bmc_result(self, result: BmcResult) -> str:
        result_id = result.result_id or f"bmc-{uuid4().hex[:12]}"
        self.conn.execute(
            "insert or replace into bmc_results values (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                result_id,
                result.check_name,
                result.status,
                result.severity.value if isinstance(result.severity, Severity) else result.severity,
                result.target,
                result.timeline_validity,
                json.dumps(result.evidence_ids, sort_keys=True),
                result.contradiction,
                json.dumps(result.details, sort_keys=True),
            ),
        )
        self.conn.commit()
        return result_id

    def add_entropy_analysis(self, analysis: EntropyAnalysis) -> str:
        analysis_id = analysis.analysis_id or f"entropy-{uuid4().hex[:12]}"
        self.conn.execute(
            "insert or replace into entropy_analyses values (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                analysis_id,
                analysis.target_path,
                analysis.verdict,
                analysis.severity.value if isinstance(analysis.severity, Severity) else analysis.severity,
                analysis.entropy_bits,
                analysis.baseline_delta_seconds_per_record,
                analysis.target_delta_seconds_per_record,
                json.dumps(analysis.evidence_ids, sort_keys=True),
                json.dumps(analysis.details, sort_keys=True),
            ),
        )
        self.conn.commit()
        return analysis_id

    def add_tool_authorization(self, authorization: ToolAuthorization) -> str:
        authorization_id = authorization.authorization_id or f"auth-{uuid4().hex[:12]}"
        self.conn.execute(
            "insert or replace into tool_authorizations values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                authorization_id,
                authorization.command_id,
                authorization.tool_name,
                authorization.nonce_hash,
                authorization.payload_hash,
                authorization.signature,
                authorization.status,
                1 if authorization.schema_valid else 0,
                authorization.issued_at_utc,
                authorization.expires_at_utc,
            ),
        )
        self.conn.commit()
        return authorization_id

    def artifacts(self, kind: str | None = None) -> list[sqlite3.Row]:
        if kind:
            return list(self.conn.execute("select * from artifacts where kind = ?", (kind,)))
        return list(self.conn.execute("select * from artifacts"))

    def claims(self) -> list[sqlite3.Row]:
        return list(
            self.conn.execute(
                """
                select * from claims
                order by
                    case severity
                        when 'CRITICAL' then 5
                        when 'HIGH' then 4
                        when 'MEDIUM' then 3
                        when 'LOW' then 2
                        else 1
                    end desc,
                    confidence desc
                """
            )
        )

    def corrections(self) -> list[sqlite3.Row]:
        return list(self.conn.execute("select * from corrections order by iteration, correction_id"))

    def observations(self, source: str | None = None) -> list[sqlite3.Row]:
        if source:
            return list(self.conn.execute("select * from observations where source = ? order by normalized_utc", (source,)))
        return list(self.conn.execute("select * from observations order by normalized_utc"))

    def clock_drifts(self) -> list[sqlite3.Row]:
        return list(self.conn.execute("select * from clock_drifts order by drift_id"))

    def anomalies(self, kind: str | None = None) -> list[sqlite3.Row]:
        order = """
            order by
                case severity
                    when 'CRITICAL' then 5
                    when 'HIGH' then 4
                    when 'MEDIUM' then 3
                    when 'LOW' then 2
                    else 1
                end desc,
                confidence_multiplier desc
        """
        if kind:
            return list(self.conn.execute(f"select * from anomalies where kind = ? {order}", (kind,)))
        return list(self.conn.execute(f"select * from anomalies {order}"))

    def sequence_recommendations(self) -> list[sqlite3.Row]:
        return list(
            self.conn.execute(
                """
                select * from sequence_recommendations
                order by
                    case priority
                        when 'CRITICAL' then 5
                        when 'HIGH' then 4
                        when 'MEDIUM' then 3
                        when 'LOW' then 2
                        else 1
                    end desc,
                    recommendation_id
                """
            )
        )

    def bayesian_scores(self) -> list[sqlite3.Row]:
        return list(self.conn.execute("select * from bayesian_scores order by score_id"))

    def counterfactual_checks(self) -> list[sqlite3.Row]:
        return list(self.conn.execute("select * from counterfactual_checks order by check_id"))

    def bmc_results(self) -> list[sqlite3.Row]:
        return list(self.conn.execute("select * from bmc_results order by result_id"))

    def entropy_analyses(self) -> list[sqlite3.Row]:
        return list(self.conn.execute("select * from entropy_analyses order by analysis_id"))

    def tool_authorizations(self) -> list[sqlite3.Row]:
        return list(self.conn.execute("select * from tool_authorizations order by authorization_id"))

    def normalized_observations_between(
        self,
        start_utc: str,
        end_utc: str,
        sources: list[str] | None = None,
    ) -> list[sqlite3.Row]:
        if sources:
            placeholders = ",".join("?" for _ in sources)
            return list(
                self.conn.execute(
                    f"""
                    select * from observations
                    where normalized_utc between ? and ?
                    and source in ({placeholders})
                    order by normalized_utc
                    """,
                    [start_utc, end_utc, *sources],
                )
            )
        return list(
            self.conn.execute(
                """
                select * from observations
                where normalized_utc between ? and ?
                order by normalized_utc
                """,
                (start_utc, end_utc),
            )
        )

    def trace_claim(self, claim_id: str) -> dict[str, Any]:
        claim = self.conn.execute("select * from claims where claim_id = ?", (claim_id,)).fetchone()
        if not claim:
            raise KeyError(f"unknown claim id: {claim_id}")
        evidence_rows = self.conn.execute(
            """
            select a.*, t.tool_name, t.summary, t.duration_ms
            from claim_evidence ce
            join artifacts a on ce.artifact_id = a.artifact_id
            left join tool_runs t on a.command_id = t.command_id
            where ce.claim_id = ?
            """,
            (claim_id,),
        ).fetchall()
        return {
            "claim": dict(claim),
            "evidence": [
                {
                    **dict(row),
                    "fields": json.loads(row["fields_json"]),
                }
                for row in evidence_rows
            ],
        }

    def _add_observations(self, artifact_id: str, artifact: Artifact) -> None:
        for field, raw_value in artifact.fields.items():
            if field not in TIMESTAMP_FIELDS:
                continue
            parsed = parse_utc(raw_value)
            if not parsed:
                self.conn.execute(
                    """
                    insert or replace into observations
                    values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        f"obs-{uuid4().hex[:12]}",
                        artifact_id,
                        artifact.kind,
                        artifact.source,
                        field,
                        "1970-01-01T00:00:00Z",
                        "1970-01-01T00:00:00Z",
                        0,
                        0.0,
                        f"malformed timestamp: {raw_value}",
                    ),
                )
                continue
            observed = format_utc(parsed)
            self.conn.execute(
                """
                insert or replace into observations
                values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    f"obs-{uuid4().hex[:12]}",
                    artifact_id,
                    artifact.kind,
                    artifact.source,
                    field,
                    observed,
                    observed,
                    0,
                    1.0,
                    "",
                ),
            )


def format_utc_from_timestamp(timestamp: float) -> str:
    from datetime import datetime, timezone

    return format_utc(datetime.fromtimestamp(timestamp, tz=timezone.utc))
