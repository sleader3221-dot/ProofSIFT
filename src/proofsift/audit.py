from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4


class AuditLogger:
    """Append-only JSONL audit stream used by CLI, tools, and agent loops."""

    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def event(self, actor: str, action: str, details: dict[str, Any] | None = None) -> str:
        event_id = f"evt-{uuid4().hex[:12]}"
        record = {
            "event_id": event_id,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "actor": actor,
            "action": action,
            "details": details or {},
        }
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
        return event_id

    def timed(self, actor: str, action: str, details: dict[str, Any] | None = None):
        return _TimedAudit(self, actor, action, details or {})


class _TimedAudit:
    def __init__(self, logger: AuditLogger, actor: str, action: str, details: dict[str, Any]):
        self.logger = logger
        self.actor = actor
        self.action = action
        self.details = details
        self.started = 0.0

    def __enter__(self):
        self.started = time.perf_counter()
        self.logger.event(self.actor, f"{self.action}.start", self.details)
        return self

    def __exit__(self, exc_type, exc, _tb):
        details = dict(self.details)
        details["duration_ms"] = int((time.perf_counter() - self.started) * 1000)
        if exc:
            details["error"] = str(exc)
            self.logger.event(self.actor, f"{self.action}.error", details)
            return False
        self.logger.event(self.actor, f"{self.action}.end", details)
        return False

