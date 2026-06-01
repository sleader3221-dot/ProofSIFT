from __future__ import annotations

from datetime import datetime, timezone


TIMESTAMP_FIELDS = {
    "created_utc",
    "modified_utc",
    "first_seen",
    "first_run_utc",
    "last_run_utc",
    "time_utc",
}


def parse_utc(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def format_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def seconds_between(left: datetime, right: datetime) -> int:
    return int((left - right).total_seconds())

