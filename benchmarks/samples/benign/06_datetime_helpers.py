"""Datetime parsing and formatting utilities."""
from datetime import datetime, timezone, timedelta

def to_utc_iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()

def calculate_age_days(created_at: datetime) -> int:
    now = datetime.now(timezone.utc)
    diff = now - created_at.astimezone(timezone.utc)
    return diff.days
