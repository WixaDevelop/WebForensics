"""Timestamp conversions for browser artifacts.

Each browser stores time in its own epoch:

* Chromium (WebKit): microseconds since 1601-01-01 UTC
* Firefox (PRTime):  microseconds since 1970-01-01 UTC
* Unix:              seconds since 1970-01-01 UTC
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

# Delta between 1601-01-01 (Windows/WebKit epoch) and 1970-01-01 (Unix epoch).
_WEBKIT_EPOCH_OFFSET_US = 11_644_473_600_000_000


def chromium_to_datetime(timestamp_us: Optional[int]) -> Optional[datetime]:
    """Convert a Chromium/WebKit microsecond timestamp to a UTC datetime."""
    if not timestamp_us:
        return None
    try:
        unix_us = int(timestamp_us) - _WEBKIT_EPOCH_OFFSET_US
        if unix_us < 0:
            return None
        return datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=unix_us)
    except (ValueError, OverflowError):
        return None


def firefox_to_datetime(timestamp_us: Optional[int]) -> Optional[datetime]:
    """Convert a Firefox PRTime microsecond timestamp to a UTC datetime."""
    if not timestamp_us:
        return None
    try:
        return datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=int(timestamp_us))
    except (ValueError, OverflowError):
        return None


def unix_to_datetime(timestamp_s: Optional[float]) -> Optional[datetime]:
    """Convert a Unix epoch (seconds) timestamp to a UTC datetime."""
    if timestamp_s in (None, 0):
        return None
    try:
        return datetime.fromtimestamp(float(timestamp_s), tz=timezone.utc)
    except (ValueError, OSError, OverflowError):
        return None


def format_dt(dt: Optional[datetime]) -> str:
    """Render a datetime as ISO-8601 (UTC) or empty string when missing."""
    if dt is None:
        return ""
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
