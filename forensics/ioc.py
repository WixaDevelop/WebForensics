"""Indicator-of-compromise loading and matching.

Loads IOCs from CSV / JSON / line-delimited text files and matches them
against artifacts already in the ``SessionStore``. Supported IOC kinds:

* ``domain``    — substring match against host portion of URLs/cookies/logins
* ``url``       — exact prefix or full-URL match (case-insensitive)
* ``hash``      — SHA-256 / SHA-1 / MD5 comparison against downloads (the file
                  itself isn't on disk for a live extraction, so we match the
                  filename / URL where a hash might be embedded).
* ``ip``        — substring against URL/host
* ``email``     — substring against any text field
* ``username``  — substring against logins / autofill

This file is intentionally I/O-agnostic so it can be reused from CLI tools.
"""

from __future__ import annotations

import csv
import json
import logging
import re
import sqlite3
from pathlib import Path
from typing import Iterable, Iterator
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


_VALID_KINDS = ("domain", "url", "hash", "ip", "email", "username")
_VALID_SEVERITIES = ("info", "low", "medium", "high", "critical")
_HASH_RE = re.compile(r"^[A-Fa-f0-9]{32}(?:[A-Fa-f0-9]{8}(?:[A-Fa-f0-9]{24})?)?$")
_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def load_iocs_from_path(path: str | Path, default_severity: str = "medium") -> list[dict]:
    """Sniff the file format and return a normalised list of IOC dicts.

    Supported shapes:

    * ``.csv`` — header row with at least a ``value`` column (``kind``,
      ``severity``, ``source``, ``description`` optional).
    * ``.json`` — either a list of objects with the same fields, or a
      ``{"iocs": [...]}`` envelope.
    * Plain text — one IOC per line. Lines starting with ``#`` are skipped.
      ``kind`` is inferred from each entry (hash > ip > url > domain).
    """
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(p)
    text = p.read_text(encoding="utf-8", errors="replace")
    suffix = p.suffix.lower()

    if suffix == ".json":
        return _from_json(text, p.name, default_severity)
    if suffix == ".csv":
        return _from_csv(text, p.name, default_severity)
    return _from_text(text, p.name, default_severity)


def _from_json(text: str, source: str, default_severity: str) -> list[dict]:
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise ValueError(f"Invalid JSON in {source}: {exc}") from exc
    if isinstance(data, dict):
        entries = data.get("iocs") or data.get("indicators") or []
    elif isinstance(data, list):
        entries = data
    else:
        entries = []
    out: list[dict] = []
    for entry in entries:
        if isinstance(entry, str):
            out.append(_normalise(entry, source=source, default_severity=default_severity))
        elif isinstance(entry, dict):
            value = str(entry.get("value") or entry.get("indicator") or entry.get("ioc") or "").strip()
            if not value:
                continue
            out.append(_normalise(
                value,
                kind=entry.get("kind") or entry.get("type"),
                severity=entry.get("severity"),
                description=entry.get("description") or entry.get("comment", ""),
                source=source,
                default_severity=default_severity,
            ))
    return out


def _from_csv(text: str, source: str, default_severity: str) -> list[dict]:
    reader = csv.DictReader(text.splitlines())
    out: list[dict] = []
    for row in reader:
        value = str(row.get("value") or row.get("indicator") or "").strip()
        if not value or value.startswith("#"):
            continue
        out.append(_normalise(
            value,
            kind=row.get("kind") or row.get("type"),
            severity=row.get("severity"),
            description=row.get("description") or "",
            source=source,
            default_severity=default_severity,
        ))
    return out


def _from_text(text: str, source: str, default_severity: str) -> list[dict]:
    out: list[dict] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        out.append(_normalise(line, source=source, default_severity=default_severity))
    return out


def _normalise(
    value: str,
    kind: str | None = None,
    severity: str | None = None,
    description: str = "",
    source: str = "",
    default_severity: str = "medium",
) -> dict:
    value = value.strip()
    kind_str = (kind or "").strip().lower()
    if kind_str not in _VALID_KINDS:
        kind_str = _infer_kind(value)
    sev = (severity or "").strip().lower()
    if sev not in _VALID_SEVERITIES:
        sev = default_severity
    # Normalise the matching surface: lowercase domains/IPs, strip scheme/paths
    # off bare hosts so we can do substring matches reliably.
    if kind_str == "domain":
        value = _strip_to_host(value).lower()
    elif kind_str == "url":
        value = value.lower()
    elif kind_str in ("hash", "ip"):
        value = value.lower()
    return {
        "value": value,
        "kind": kind_str,
        "severity": sev,
        "source": source,
        "description": description,
    }


def _strip_to_host(value: str) -> str:
    if "://" in value:
        try:
            return urlparse(value).hostname or value
        except ValueError:
            return value
    # Drop trailing path / port if present.
    return value.split("/", 1)[0].split(":", 1)[0]


def _infer_kind(value: str) -> str:
    if _HASH_RE.match(value):
        return "hash"
    if _IP_RE.match(value):
        return "ip"
    if "@" in value and "." in value.split("@")[-1]:
        return "email"
    if "://" in value or value.startswith("/"):
        return "url"
    return "domain"


# ---------------------------------------------------------------------------
# Matching against the store
# ---------------------------------------------------------------------------


def _columns_for(kind: str) -> tuple[str, ...]:
    """Per-artifact column tuples — first element is the canonical 'host' field."""
    return {
        "history":   ("url", "title"),
        "cookies":   ("host", "name", "value"),
        "downloads": ("url", "target_path", "referrer", "mime_type"),
        "logins":    ("origin_url", "action_url", "username"),
        "bookmarks": ("url", "name", "folder"),
    }.get(kind, ())


def match_all(conn: sqlite3.Connection) -> int:
    """Re-run every IOC against every artifact. Returns the number of hits.

    Cheaper than streaming during ingest, and easier to re-do after the user
    changes the IOC list. Hits are written into ``ioc_hits``.
    """
    conn.execute("DELETE FROM ioc_hits")
    iocs = list(conn.execute("SELECT id, value, kind FROM iocs"))
    if not iocs:
        return 0
    total = 0
    artifact_tables = ("history", "cookies", "downloads", "logins", "bookmarks")
    for ioc in iocs:
        ioc_id = int(ioc["id"])
        value = (ioc["value"] or "").strip()
        kind = ioc["kind"]
        if not value:
            continue
        for table in artifact_tables:
            cols = _columns_for(table)
            if not cols:
                continue
            total += _match_in_table(conn, ioc_id, value, kind, table, cols)
    return total


def _match_in_table(
    conn: sqlite3.Connection,
    ioc_id: int,
    value: str,
    kind: str,
    table: str,
    cols: tuple[str, ...],
) -> int:
    """Insert ioc_hits rows for every match in *table*."""
    # All IOC kinds end up as substring matches; ``url`` allows partial / full.
    like_value = f"%{value}%"
    wheres = " OR ".join(f"LOWER({c}) LIKE ?" for c in cols)
    sql = f"SELECT id, profile_id, {', '.join(cols)} FROM {table} WHERE {wheres}"
    params = tuple(like_value for _ in cols)
    hits = 0
    for row in conn.execute(sql, params):
        artifact_id = int(row["id"])
        profile_id = int(row["profile_id"])
        matched_field, matched_value = _pick_match(row, cols, value)
        conn.execute(
            "INSERT INTO ioc_hits(ioc_id, artifact_kind, artifact_id, profile_id, "
            "matched_field, matched_value) VALUES(?, ?, ?, ?, ?, ?)",
            (ioc_id, table, artifact_id, profile_id, matched_field, matched_value),
        )
        hits += 1
    return hits


def _pick_match(row: sqlite3.Row, cols: tuple[str, ...], value: str) -> tuple[str, str]:
    needle = value.lower()
    for col in cols:
        cell = row[col]
        if cell and needle in str(cell).lower():
            return col, str(cell)
    return cols[0], str(row[cols[0]]) if row[cols[0]] is not None else ""


def hit_count_by_kind(conn: sqlite3.Connection) -> dict[str, int]:
    out: dict[str, int] = {}
    for row in conn.execute(
        "SELECT artifact_kind, COUNT(*) AS n FROM ioc_hits GROUP BY artifact_kind"
    ):
        out[row["artifact_kind"]] = int(row["n"] or 0)
    return out
