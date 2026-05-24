"""Diff two ``.wfs`` sessions.

Common analyst question: "this profile was captured today and last month —
what changed?" The diff produces:

* Per-table counts (added / removed)
* Sample of new URLs / cookies / logins / tabs
* List of disappeared URLs (potential history clears between captures)

The diff is matched on logical identity rather than DB rowid:

* ``history``      — match by URL
* ``cookies``      — match by (host, name, path)
* ``downloads``    — match by (url, target_path, start_time)
* ``logins``       — match by (origin_url, username)
* ``bookmarks``    — match by URL
* ``open_tabs``    — match by (window_idx, tab_idx, url)
* ``permissions``  — match by (origin, permission)
"""

from __future__ import annotations

import logging
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class TableDiff:
    table: str
    added: list[dict] = field(default_factory=list)
    removed: list[dict] = field(default_factory=list)


@dataclass
class SessionDiff:
    left_path: Path
    right_path: Path
    tables: dict[str, TableDiff] = field(default_factory=dict)

    @property
    def summary(self) -> str:
        parts = []
        for name, td in self.tables.items():
            if td.added or td.removed:
                parts.append(f"{name}: +{len(td.added)} -{len(td.removed)}")
        return " | ".join(parts) if parts else "no changes"


_MATCH_KEYS: dict[str, tuple[str, ...]] = {
    "history":      ("url",),
    "cookies":      ("host", "name", "path"),
    "downloads":    ("url", "target_path", "start_time"),
    "logins":       ("origin_url", "username"),
    "bookmarks":    ("url",),
    "autofill":     ("field_name", "value"),
    "extensions":   ("extension_id",),
    "open_tabs":    ("window_idx", "tab_idx", "url"),
    "permissions":  ("origin", "permission"),
}


def compare_wfs(left: Path, right: Path) -> SessionDiff:
    """Return a ``SessionDiff`` for the two ``.wfs`` files."""
    left = Path(left)
    right = Path(right)
    if not left.is_file() or not right.is_file():
        raise FileNotFoundError(left if not left.is_file() else right)

    diff = SessionDiff(left_path=left, right_path=right)
    left_conn = _open_ro(left)
    right_conn = _open_ro(right)
    try:
        for table, keys in _MATCH_KEYS.items():
            try:
                left_rows = _select_table(left_conn, table)
                right_rows = _select_table(right_conn, table)
            except sqlite3.OperationalError:
                continue
            diff.tables[table] = _compute_diff(table, keys, left_rows, right_rows)
    finally:
        left_conn.close()
        right_conn.close()
    return diff


def _open_ro(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def _select_table(conn: sqlite3.Connection, table: str) -> list[sqlite3.Row]:
    return list(conn.execute(f"SELECT * FROM {table}"))


def _compute_diff(
    table: str,
    keys: tuple[str, ...],
    left_rows: list[sqlite3.Row],
    right_rows: list[sqlite3.Row],
) -> TableDiff:
    """Set-difference rows by *keys* and return what's new on each side."""
    def fingerprint(row: sqlite3.Row) -> tuple:
        return tuple(str(row[k]) if k in row.keys() and row[k] is not None else "" for k in keys)

    left_index = {fingerprint(r): r for r in left_rows}
    right_index = {fingerprint(r): r for r in right_rows}

    added = []
    removed = []
    for key, row in right_index.items():
        if key not in left_index:
            added.append({k: row[k] for k in row.keys() if k != "id"})
    for key, row in left_index.items():
        if key not in right_index:
            removed.append({k: row[k] for k in row.keys() if k != "id"})

    return TableDiff(table=table, added=added, removed=removed)
