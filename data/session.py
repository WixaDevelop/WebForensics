"""High-level session manager around :class:`SessionStore`.

A *session* is just the SQLite database produced by ``SessionStore`` plus a
tiny ``__session__`` row inside ``meta``. Loading a session is therefore as
cheap as opening any other DB — no re-extraction needed.

The file extension is ``.wfs`` (Web Forensics Session) but it's a plain
SQLite database; analysts can poke at it with any SQLite browser too.
"""

from __future__ import annotations

import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from data.store import SessionStore


_SESSION_META_KEY = "__session__"
_SCHEMA_VERSION = 1


class Session:
    """Wraps a ``SessionStore`` with save/load semantics."""

    def __init__(self, store: SessionStore, path: Optional[Path] = None) -> None:
        self.store = store
        self.path = path  # ``None`` until saved or loaded explicitly

    # --- Factory ----------------------------------------------------------

    @classmethod
    def new(cls) -> "Session":
        return cls(SessionStore())

    @classmethod
    def open(cls, path: str | Path) -> "Session":
        target = Path(path)
        if not target.is_file():
            raise FileNotFoundError(target)
        store = SessionStore(target)
        if not _is_wfs_database(store):
            store.close()
            raise ValueError(
                f"{target} is not a WebForensics session file "
                "(missing __session__ marker)."
            )
        return cls(store, target)

    # --- Save -------------------------------------------------------------

    def save_as(self, path: str | Path) -> Path:
        """Persist the in-progress session to ``path``.

        We rely on ``VACUUM INTO`` so the written file is compact and the
        ``-wal`` / ``-shm`` sidecars are folded back into it. Falls back to
        a plain file copy on older SQLite versions.
        """
        target = Path(path)
        if target.suffix.lower() != SessionStore.SUFFIX:
            target = target.with_suffix(SessionStore.SUFFIX)
        self._stamp_meta()

        conn = self.store.connection()
        try:
            # ``VACUUM INTO`` requires the file to not exist yet.
            if target.exists():
                target.unlink()
            safe = str(target).replace("'", "''")
            conn.execute(f"VACUUM INTO '{safe}'")
        except Exception:  # noqa: BLE001 — fall back to a checkpoint+copy
            conn.execute("PRAGMA wal_checkpoint(FULL)")
            shutil.copy2(self.store.path, target)

        self.path = target
        return target

    def _stamp_meta(self) -> None:
        meta = {
            "schema_version": _SCHEMA_VERSION,
            "saved_at": datetime.now(timezone.utc).isoformat(),
        }
        self.store.connection().execute(
            "INSERT INTO meta(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (_SESSION_META_KEY, json.dumps(meta)),
        )

    # --- Close ------------------------------------------------------------

    def close(self) -> None:
        self.store.close()


def _is_wfs_database(store: SessionStore) -> bool:
    """Reject random SQLite files that happen to have a ``.wfs`` extension."""
    row = store.connection().execute(
        "SELECT value FROM meta WHERE key=?", (_SESSION_META_KEY,)
    ).fetchone()
    if row is not None:
        return True
    # Backwards compatibility: an unsaved DB that just has the artifact tables
    # but no marker can still be opened, but only if the expected schema exists.
    table = store.connection().execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='profiles'"
    ).fetchone()
    return table is not None
