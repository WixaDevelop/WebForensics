"""Append-only audit log of forensic actions.

Records every consequential action (open profile, extract, export, save
session) to a JSON Lines file inside the user's data directory. Lines are
never deleted or rewritten; that's what makes them defensible if questioned
later.

Each line:

::

    {
      "ts":     "2024-...Z",
      "actor":  "<windows username>",
      "action": "extract|export|open_session|open_image",
      "target": "<file path or profile id>",
      "extra":  { ... action-specific keys ... }
    }
"""

from __future__ import annotations

import getpass
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _default_log_path() -> Path:
    base = os.environ.get("LOCALAPPDATA") or os.environ.get("XDG_DATA_HOME") or str(Path.home())
    folder = Path(base) / "WebForensics"
    folder.mkdir(parents=True, exist_ok=True)
    return folder / "audit.log.jsonl"


class AuditLog:
    """Tiny wrapper that opens the log file fresh on every write."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else _default_log_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, action: str, target: str = "", **extra: Any) -> None:
        line = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "actor": _actor(),
            "action": action,
            "target": target,
            "extra": extra or {},
        }
        # Append-and-flush per record so a crash never loses the last event.
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(line, ensure_ascii=False) + "\n")

    def tail(self, n: int = 200) -> list[dict[str, Any]]:
        if not self.path.is_file():
            return []
        # Reading the full file is fine — these logs stay small in practice.
        with open(self.path, "r", encoding="utf-8") as fh:
            lines = fh.readlines()[-n:]
        out: list[dict[str, Any]] = []
        for raw in lines:
            raw = raw.strip()
            if not raw:
                continue
            try:
                out.append(json.loads(raw))
            except json.JSONDecodeError:
                continue
        return out


def _actor() -> str:
    try:
        return getpass.getuser()
    except Exception:  # noqa: BLE001
        return "unknown"
