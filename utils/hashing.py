"""SHA-256 helpers for chain-of-custody.

Forensic best practice: record a hash of every source file we read so a third
party can prove we didn't tamper with the evidence. We stream the file so
multi-gigabyte images don't blow up memory.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Iterable

_CHUNK = 1 << 20  # 1 MiB


def sha256_file(path: str | Path) -> str:
    """Stream-hash a single file, returning lower-case hex digest."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(_CHUNK)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def sha256_many(paths: Iterable[str | Path]) -> dict[str, str]:
    """Convenience: ``{path_str: digest}`` for an iterable of paths."""
    return {str(p): sha256_file(p) for p in paths}
