"""Report signing — HMAC-SHA256 over files.

Defence-defensible reports need to be tamper-evident: anyone who opens the
PDF a year from now should be able to verify it's the same file the analyst
generated. We provide:

* ``sign_file(path, key)`` — compute HMAC-SHA256 of a file and write
  ``<path>.sig`` next to it containing ``<hex-digest>  <basename>``.
* ``verify_file(path, key)`` — recompute and compare against the sidecar.
* A *case key* — random 32-byte secret persisted at
  ``%LOCALAPPDATA%\\WebForensics\\case.key`` (generated on first run). The same
  machine can always verify what it signed; sharing the key with reviewers
  lets them verify too.

We deliberately avoid PGP / X.509 — they're powerful but require key
management most analysts won't set up. HMAC is enough for "did the bytes
change after signing": exactly the property courts ask about.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_CASE_KEY_BYTES = 32


def case_key_path() -> Path:
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~/.config")
    return Path(base) / "WebForensics" / "case.key"


def load_or_create_case_key() -> bytes:
    """Return the persistent per-machine case key, creating it on first use."""
    path = case_key_path()
    if path.is_file():
        try:
            return path.read_bytes()
        except OSError as exc:
            logger.debug("Could not read case key %s: %s", path, exc)
    path.parent.mkdir(parents=True, exist_ok=True)
    key = secrets.token_bytes(_CASE_KEY_BYTES)
    try:
        path.write_bytes(key)
    except OSError as exc:
        logger.warning("Could not persist case key %s: %s", path, exc)
    return key


def hmac_file(path: str | Path, key: bytes) -> str:
    """Stream a file through HMAC-SHA256 and return the hex digest."""
    h = hmac.new(key, digestmod=hashlib.sha256)
    with Path(path).open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sign_file(path: str | Path, key: Optional[bytes] = None) -> Path:
    """Write ``<path>.sig`` containing the file's HMAC and return its path."""
    if key is None:
        key = load_or_create_case_key()
    digest = hmac_file(path, key)
    sig_path = Path(str(path) + ".sig")
    sig_path.write_text(
        f"hmac-sha256={digest}\nfile={Path(path).name}\nbytes={Path(path).stat().st_size}\n",
        encoding="utf-8",
    )
    return sig_path


def verify_file(path: str | Path, key: Optional[bytes] = None) -> tuple[bool, str]:
    """Re-verify a sidecar signature. Returns ``(ok, detail)``."""
    target = Path(path)
    sig_path = Path(str(path) + ".sig")
    if not sig_path.is_file():
        return False, f"No signature file at {sig_path}"
    if key is None:
        key = load_or_create_case_key()
    declared = ""
    for line in sig_path.read_text(encoding="utf-8").splitlines():
        if line.startswith("hmac-sha256="):
            declared = line.split("=", 1)[1].strip()
            break
    if not declared:
        return False, "Signature file is malformed"
    computed = hmac_file(target, key)
    ok = hmac.compare_digest(declared, computed)
    return ok, (
        "Signature matches — file unaltered since signing."
        if ok else
        f"Mismatch: declared {declared[:16]}…, computed {computed[:16]}…"
    )
