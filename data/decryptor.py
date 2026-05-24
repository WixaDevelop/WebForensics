"""Chromium credential / cookie decryption (Windows).

Modern Chromium builds (M80+) wrap the user's saved secrets with AES-256-GCM
using a per-installation key. That key lives — base64+DPAPI-encrypted — inside
``Local State`` next to ``User Data``. We:

1.  Read ``os_crypt.encrypted_key`` from ``Local State``.
2.  Strip the ``DPAPI`` magic prefix, then call ``CryptUnprotectData`` to get
    the raw 32-byte AES key. This only works when the analysis runs under the
    same Windows account that originally encrypted it.
3.  For each ciphertext, peek at its 3-byte prefix:
        * ``v10``/``v11`` → AES-256-GCM. Layout is ``prefix || iv(12) || ct``,
          and the GCM tag is the last 16 bytes of ``ct``.
        * Anything else  → legacy DPAPI blob; ``CryptUnprotectData`` directly.

If decryption is unavailable (non-Windows, key mismatch, missing dependency)
``ChromiumDecryptor.decrypt`` returns ``None`` and the caller marks the value
as ``encrypted=True`` rather than crashing.
"""

from __future__ import annotations

import base64
import json
import logging
import sys
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# AES-GCM is provided by pycryptodome; DPAPI by pywin32. Both are Windows-only.
try:  # pragma: no cover — import guard
    from Crypto.Cipher import AES  # type: ignore[import-not-found]

    _HAS_CRYPTO = True
except Exception:  # noqa: BLE001 — any import failure disables decryption
    _HAS_CRYPTO = False

try:  # pragma: no cover — Windows-only
    import win32crypt  # type: ignore[import-not-found]

    _HAS_DPAPI = True
except Exception:  # noqa: BLE001
    _HAS_DPAPI = False


_DPAPI_PREFIX = b"DPAPI"
_GCM_PREFIXES = (b"v10", b"v11")
_GCM_IV_LEN = 12
_GCM_TAG_LEN = 16


def _dpapi_unprotect(blob: bytes) -> Optional[bytes]:
    """Unwrap a Windows DPAPI blob; returns ``None`` on failure."""
    if not _HAS_DPAPI:
        return None
    try:
        # CryptUnprotectData returns (description, plaintext).
        _, plaintext = win32crypt.CryptUnprotectData(blob, None, None, None, 0)
        return plaintext
    except Exception as exc:  # noqa: BLE001 — DPAPI raises pywintypes.error
        logger.debug("DPAPI unprotect failed: %s", exc)
        return None


class ChromiumDecryptor:
    """Decrypts Chromium-style ciphertexts for a given ``Local State`` file."""

    def __init__(self, local_state_path: str | Path) -> None:
        self.local_state_path = Path(local_state_path)
        self._key: Optional[bytes] = None
        self._available = False
        self._load_key()

    @property
    def available(self) -> bool:
        """True when decryption is possible (key loaded + crypto libs present)."""
        return self._available

    def _load_key(self) -> None:
        if sys.platform != "win32" or not (_HAS_CRYPTO and _HAS_DPAPI):
            return
        if not self.local_state_path.is_file():
            return
        try:
            data = json.loads(self.local_state_path.read_text(encoding="utf-8"))
            encrypted_key_b64 = data["os_crypt"]["encrypted_key"]
        except (OSError, ValueError, KeyError) as exc:
            logger.debug("Local State unreadable: %s", exc)
            return

        try:
            encrypted_key = base64.b64decode(encrypted_key_b64)
        except (ValueError, TypeError):
            return
        if not encrypted_key.startswith(_DPAPI_PREFIX):
            return

        key = _dpapi_unprotect(encrypted_key[len(_DPAPI_PREFIX):])
        if key and len(key) == 32:
            self._key = key
            self._available = True

    def decrypt(self, ciphertext: Optional[bytes]) -> Optional[bytes]:
        """Return plaintext bytes, or ``None`` when the value cannot be decrypted."""
        if not ciphertext:
            return b"" if ciphertext == b"" else None

        prefix = bytes(ciphertext[:3])
        if prefix in _GCM_PREFIXES:
            if not (self._available and _HAS_CRYPTO and self._key):
                return None
            try:
                iv = ciphertext[3:3 + _GCM_IV_LEN]
                payload = ciphertext[3 + _GCM_IV_LEN:]
                if len(payload) < _GCM_TAG_LEN:
                    return None
                ct, tag = payload[:-_GCM_TAG_LEN], payload[-_GCM_TAG_LEN:]
                cipher = AES.new(self._key, AES.MODE_GCM, nonce=iv)
                return cipher.decrypt_and_verify(ct, tag)
            except Exception as exc:  # noqa: BLE001 — any failure means undecryptable
                logger.debug("AES-GCM decrypt failed: %s", exc)
                return None

        # Legacy: a raw DPAPI blob.
        return _dpapi_unprotect(bytes(ciphertext))

    def decrypt_text(self, ciphertext: Optional[bytes]) -> Optional[str]:
        """Convenience wrapper that decodes the plaintext as UTF-8."""
        plain = self.decrypt(ciphertext)
        if plain is None:
            return None
        try:
            return plain.decode("utf-8", errors="replace")
        except UnicodeDecodeError:
            return None
