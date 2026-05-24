"""Firefox login decryption via NSS.

Firefox keeps the *encrypted* username/password as BER-encoded blobs in
``logins.json``. The key used to AES-decrypt those blobs lives in
``key4.db`` and is itself wrapped by a derivation of the user's master
password (an empty string when none is set).

We don't want to re-implement NSS by hand, so the strategy is to *borrow*
the ``nss3`` shared library that ships with the analyst's Firefox install:

1.  Find ``nss3.dll`` (Windows) / ``libnss3.so`` next to ``firefox.exe``.
2.  Load it with ``ctypes`` and bind ``NSS_Init``, ``PK11_GetInternalKeySlot``,
    ``PK11_Authenticate``, ``PK11SDR_Decrypt``, ``NSS_Shutdown``.
3.  Initialise NSS against the profile directory; that loads ``key4.db``.
4.  Decrypt each entry's blob.

If NSS can't be found, the decryptor reports itself as ``available = False``
and the caller falls back to the encrypted=True placeholder.

Caveats
~~~~~~~
* Master-password-protected profiles need the password passed in.
* NSS is **not** thread-safe between profiles — init/shutdown must wrap each
  use, which is what :meth:`decrypt_logins` does.
"""

from __future__ import annotations

import base64
import ctypes
import json
import logging
import os
import sys
from ctypes import (
    POINTER,
    Structure,
    byref,
    c_char_p,
    c_int,
    c_uint,
    c_ulong,
    c_void_p,
)
from pathlib import Path
from typing import Iterable, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# NSS C bindings — only enough surface to do SDR decryption.
# ---------------------------------------------------------------------------


class _SECItem(Structure):
    _fields_ = [("type", c_uint), ("data", c_void_p), ("len", c_uint)]


def _candidate_lib_paths() -> list[Path]:
    """Look in well-known Firefox install dirs and fall back to PATH."""
    candidates: list[Path] = []
    if sys.platform == "win32":
        for base in (
            os.environ.get("PROGRAMFILES", r"C:\Program Files"),
            os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)"),
        ):
            if base:
                candidates.append(Path(base) / "Mozilla Firefox" / "nss3.dll")
                candidates.append(Path(base) / "Firefox Developer Edition" / "nss3.dll")
    elif sys.platform == "darwin":
        candidates.extend([
            Path("/Applications/Firefox.app/Contents/MacOS/libnss3.dylib"),
        ])
    else:
        candidates.extend([
            Path("/usr/lib/firefox/libnss3.so"),
            Path("/usr/lib64/firefox/libnss3.so"),
            Path("/snap/firefox/current/usr/lib/firefox/libnss3.so"),
        ])
    return candidates


def _load_nss() -> Optional[ctypes.CDLL]:
    for candidate in _candidate_lib_paths():
        if candidate.is_file():
            try:
                # On Windows we must add the directory to the DLL search path
                # so nss3.dll can pick up its own siblings (mozglue, etc.).
                if sys.platform == "win32" and hasattr(os, "add_dll_directory"):
                    os.add_dll_directory(str(candidate.parent))
                return ctypes.CDLL(str(candidate))
            except OSError as exc:  # pragma: no cover — load failures are noisy
                logger.debug("Could not load %s: %s", candidate, exc)
    # Last-ditch: trust the system loader.
    for name in ("nss3", "libnss3.so", "libnss3.dylib"):
        try:
            return ctypes.CDLL(name)
        except OSError:
            continue
    return None


class NSSDecryptor:
    """Decrypt the username/password blobs from a Firefox ``logins.json``."""

    def __init__(self, profile_dir: str | Path, master_password: str = "") -> None:
        self.profile_dir = Path(profile_dir)
        self._master_password = master_password
        self._nss = _load_nss()
        self._initialised = False
        if self._nss is not None:
            self._bind_symbols()

    # --- Public ----------------------------------------------------------

    @property
    def available(self) -> bool:
        return self._nss is not None and (self.profile_dir / "key4.db").is_file()

    def decrypt_logins(self) -> list[dict]:
        """Return ``[{origin, action, username, password, ...}]`` plaintexts.

        The list mirrors ``logins.json`` order so a caller can zip it with
        the original entries to merge timestamps.
        """
        path = self.profile_dir / "logins.json"
        if not path.is_file():
            return []
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return []
        entries = data.get("logins") or []
        if not entries:
            return []

        if not self.available:
            return [self._placeholder(e) for e in entries]

        results: list[dict] = []
        try:
            self._init()
            for entry in entries:
                results.append(self._decrypt_entry(entry))
        finally:
            self._shutdown()
        return results

    # --- Low level -------------------------------------------------------

    def _bind_symbols(self) -> None:
        nss = self._nss
        nss.NSS_Init.argtypes = [c_char_p]
        nss.NSS_Init.restype = c_int
        nss.NSS_Shutdown.restype = c_int
        nss.PK11_GetInternalKeySlot.restype = c_void_p
        nss.PK11_FreeSlot.argtypes = [c_void_p]
        nss.PK11_Authenticate.argtypes = [c_void_p, c_int, c_void_p]
        nss.PK11_Authenticate.restype = c_int
        nss.PK11_CheckUserPassword.argtypes = [c_void_p, c_char_p]
        nss.PK11_CheckUserPassword.restype = c_int
        nss.PK11SDR_Decrypt.argtypes = [POINTER(_SECItem), POINTER(_SECItem), c_void_p]
        nss.PK11SDR_Decrypt.restype = c_int
        nss.SECITEM_ZfreeItem.argtypes = [POINTER(_SECItem), c_int]

    def _init(self) -> None:
        if self._initialised:
            return
        rc = self._nss.NSS_Init(str(self.profile_dir).encode("utf-8"))
        if rc != 0:
            raise RuntimeError(f"NSS_Init failed ({rc}) for {self.profile_dir}")
        slot = self._nss.PK11_GetInternalKeySlot()
        if not slot:
            raise RuntimeError("PK11_GetInternalKeySlot returned NULL")
        try:
            # An empty master password is the common case; supplying it as
            # an empty string still triggers the key-unwrap path.
            pw = self._master_password.encode("utf-8")
            if self._nss.PK11_CheckUserPassword(slot, pw) != 0:
                raise RuntimeError("Master password rejected by NSS")
        finally:
            self._nss.PK11_FreeSlot(slot)
        self._initialised = True

    def _shutdown(self) -> None:
        if self._initialised:
            self._nss.NSS_Shutdown()
            self._initialised = False

    def _decrypt_blob(self, b64_blob: str) -> Optional[str]:
        if not b64_blob:
            return ""
        try:
            raw = base64.b64decode(b64_blob)
        except (ValueError, TypeError):
            return None
        encrypted = _SECItem(0, ctypes.cast(ctypes.create_string_buffer(raw), c_void_p), len(raw))
        decrypted = _SECItem(0, None, 0)
        rc = self._nss.PK11SDR_Decrypt(byref(encrypted), byref(decrypted), None)
        if rc != 0:
            return None
        try:
            return ctypes.string_at(decrypted.data, decrypted.len).decode("utf-8", errors="replace")
        finally:
            self._nss.SECITEM_ZfreeItem(byref(decrypted), 0)

    def _decrypt_entry(self, entry: dict) -> dict:
        username = self._decrypt_blob(entry.get("encryptedUsername", "")) or ""
        password = self._decrypt_blob(entry.get("encryptedPassword", "")) or ""
        decrypted = bool(username or password)
        return {
            "origin_url": entry.get("hostname") or entry.get("origin") or "",
            "action_url": entry.get("formSubmitURL") or "",
            "username": username,
            "password": password,
            "time_created": entry.get("timeCreated"),
            "time_last_used": entry.get("timeLastUsed"),
            "times_used": entry.get("timesUsed") or 0,
            "encrypted": not decrypted,
        }

    @staticmethod
    def _placeholder(entry: dict) -> dict:
        # Used when NSS isn't available — surface metadata, hide blobs.
        return {
            "origin_url": entry.get("hostname") or entry.get("origin") or "",
            "action_url": entry.get("formSubmitURL") or "",
            "username": "",
            "password": "",
            "time_created": entry.get("timeCreated"),
            "time_last_used": entry.get("timeLastUsed"),
            "times_used": entry.get("timesUsed") or 0,
            "encrypted": True,
        }
