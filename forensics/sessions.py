"""Open-tab / session-restore parsers.

Chromium and Firefox use very different formats to remember what tabs were
open when the browser was last closed:

* **Chromium** writes a "Sessions Numbered Backend" (SNSS) command log to
  ``Profile/Sessions/Session_<timestamp>`` and ``Profile/Sessions/Tabs_<…>``.
  Format isn't officially documented but the structure is straightforward:
  4-byte length prefix, 1-byte command type, then per-type payload. Decoding
  the *full* state requires reproducing Chromium's pickle parser; what we do
  here is the forensically-useful subset — scan for ``CommandUpdateTabNavigation``
  payloads and extract the embedded URLs + titles.

* **Firefox** keeps the current session in ``sessionstore.jsonlz4`` (and
  optional ``sessionstore-backups/recovery.jsonlz4``). The container format
  is Mozilla's custom ``mozLz40\\0`` + 4-byte little-endian uncompressed size +
  LZ4-compressed JSON. We use ``lz4.block`` if installed; otherwise we fall
  back to a tiny pure-Python LZ4 block decoder.

We never crash if these files are missing or unreadable — both browsers may
not write them depending on settings or recent crashes.
"""

from __future__ import annotations

import json
import logging
import re
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Chromium SNSS
# ---------------------------------------------------------------------------


def parse_chromium_session_files(profile_dir: Path) -> Iterator[dict]:
    """Yield per-tab dicts from a Chromium profile's session files."""
    sessions_dir = profile_dir / "Sessions"
    if not sessions_dir.is_dir():
        return
    tab_idx_counter = 0
    # ``Tabs_<…>`` files are per-tab; ``Session_<…>`` is the whole window state.
    # Both share the SNSS layout, so we walk every file.
    for file in sessions_dir.iterdir():
        if not file.is_file():
            continue
        # Session-restore files have no extension and start with the magic
        # bytes ``SNSS``.
        try:
            with file.open("rb") as fh:
                magic = fh.read(4)
                if magic != b"SNSS":
                    continue
                fh.seek(0)
                for url, title in _walk_snss_commands(fh.read()):
                    session = "current" if file.name.startswith("Session_") else "last"
                    yield {
                        "session": session,
                        "window_idx": 0,
                        "tab_idx": tab_idx_counter,
                        "url": url,
                        "title": title,
                        "last_active": None,
                        "pinned": False,
                    }
                    tab_idx_counter += 1
        except OSError as exc:
            logger.debug("SNSS open failed for %s: %s", file, exc)


def _walk_snss_commands(blob: bytes) -> Iterator[tuple[str, str]]:
    """Scan an SNSS blob and yield ``(url, title)`` pairs.

    We don't decode every command type — just look for embedded URLs/titles in
    the per-command payload. Chromium's `Pickle` format stores strings as
    ``<length:u32><utf-8 bytes>``, padded to 4-byte boundaries.
    """
    pos = 8  # skip magic + version
    seen: set[tuple[str, str]] = set()
    while pos < len(blob) - 4:
        try:
            cmd_len = struct.unpack("<H", blob[pos:pos + 2])[0]
        except struct.error:
            break
        pos += 2
        if cmd_len == 0 or cmd_len > 1 << 20 or pos + cmd_len > len(blob):
            break
        payload = blob[pos:pos + cmd_len]
        pos += cmd_len
        # Hunt for HTTP/HTTPS URLs followed by a length-prefixed title.
        for url_match in re.finditer(rb"https?://[\x20-\x7e]{4,4096}", payload):
            url = url_match.group(0).decode("utf-8", errors="replace").rstrip()
            # Try to recover a title from the bytes following the URL.
            title = ""
            tail_start = url_match.end()
            if tail_start + 4 < len(payload):
                tlen = struct.unpack("<I", payload[tail_start:tail_start + 4])[0]
                if 0 < tlen < 4096 and tail_start + 4 + tlen <= len(payload):
                    title = payload[tail_start + 4:tail_start + 4 + tlen].decode(
                        "utf-8", errors="replace"
                    )
            key = (url, title)
            if key in seen:
                continue
            seen.add(key)
            yield url, title


# ---------------------------------------------------------------------------
# Firefox sessionstore.jsonlz4
# ---------------------------------------------------------------------------


_MOZLZ4_MAGIC = b"mozLz40\x00"


def parse_firefox_session(profile_dir: Path) -> Iterator[dict]:
    """Yield per-tab dicts from a Firefox profile's session-store files."""
    candidates = [
        (profile_dir / "sessionstore.jsonlz4", "current"),
        (profile_dir / "sessionstore-backups" / "recovery.jsonlz4", "current"),
        (profile_dir / "sessionstore-backups" / "previous.jsonlz4", "last"),
        (profile_dir / "sessionstore.js", "current"),  # legacy uncompressed
    ]
    for path, session_label in candidates:
        if not path.is_file():
            continue
        data = _read_mozlz4_or_json(path)
        if not data:
            continue
        try:
            doc = json.loads(data)
        except (ValueError, UnicodeDecodeError):
            continue
        yield from _walk_firefox_session(doc, session_label)


def _read_mozlz4_or_json(path: Path) -> Optional[bytes]:
    try:
        raw = path.read_bytes()
    except OSError:
        return None
    if not raw:
        return None
    if raw.startswith(_MOZLZ4_MAGIC):
        if len(raw) < 12:
            return None
        decompressed_size = struct.unpack("<I", raw[8:12])[0]
        compressed = raw[12:]
        try:
            from lz4.block import decompress as lz4_decompress  # type: ignore
            return lz4_decompress(compressed, uncompressed_size=decompressed_size)
        except Exception:  # noqa: BLE001 — try the pure-Python fallback
            pass
        return _lz4_block_decompress(compressed, decompressed_size)
    if raw.startswith(b"{"):
        return raw
    return None


def _lz4_block_decompress(src: bytes, expected_size: int) -> Optional[bytes]:
    """Tiny pure-Python LZ4 block decompressor.

    Slow but dependency-free. Only called when ``lz4.block`` is unavailable —
    the dominant cost of session-store reading is the JSON parse, not this.
    """
    out = bytearray()
    pos = 0
    while pos < len(src):
        token = src[pos]
        pos += 1
        literal_len = token >> 4
        if literal_len == 15:
            while pos < len(src):
                b = src[pos]
                pos += 1
                literal_len += b
                if b != 255:
                    break
        if pos + literal_len > len(src):
            return None
        out += src[pos:pos + literal_len]
        pos += literal_len
        if pos >= len(src):
            break
        if pos + 2 > len(src):
            return None
        offset = struct.unpack("<H", src[pos:pos + 2])[0]
        pos += 2
        match_len = (token & 0x0F) + 4
        if match_len == 19:
            while pos < len(src):
                b = src[pos]
                pos += 1
                match_len += b
                if b != 255:
                    break
        start = len(out) - offset
        if start < 0:
            return None
        for _ in range(match_len):
            out.append(out[start])
            start += 1
    if expected_size and len(out) != expected_size:
        # Some Mozilla files pad; tolerate a few bytes of drift.
        if abs(len(out) - expected_size) > 16:
            return None
    return bytes(out)


def _walk_firefox_session(doc: dict, session_label: str) -> Iterator[dict]:
    windows = doc.get("windows", []) if isinstance(doc, dict) else []
    for w_idx, window in enumerate(windows):
        tabs = window.get("tabs", []) if isinstance(window, dict) else []
        for t_idx, tab in enumerate(tabs):
            entries = tab.get("entries") or []
            current_idx = max(0, (tab.get("index") or 1) - 1)
            if not entries:
                continue
            entry = entries[min(current_idx, len(entries) - 1)]
            url = entry.get("url") or ""
            title = entry.get("title") or ""
            last_accessed = tab.get("lastAccessed") or 0
            last_active = None
            if isinstance(last_accessed, (int, float)) and last_accessed > 0:
                try:
                    last_active = datetime.fromtimestamp(last_accessed / 1000.0, tz=timezone.utc)
                except (OverflowError, ValueError):
                    last_active = None
            yield {
                "session": session_label,
                "window_idx": w_idx,
                "tab_idx": t_idx,
                "url": url,
                "title": title,
                "last_active": last_active,
                "pinned": bool(tab.get("pinned")),
            }
