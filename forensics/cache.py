"""Browser cache parsers.

Only the *metadata* is extracted — URL, MIME, fetch time, size, status — not
the cached body. The body bloat would explode the SQLite store, and forensic
practice usually wants "what URLs did the user fetch even if history was
wiped" rather than the raw payloads.

Two implementations:

* **Chromium Simple Cache** (current default since M86+). Layout:
  - ``index-dir/the-real-index`` — flat binary index, see
    https://www.chromium.org/developers/design-documents/network-stack/disk-cache/very-simple-backend/
  - ``<hash>_0`` files — one per cached entry. Header is a `SimpleFileHeader`,
    followed by URL bytes (length in the header), then payload, then a
    `SimpleFileEOF` and the response headers.
  - The URL is what we read; we skip the payload entirely. Timestamps come
    from the index entry (we fall back to file mtime for resilience).

* **Firefox cache2** (current since FF 32). Layout:
  - ``entries/`` directory, one file per entry.
  - Each file ends with a metadata block: 4 bytes total length, then a
    null-terminated key (which contains the URL), then frame info we ignore.
  - Timestamps from filesystem since the binary metadata format is opaque.

If a profile uses an older cache backend (BlockFile, etc.) we silently skip.
The user can always fall back to history + carving.
"""

from __future__ import annotations

import logging
import os
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Chromium "Simple Cache"
# ---------------------------------------------------------------------------


_SIMPLE_MAGIC = 0xFCFB6D1BA7725C30  # SimpleFileHeader.magic (little-endian)
_SIMPLE_HEADER_FMT = "<QIQI"          # magic (u64), version (u32), key_hash (u64), key_length (u32)
_SIMPLE_HEADER_SIZE = struct.calcsize(_SIMPLE_HEADER_FMT)


def parse_chromium_cache(cache_dir: Path) -> Iterator[dict]:
    """Yield cache-entry dicts for every Simple Cache file under *cache_dir*."""
    if not cache_dir.is_dir():
        return
    # Each entry file is named <hex_hash>_<stream_idx>. The interesting bits
    # all live in stream 0; the data streams (_1, _2) we don't need.
    for entry in cache_dir.iterdir():
        if not entry.is_file() or "_" not in entry.name:
            continue
        if not entry.name.endswith("_0"):
            continue
        try:
            yield from _parse_simple_cache_file(entry)
        except Exception as exc:  # noqa: BLE001 — keep going on bad files
            logger.debug("Skipped %s: %s", entry, exc)


def _parse_simple_cache_file(path: Path) -> Iterator[dict]:
    try:
        with path.open("rb") as fh:
            header = fh.read(_SIMPLE_HEADER_SIZE)
            if len(header) != _SIMPLE_HEADER_SIZE:
                return
            magic, version, _key_hash, key_length = struct.unpack(_SIMPLE_HEADER_FMT, header)
            if magic != _SIMPLE_MAGIC:
                return
            if key_length <= 0 or key_length > 4096:
                return
            key_bytes = fh.read(key_length)
            if len(key_bytes) != key_length:
                return
    except OSError:
        return

    url = key_bytes.decode("utf-8", errors="replace")
    # Filter obvious non-HTTP keys (Chromium also uses the cache for non-net
    # resources; their keys start with namespaces like ``_dk_``).
    if not url.startswith(("http://", "https://", "ftp://", "ws://", "wss://")):
        return
    try:
        stat = path.stat()
        mtime = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
        size = int(stat.st_size)
    except OSError:
        mtime = None
        size = 0
    yield {
        "url": url,
        "mime_type": "",      # could be parsed from the response headers
        "size": size,
        "fetched_at": mtime,
        "last_used": mtime,
        "status_code": 0,
        "source": "chromium_simplecache",
    }


# ---------------------------------------------------------------------------
# Firefox cache2
# ---------------------------------------------------------------------------


def parse_firefox_cache(cache_dir: Path) -> Iterator[dict]:
    """Yield cache-entry dicts for every Firefox cache2 entry under *cache_dir*."""
    entries_dir = cache_dir / "entries"
    if not entries_dir.is_dir():
        return
    for entry in entries_dir.iterdir():
        if not entry.is_file():
            continue
        try:
            yield from _parse_firefox_cache_file(entry)
        except Exception as exc:  # noqa: BLE001
            logger.debug("Skipped %s: %s", entry, exc)


def _parse_firefox_cache_file(path: Path) -> Iterator[dict]:
    # cache2 files end with a metadata block. The last 4 bytes are a big-endian
    # uint32 telling us how far back the metadata starts from the end. The
    # metadata begins with a version (u32), then fetch_count (u32),
    # fetch_time (u32), last_modified (u32), expiration_time (u32), then the
    # null-terminated key. The "key" is "<URL_separator><URL>" — in practice
    # it's a colon-prefixed bucket name plus ``:`` and the URL.
    try:
        size = path.stat().st_size
    except OSError:
        return
    if size < 8:
        return
    try:
        with path.open("rb") as fh:
            fh.seek(size - 4)
            tail = fh.read(4)
            if len(tail) != 4:
                return
            meta_offset = struct.unpack(">I", tail)[0]
            if meta_offset == 0 or meta_offset > size:
                return
            fh.seek(size - meta_offset)
            meta = fh.read(meta_offset)
    except OSError:
        return
    if len(meta) < 20:
        return
    # Skip the leading uint32s (version + 4 timestamps); not strictly required
    # but useful in case Firefox adds more fields later.
    pos = 20
    try:
        key_end = meta.index(b"\x00", pos)
    except ValueError:
        return
    key = meta[pos:key_end].decode("utf-8", errors="replace")
    # Key format: "<bucket>:<URL>" or sometimes "<bucket>,<URL>".
    url = key.split(":", 1)[-1].split(",", 1)[-1]
    if not url.startswith(("http://", "https://", "ftp://")):
        return
    try:
        version, fetch_count, fetch_time, last_modified, _expiration = struct.unpack(
            ">IIIII", meta[:20]
        )
    except struct.error:
        version = fetch_count = fetch_time = last_modified = 0
    fetched = _from_secs(fetch_time)
    last_used = _from_secs(last_modified)
    yield {
        "url": url,
        "mime_type": "",
        "size": size,
        "fetched_at": fetched,
        "last_used": last_used,
        "status_code": 0,
        "source": "firefox_cache2",
    }


def _from_secs(value: int) -> Optional[datetime]:
    if not value or value < 1_000_000_000:
        return None
    try:
        return datetime.fromtimestamp(value, tz=timezone.utc)
    except (OverflowError, ValueError):
        return None
