"""LocalStorage / SessionStorage / IndexedDB extraction.

Both Chromium and Firefox store this data outside of the artifact SQLite DBs,
in storage backends that are awkward to read post-mortem:

* **Chromium** uses LevelDB. We do NOT depend on ``plyvel``. Instead we read
  the ``.ldb`` (sorted-string-table) and ``.log`` (write-ahead) files
  directly. The file format is documented at
  https://github.com/google/leveldb/blob/main/doc/table_format.md — for our
  purposes (forensic recovery) we just walk every record's key and value
  and let the caller decide whether it's interesting. We deliberately accept
  noise: better to recover too much than miss a JWT.

* **Firefox** persists per-origin storage to
  ``storage/default/<origin>/ls/data.sqlite`` (LocalStorage) and
  ``storage/default/<origin>/idb/<dbname>.sqlite`` (IndexedDB).

Output schema (per record): ``origin``, ``key``, ``value``, ``last_modified``,
``source``.
"""

from __future__ import annotations

import logging
import re
import sqlite3
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator
from urllib.parse import unquote

logger = logging.getLogger(__name__)


_MIN_VALUE_LEN = 4
_MAX_VALUE_LEN = 65536      # ldb leaf-block payloads cap out at ~64KB realistically


# ---------------------------------------------------------------------------
# Chromium LevelDB
# ---------------------------------------------------------------------------


def parse_chromium_leveldb(root: Path, kind: str) -> Iterator[dict]:
    """Walk every ``.ldb`` and ``.log`` under *root* and yield records.

    ``kind`` is just passed through so the caller knows whether it asked for
    LocalStorage or IndexedDB. The records aren't classified further — keys
    are returned as raw text where decodable.
    """
    if not root.is_dir():
        return
    # LocalStorage stores per-origin: the LevelDB key encoding is
    # ``META:<origin>\x00<key>`` or ``_<origin>\x00\x01<key>``.
    # IndexedDB keys are much more complex; we still extract URL-bearing strings.
    for entry in root.rglob("*"):
        if not entry.is_file():
            continue
        if entry.suffix.lower() not in (".ldb", ".log"):
            continue
        try:
            yield from _walk_leveldb_file(entry, kind)
        except Exception as exc:  # noqa: BLE001 — never let one bad file kill the lot
            logger.debug("LDB skip %s: %s", entry, exc)


def _walk_leveldb_file(path: Path, kind: str) -> Iterator[dict]:
    """Naive but effective LDB extractor — scan for printable key/value pairs.

    We don't parse the full footer/index. Instead we treat the file as a blob
    and look for "key\\x00value" pairs where the key looks like a URL or
    starts with a known LocalStorage prefix. For pure ``.log`` files we walk
    every Snappy/no-compression record (LevelDB uses block-level Snappy; we
    skip Snappy-compressed payloads since we don't have a decompressor here).
    """
    try:
        blob = path.read_bytes()
    except OSError:
        return

    # Chromium LocalStorage keys look like: META:<origin>\0\1<key> or _<origin>\0\1<key>.
    # We can fish them out by regex.
    pattern = re.compile(
        rb"(?P<prefix>META:|_)?https?://[^\x00]{4,256}\x00\x01?(?P<key>[ -~]{1,256})"
    )
    seen_origin: dict[str, datetime | None] = {}
    try:
        stat_mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
    except OSError:
        stat_mtime = None

    for match in pattern.finditer(blob):
        start = match.start()
        # Re-parse the origin since the regex doesn't bind it as a group.
        origin_start = start + (len(match.group("prefix") or b""))
        origin_end = blob.find(b"\x00", origin_start)
        if origin_end <= 0:
            continue
        origin = blob[origin_start:origin_end].decode("utf-8", errors="replace")
        key = match.group("key").decode("utf-8", errors="replace")
        # Try to grab the value bytes that follow the matched key.
        value_start = match.end()
        # Stop at the next ASCII control byte that smells like a record boundary.
        value_end = value_start
        while value_end < min(len(blob), value_start + _MAX_VALUE_LEN):
            b = blob[value_end]
            if b == 0 or (b < 0x09 and b != 0x0A and b != 0x0D):
                break
            value_end += 1
        value = blob[value_start:value_end]
        if len(value) < _MIN_VALUE_LEN:
            continue
        text = _decode_storage_value(value)
        if text is None:
            continue
        yield {
            "origin": origin,
            "key": key,
            "value": text,
            "last_modified": stat_mtime,
            "source": str(path),
        }
        seen_origin.setdefault(origin, stat_mtime)


def _decode_storage_value(raw: bytes) -> str | None:
    """Chromium prepends a one-byte type tag to LocalStorage values:

    * ``0x00`` UTF-16 LE bytes (BOM-less)
    * ``0x01`` UTF-8 bytes
    * ``0x02`` Latin-1 bytes

    IndexedDB values are V8 structured-clone; we don't decode that here but
    do return a best-effort UTF-8 decode so URL-like / JSON-like content is
    still searchable.
    """
    if not raw:
        return None
    tag = raw[0]
    payload = raw[1:]
    try:
        if tag == 0x00 and len(payload) >= 2:
            return payload.decode("utf-16-le", errors="replace")
        if tag == 0x01:
            return payload.decode("utf-8", errors="replace")
        if tag == 0x02:
            return payload.decode("latin-1", errors="replace")
    except UnicodeError:
        pass
    # Fall back: raw bytes, UTF-8 with replacement.
    try:
        decoded = raw.decode("utf-8", errors="replace")
    except UnicodeError:
        return None
    # If the decode is mostly non-printable noise, skip.
    printable = sum(1 for c in decoded if c.isprintable() or c in "\n\r\t")
    if printable < max(4, len(decoded) // 2):
        return None
    return decoded


# ---------------------------------------------------------------------------
# Firefox LocalStorage / IndexedDB
# ---------------------------------------------------------------------------


_FF_LS_DIR_PATTERNS = ("storage/default", "webappsstore.sqlite")


def parse_firefox_storage(profile_dir: Path) -> Iterator[dict]:
    """Yield records from Firefox's LocalStorage + IndexedDB SQLite files."""
    if not profile_dir.is_dir():
        return

    # Modern Firefox: webappsstore.sqlite at the profile root (one SQLite file
    # holding every origin's LocalStorage).
    webapps_db = profile_dir / "webappsstore.sqlite"
    if webapps_db.is_file():
        yield from _read_firefox_webappsstore(webapps_db)

    # New per-origin layout under storage/default/<origin>/ls/data.sqlite.
    storage_root = profile_dir / "storage" / "default"
    if storage_root.is_dir():
        for origin_dir in storage_root.iterdir():
            if not origin_dir.is_dir():
                continue
            origin = _decode_ff_origin_dir(origin_dir.name)
            ls_db = origin_dir / "ls" / "data.sqlite"
            if ls_db.is_file():
                yield from _read_firefox_ls_per_origin(ls_db, origin)
            idb_dir = origin_dir / "idb"
            if idb_dir.is_dir():
                for db_file in idb_dir.glob("*.sqlite"):
                    yield from _read_firefox_indexeddb(db_file, origin)


def _decode_ff_origin_dir(name: str) -> str:
    """Firefox encodes origins as ``https+++example.com`` in the filesystem."""
    if "+++" in name:
        scheme, rest = name.split("+++", 1)
        return f"{scheme}://{rest.replace('+', ':')}"
    return name


def _read_firefox_webappsstore(db_path: Path) -> Iterator[dict]:
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
    except sqlite3.Error as exc:
        logger.debug("webappsstore open failed: %s", exc)
        return
    try:
        # Modern schema: `webappsstore2(originAttributes, originKey, scope, key, value)`.
        rows = conn.execute(
            "SELECT scope AS scope, key, value FROM webappsstore2"
        )
        for row in rows:
            scope = row["scope"] or ""
            yield {
                "origin": _scope_to_origin(scope),
                "kind": "localstorage",
                "key": row["key"] or "",
                "value": row["value"] or "",
                "last_modified": None,
                "source": str(db_path),
            }
    except sqlite3.Error as exc:
        logger.debug("webappsstore read failed: %s", exc)
    finally:
        conn.close()


def _scope_to_origin(scope: str) -> str:
    # Firefox stores scope as ``moc.elpmaxe.:https:443``. Reverse the host and
    # rebuild ``<scheme>://<host>``.
    parts = scope.split(":", 2)
    if len(parts) >= 2:
        reversed_host = parts[0].rstrip(".")
        host = ".".join(reversed(reversed_host.split(".")))
        scheme = parts[1] if len(parts) > 1 else "http"
        return f"{scheme}://{host}"
    return scope


def _read_firefox_ls_per_origin(db_path: Path, origin: str) -> Iterator[dict]:
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
    except sqlite3.Error:
        return
    try:
        for row in conn.execute("SELECT key, utf16_length, conversion_type, value FROM data"):
            try:
                raw_value = row["value"]
                if isinstance(raw_value, (bytes, bytearray)):
                    value = raw_value.decode("utf-16-le", errors="replace")
                else:
                    value = str(raw_value or "")
            except (UnicodeError, AttributeError):
                value = ""
            yield {
                "origin": origin,
                "kind": "localstorage",
                "key": row["key"] or "",
                "value": value,
                "last_modified": None,
                "source": str(db_path),
            }
    except sqlite3.Error as exc:
        logger.debug("FF LS read failed: %s", exc)
    finally:
        conn.close()


def _read_firefox_indexeddb(db_path: Path, origin: str) -> Iterator[dict]:
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
    except sqlite3.Error:
        return
    try:
        # IndexedDB stores values as structured clones inside ``object_data``.
        # We can't decode them properly without the V8/SpiderMonkey serializer,
        # but emitting the raw blob lets analysts grep for tokens.
        for row in conn.execute(
            "SELECT object_store_id AS oid, key, data FROM object_data LIMIT 5000"
        ):
            data = row["data"]
            text = data.decode("utf-8", errors="replace") if isinstance(data, (bytes, bytearray)) else str(data or "")
            yield {
                "origin": origin,
                "kind": "indexeddb",
                "key": f"object_store={row['oid']}",
                "value": text[:4096],
                "last_modified": None,
                "source": str(db_path),
            }
    except sqlite3.Error:
        pass
    finally:
        conn.close()
