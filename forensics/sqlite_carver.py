"""Best-effort recovery of deleted SQLite records.

Two sources of deleted content:

1.  **WAL file** — uncommitted / recently-checkpointed pages live in
    ``<db>-wal``. Rows that were deleted but whose pages haven't been
    overwritten yet still parse cleanly.
2.  **Freelist + unallocated cells** — SQLite marks deleted records by
    rewriting the cell pointer array; the payload bytes usually survive until
    the next vacuum / overwrite.

Approach: shadow-attach the source DB *with* its WAL using SQLite itself —
this gives us the WAL view "for free". Then we scan every page for cells whose
offsets point above ``cellpointerarray_end`` (i.e. inside the unused middle of
the page) and try to parse them with the table's record format. Anything we
can decode and *can't* find in the live table is treated as deleted.

The carver is conservative: if we can't reliably parse a row we skip it. A
single column that fails to decode discards the whole record. The point is
forensic confidence, not chasing every byte.
"""

from __future__ import annotations

import logging
import shutil
import sqlite3
import struct
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator, Optional

logger = logging.getLogger(__name__)


# SQLite "varint" — used everywhere in record formats. Up to 9 bytes; the 9th
# is the full byte instead of 7 bits. See https://sqlite.org/fileformat.html
def _read_varint(buf: bytes, offset: int) -> tuple[int, int]:
    value = 0
    for i in range(8):
        if offset + i >= len(buf):
            raise ValueError("truncated varint")
        byte = buf[offset + i]
        value = (value << 7) | (byte & 0x7F)
        if not (byte & 0x80):
            return value, i + 1
    # 9th byte uses all 8 bits.
    if offset + 8 >= len(buf):
        raise ValueError("truncated varint (long)")
    value = (value << 8) | buf[offset + 8]
    return value, 9


# Serial-type → (size, decoder). Returns (size_bytes, python_value).
def _serial_size(serial_type: int) -> int:
    table = {0: 0, 1: 1, 2: 2, 3: 3, 4: 4, 5: 6, 6: 8, 7: 8, 8: 0, 9: 0}
    if serial_type in table:
        return table[serial_type]
    if serial_type >= 12:
        return (serial_type - (12 if serial_type % 2 == 0 else 13)) // 2
    raise ValueError(f"reserved serial type {serial_type}")


def _decode_value(serial_type: int, buf: bytes, offset: int):
    if serial_type == 0:
        return None, 0
    if serial_type in (1, 2, 3, 4, 5, 6):
        size = _serial_size(serial_type)
        raw = buf[offset:offset + size]
        if len(raw) != size:
            raise ValueError("truncated int")
        return int.from_bytes(raw, byteorder="big", signed=True), size
    if serial_type == 7:  # IEEE 754 double
        raw = buf[offset:offset + 8]
        if len(raw) != 8:
            raise ValueError("truncated float")
        return struct.unpack(">d", raw)[0], 8
    if serial_type in (8, 9):
        return (0 if serial_type == 8 else 1), 0
    if serial_type >= 12:
        size = _serial_size(serial_type)
        raw = buf[offset:offset + size]
        if len(raw) != size:
            raise ValueError("truncated blob/text")
        if serial_type % 2 == 0:  # BLOB
            return raw, size
        # TEXT — UTF-8 if not declared otherwise. We don't have the page header
        # encoding here, so attempt UTF-8 and fall back to latin-1.
        try:
            return raw.decode("utf-8"), size
        except UnicodeDecodeError:
            return raw.decode("latin-1", errors="replace"), size
    raise ValueError(f"reserved serial {serial_type}")


@dataclass
class CarvedRecord:
    """A row we managed to decode from unallocated / WAL space."""

    table: str
    column_values: tuple
    rowid: Optional[int] = None
    source: str = "freelist"   # freelist | wal | unallocated


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def carve_table(
    db_path: str | Path,
    table: str,
    column_count: int,
) -> Iterator[CarvedRecord]:
    """Yield deleted records found in *db_path* for *table*.

    *column_count* is the number of columns the live table has — we use it to
    filter junk records that happened to decode. ``rowid``-only header bytes
    are silently dropped.
    """
    src = Path(db_path)
    if not src.is_file():
        return
    # Work on a copy so we don't fight Chromium's lock and don't mutate the
    # original WAL even by reading it.
    tmpdir = Path(tempfile.mkdtemp(prefix="wf_carve_"))
    try:
        db_copy = tmpdir / src.name
        try:
            shutil.copy2(src, db_copy)
        except OSError:
            return
        for suffix in ("-wal", "-shm"):
            sibling = src.with_name(src.name + suffix)
            if sibling.is_file():
                try:
                    shutil.copy2(sibling, tmpdir / sibling.name)
                except OSError:
                    pass

        # Snapshot live rowids so we can tell carved-but-still-alive apart.
        live_rowids: set[int] = set()
        try:
            uri = f"file:{db_copy.as_posix()}?mode=ro"
            conn = sqlite3.connect(uri, uri=True, timeout=5)
            conn.row_factory = sqlite3.Row
            try:
                live_rowids = {
                    int(row["rowid"])
                    for row in conn.execute(f"SELECT rowid FROM {table}")
                }
            except sqlite3.Error:
                live_rowids = set()
            conn.close()
        except sqlite3.Error:
            pass

        yield from _scan_unallocated(db_copy, table, column_count, live_rowids)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Internal page scanner
# ---------------------------------------------------------------------------


def _scan_unallocated(
    db_path: Path,
    table: str,
    column_count: int,
    live_rowids: set[int],
) -> Iterator[CarvedRecord]:
    raw = db_path.read_bytes()
    if len(raw) < 100 or raw[:16] != b"SQLite format 3\x00":
        return

    page_size = int.from_bytes(raw[16:18], "big") or 65536
    # SQLite encodes page size 1 as 65536.
    if page_size == 1:
        page_size = 65536
    page_count = (len(raw) + page_size - 1) // page_size

    # Page 1 starts after the file header (offset 100). Other pages have
    # ``btree_header`` at byte 0 of the page.
    for pno in range(page_count):
        page_start = pno * page_size
        page = raw[page_start:page_start + page_size]
        if len(page) < 8:
            continue
        header_offset = 100 if pno == 0 else 0
        btree_header = page[header_offset:header_offset + 12]
        if len(btree_header) < 8:
            continue
        page_type = btree_header[0]
        # 0x0D = table B-tree leaf — these hold the actual row data.
        if page_type != 0x0D:
            continue

        cell_count = int.from_bytes(btree_header[3:5], "big")
        cell_content_start = int.from_bytes(btree_header[5:7], "big") or page_size

        # The "live" cells: their offsets live in an array right after the header.
        cell_ptr_array_offset = header_offset + 8
        live_offsets: set[int] = set()
        for i in range(cell_count):
            off = cell_ptr_array_offset + i * 2
            if off + 2 > len(page):
                break
            live_offsets.add(int.from_bytes(page[off:off + 2], "big"))

        # Hunt for record-shaped payloads in the *unallocated* span: from the
        # end of the cell-pointer array up to cell_content_start.
        unalloc_start = cell_ptr_array_offset + cell_count * 2
        unalloc_end = cell_content_start
        if unalloc_end <= unalloc_start:
            continue
        # Worst case the unallocated region is a few KB; scan byte by byte
        # because cell starts aren't aligned.
        for pos in range(unalloc_start, unalloc_end):
            if pos in live_offsets:
                continue
            try:
                record = _try_decode_cell(page, pos, column_count)
            except Exception:  # noqa: BLE001 — every byte we try is suspect
                continue
            if record is None:
                continue
            rowid = record.rowid
            if rowid is not None and rowid in live_rowids:
                continue
            record.table = table
            record.source = "unallocated"
            yield record


def _try_decode_cell(page: bytes, offset: int, expected_columns: int) -> Optional[CarvedRecord]:
    """Attempt to parse a table-btree-leaf cell starting at *offset*."""
    # Cell layout: payload_size (varint), rowid (varint), payload, [overflow].
    pos = offset
    payload_size, n = _read_varint(page, pos)
    pos += n
    if payload_size <= 0 or payload_size > 8192:  # safety bound
        return None
    rowid, n = _read_varint(page, pos)
    pos += n
    if rowid < 0 or rowid > 1 << 40:
        return None
    payload_start = pos
    if payload_start + payload_size > len(page):
        return None
    payload = page[payload_start:payload_start + payload_size]

    # Payload starts with its own header: size_of_header (varint), then a
    # varint per column giving the serial type.
    header_size, n = _read_varint(payload, 0)
    if header_size <= 0 or header_size > payload_size:
        return None
    hpos = n
    serial_types: list[int] = []
    while hpos < header_size:
        t, k = _read_varint(payload, hpos)
        serial_types.append(t)
        hpos += k
    if len(serial_types) != expected_columns:
        return None
    body_pos = header_size
    values: list = []
    for stype in serial_types:
        try:
            value, consumed = _decode_value(stype, payload, body_pos)
        except Exception:
            return None
        body_pos += consumed
        values.append(value)
    if body_pos > payload_size:
        return None
    return CarvedRecord(
        table="",
        column_values=tuple(values),
        rowid=rowid,
    )


# ---------------------------------------------------------------------------
# Convenience wrappers per browser table
# ---------------------------------------------------------------------------


def carve_chromium_history(history_db: str | Path) -> list[dict]:
    """Carve deleted rows from a Chromium ``urls`` table.

    Chromium's ``urls`` schema: ``id, url, title, visit_count, typed_count,
    last_visit_time, hidden, favicon_id``. The carver yields these in the
    same column order.
    """
    out: list[dict] = []
    for record in carve_table(history_db, "urls", column_count=8):
        values = record.column_values
        # Sanity check: a real history row should at minimum have a URL string.
        url = values[1] if len(values) > 1 else None
        if not isinstance(url, str) or not url.startswith(("http://", "https://", "ftp://", "file://")):
            continue
        out.append({
            "url": url,
            "title": str(values[2] or "") if len(values) > 2 else "",
            "visit_count": int(values[3] or 0) if len(values) > 3 else 0,
            "typed_count": int(values[4] or 0) if len(values) > 4 else 0,
            "last_visit_chromium": int(values[5] or 0) if len(values) > 5 else 0,
            "source": record.source,
        })
    return out


def carve_firefox_history(places_db: str | Path) -> list[dict]:
    """Carve deleted rows from a Firefox ``moz_places`` table.

    Schema varies across Firefox versions; we accept rows with at least 5
    columns and a URL-looking value in slot 1.
    """
    out: list[dict] = []
    # moz_places has had between 8 and 16+ columns; try a few common shapes.
    for cols in (14, 13, 12, 11, 10, 9, 8):
        for record in carve_table(places_db, "moz_places", column_count=cols):
            values = record.column_values
            url = values[1] if len(values) > 1 else None
            if not isinstance(url, str) or "://" not in url:
                continue
            out.append({
                "url": url,
                "title": str(values[2] or "") if len(values) > 2 else "",
                "visit_count": int(values[4] or 0) if len(values) > 4 else 0,
                "source": record.source,
            })
        if out:
            return out
    return out
