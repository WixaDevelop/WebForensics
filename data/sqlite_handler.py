"""Safe SQLite access for live browser databases.

Browsers keep their SQLite files open with an exclusive lock while running, so
opening them directly fails with ``database is locked``. We sidestep that by
copying the file (and its ``-wal`` / ``-shm`` siblings) to a temp directory
before opening it read-only. The copy is deleted on context-manager exit.

On Windows, browsers (especially Edge and modern Chrome) open their cookie
databases with a flag that forbids even *reading* — so plain ``shutil.copy2``
hits ``[WinError 32]``. We work around it by reading through the Win32 API
with the FILE_SHARE_* flags set, which the SQLite engine inside Chromium
also tolerates.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path
from typing import Iterator, Optional


def _copy_locked(src: Path, dst: Path) -> None:
    """Copy a file the OS may have locked with an exclusive write handle.

    Falls back to a Win32 ``CreateFileW`` open with permissive share flags so
    we can still pull bytes off a running browser's cookie DB. On non-Windows,
    or when ``pywin32`` is missing, this is just ``shutil.copy2``.
    """
    if sys.platform != "win32":
        shutil.copy2(src, dst)
        return
    try:
        shutil.copy2(src, dst)
        return
    except PermissionError:
        pass

    try:
        import win32con  # type: ignore[import-not-found]
        import win32file  # type: ignore[import-not-found]
        import pywintypes  # type: ignore[import-not-found]
    except ImportError as exc:  # pragma: no cover — pywin32 unavailable
        raise SQLiteHandlerError(
            f"Cannot read locked file {src}: pywin32 not installed"
        ) from exc

    share = (
        win32con.FILE_SHARE_READ
        | win32con.FILE_SHARE_WRITE
        | win32con.FILE_SHARE_DELETE
    )
    try:
        handle = win32file.CreateFileW(
            str(src),
            win32con.GENERIC_READ,
            share,
            None,
            win32con.OPEN_EXISTING,
            win32con.FILE_ATTRIBUTE_NORMAL,
            None,
        )
    except pywintypes.error as exc:
        # Chromium opens its cookie DB with ``dwShareMode=0`` while running,
        # which even FILE_SHARE_READ can't override. The honest fix is a
        # Volume Shadow Copy snapshot, which needs admin and is out of scope
        # for live extraction; pointing at a forensic image works fine.
        raise SQLiteHandlerError(
            f"{src.name} is locked — close the browser or analyse a forensic image."
        ) from exc

    try:
        with open(dst, "wb") as out:
            while True:
                ec, chunk = win32file.ReadFile(handle, 1 << 20)  # 1 MiB
                if ec != 0 or not chunk:
                    break
                out.write(chunk)
    finally:
        try:
            win32file.CloseHandle(handle)
        except Exception:  # noqa: BLE001
            pass


class SQLiteHandlerError(RuntimeError):
    """Raised when a database cannot be opened or copied."""


@contextlib.contextmanager
def open_browser_db(db_path: str | Path) -> Iterator[sqlite3.Connection]:
    """Yield a read-only ``sqlite3.Connection`` for a (possibly locked) DB.

    ``db_path`` is copied into a private temp directory together with its
    write-ahead log and shared-memory files when they exist. The connection
    uses URI mode with ``mode=ro`` to guarantee no writes hit the copy.
    """
    src = Path(db_path)
    if not src.is_file():
        raise SQLiteHandlerError(f"Database not found: {src}")

    tmpdir = Path(tempfile.mkdtemp(prefix="wf_sqlite_"))
    try:
        copy_path = tmpdir / src.name
        _copy_locked(src, copy_path)
        # WAL/SHM are required to read the *current* state; missing is fine.
        for suffix in ("-wal", "-shm"):
            sibling = src.with_name(src.name + suffix)
            if sibling.is_file():
                try:
                    _copy_locked(sibling, tmpdir / sibling.name)
                except SQLiteHandlerError:
                    # Sidecar files are optional — pressing on with just the main DB.
                    pass

        uri = f"file:{copy_path.as_posix()}?mode=ro&immutable=1"
        try:
            conn = sqlite3.connect(uri, uri=True, timeout=5)
        except sqlite3.Error as exc:
            raise SQLiteHandlerError(f"Cannot open {src}: {exc}") from exc
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def fetch_all(
    db_path: str | Path,
    query: str,
    params: tuple = (),
) -> list[sqlite3.Row]:
    """One-shot helper: open, query, return rows, close."""
    with open_browser_db(db_path) as conn:
        cursor = conn.execute(query, params)
        return cursor.fetchall()


def table_exists(conn: sqlite3.Connection, table: str) -> bool:
    row: Optional[sqlite3.Row] = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (table,),
    ).fetchone()
    return row is not None


def column_exists(conn: sqlite3.Connection, table: str, column: str) -> bool:
    """Used to handle schema drift across Chromium versions."""
    if not table_exists(conn, table):
        return False
    return any(row["name"] == column for row in conn.execute(f"PRAGMA table_info({table})"))
