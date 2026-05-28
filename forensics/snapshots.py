"""Enumerate Volume Shadow Copies (VSS) on an NTFS volume.

Windows takes periodic snapshots of NTFS volumes (System Restore points,
Backup, scheduled VSS jobs). Those snapshots are stored *inside* the
NTFS volume itself and frequently contain pristine copies of browser
profiles from days or weeks before the live state — gold for forensic
work where the live profile has been wiped or rolled forward.

This module:

* uses ``pyvshadow`` to enumerate snapshot stores from a raw NTFS
  partition view,
* wraps each store in a ``pytsk3.Img_Info`` shim so the existing
  filesystem walker can treat it like any other disk,
* labels each staged profile with the snapshot's creation timestamp so
  the analyst can correlate historical state with timeline gaps.

If ``pyvshadow`` is not installed, every entry point raises
:class:`SnapshotError` so callers can degrade gracefully.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable, List, Optional

logger = logging.getLogger(__name__)


class SnapshotError(RuntimeError):
    """Raised when VSS enumeration fails."""


try:  # pragma: no cover — optional native dep
    import pyvshadow  # type: ignore[import-not-found]
    _HAS_VSHADOW = True
except Exception:  # noqa: BLE001
    _HAS_VSHADOW = False

try:  # pragma: no cover — optional native dep
    import pytsk3  # type: ignore[import-not-found]
    _HAS_TSK = True
except Exception:  # noqa: BLE001
    _HAS_TSK = False


@dataclass
class SnapshotInfo:
    """Metadata about one VSS store inside an NTFS volume."""

    index: int
    identifier: str
    creation_time: Optional[datetime]
    size: int

    @property
    def label(self) -> str:
        """Short label used to tag staged profiles from this snapshot."""
        if self.creation_time is None:
            return f"snapshot-{self.index}"
        return self.creation_time.strftime("snapshot-%Y%m%d-%H%M%S")


# ---------------------------------------------------------------------------
# pytsk3 adapter
# ---------------------------------------------------------------------------


if _HAS_TSK:

    class _StoreImgInfo(pytsk3.Img_Info):
        """Bridge that exposes a pyvshadow store to ``pytsk3``."""

        def __init__(self, store) -> None:
            self._store = store
            super().__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

        def read(self, offset: int, size: int) -> bytes:
            try:
                return self._store.read_buffer_at_offset(size, offset)
            except IOError:
                return b""

        def get_size(self) -> int:
            return self._store.get_size()

        def close(self) -> None:  # pragma: no cover
            try:
                self._store.close()
            except Exception:  # noqa: BLE001
                pass

else:  # pragma: no cover
    _StoreImgInfo = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def _filetime_to_datetime(ft: int) -> Optional[datetime]:
    """Convert a Windows FILETIME (100-ns since 1601-01-01) to UTC datetime."""
    if ft <= 0:
        return None
    try:
        unix = (ft - 116444736000000000) / 10_000_000
        return datetime.fromtimestamp(unix, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


@dataclass
class _OpenedSnapshot:
    """A snapshot ready to feed the existing locator."""

    info: SnapshotInfo
    img: "pytsk3.Img_Info"
    fs: "pytsk3.FS_Info"


def iter_snapshots(volume_file_object) -> Iterable[_OpenedSnapshot]:
    """Yield every VSS store on *volume_file_object* as an opened FS.

    *volume_file_object* must be a file-like view of the *raw NTFS
    partition* (not the disk image). Use ``_PartitionFileObject`` from
    :mod:`forensics.bitlocker` or any equivalent slice for E01 / raw
    images; pass the path directly for a mounted volume.
    """
    if not _HAS_VSHADOW:
        raise SnapshotError(
            "libvshadow-python (pyvshadow) is not installed. "
            "Run `pip install libvshadow-python` to enable snapshot support."
        )
    if not _HAS_TSK:
        raise SnapshotError("pytsk3 is not installed; cannot expose snapshots.")

    vol = pyvshadow.volume()
    try:
        vol.open_file_object(volume_file_object)
    except IOError as exc:
        logger.debug("No VSS stores on this volume: %s", exc)
        return

    count = vol.get_number_of_stores()
    logger.info("Found %d VSS store(s)", count)
    for idx in range(count):
        try:
            store = vol.get_store(idx)
        except (IOError, IndexError) as exc:
            logger.debug("VSS store %d unreadable: %s", idx, exc)
            continue
        try:
            ident = store.get_identifier() if hasattr(store, "get_identifier") else f"#{idx}"
        except Exception:  # noqa: BLE001
            ident = f"#{idx}"
        try:
            ft = store.get_creation_time_as_integer() if hasattr(store, "get_creation_time_as_integer") else 0
        except Exception:  # noqa: BLE001
            ft = 0
        info = SnapshotInfo(
            index=idx,
            identifier=str(ident) if ident else f"#{idx}",
            creation_time=_filetime_to_datetime(ft),
            size=store.get_size(),
        )
        img = _StoreImgInfo(store)
        try:
            fs = pytsk3.FS_Info(img)
        except IOError as exc:
            logger.debug("VSS store %d has no openable FS: %s", idx, exc)
            try:
                img.close()
            except Exception:  # noqa: BLE001
                pass
            continue
        yield _OpenedSnapshot(info=info, img=img, fs=fs)


def has_snapshots(volume_file_object) -> int:
    """Return the number of VSS stores on *volume_file_object* (0 on any error)."""
    if not _HAS_VSHADOW:
        return 0
    try:
        vol = pyvshadow.volume()
        vol.open_file_object(volume_file_object)
        n = vol.get_number_of_stores()
        vol.close()
        return n
    except Exception:  # noqa: BLE001
        return 0
