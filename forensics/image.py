"""Open forensic images so the rest of the app can pretend they are disks.

This module produces a ``pytsk3.Img_Info`` instance regardless of whether the
input is a raw ``.dd`` / ``.img`` / ``.bin`` or a segmented EnCase E01. The
trick for E01 is to wrap ``pyewf`` in a small ``Img_Info`` subclass that
forwards reads to the EWF handle — Sleuth Kit only knows about flat blobs.

If pyewf/pytsk3 are unavailable on the platform, ``open_image`` raises a
clear :class:`ForensicImageError` so the GUI can surface that.
"""

from __future__ import annotations

import glob
import logging
import os
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger(__name__)


class ForensicImageError(RuntimeError):
    """Raised when an image can't be opened or read."""


try:  # pragma: no cover — optional native deps
    import pytsk3  # type: ignore[import-not-found]
    _HAS_TSK = True
except Exception:  # noqa: BLE001
    _HAS_TSK = False

try:  # pragma: no cover — optional native deps
    import pyewf  # type: ignore[import-not-found]
    _HAS_EWF = True
except Exception:  # noqa: BLE001
    _HAS_EWF = False


if _HAS_TSK and _HAS_EWF:

    class _EWFImgInfo(pytsk3.Img_Info):
        """Glue between EnCase EWF segmented files and TSK's image API."""

        def __init__(self, ewf_handle):
            self._handle = ewf_handle
            super().__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

        def close(self):
            self._handle.close()

        def read(self, offset: int, size: int) -> bytes:
            self._handle.seek(offset)
            return self._handle.read(size)

        def get_size(self) -> int:
            return self._handle.get_media_size()

else:  # pragma: no cover
    _EWFImgInfo = None  # type: ignore[assignment]


_EWF_PATTERN_SUFFIXES = (".E01", ".e01")


def _discover_ewf_segments(first: Path) -> List[str]:
    """E01 files come as ``Image.E01``, ``Image.E02``... — pyewf needs all."""
    stem = first.stem
    pattern = str(first.with_name(f"{stem}.E??"))
    matches = sorted(glob.glob(pattern, recursive=False))
    if not matches:
        # Fall back to lowercase variants (some tools produce ``.e01``).
        pattern = str(first.with_name(f"{stem}.e??"))
        matches = sorted(glob.glob(pattern))
    return matches or [str(first)]


def open_image(path: str | Path):
    """Return a :class:`pytsk3.Img_Info` for the image at *path*.

    Supports E01 (single or segmented) and raw images (``.dd``, ``.img``,
    ``.bin``, or any unrecognised extension that TSK can open directly).
    """
    if not _HAS_TSK:
        raise ForensicImageError(
            "pytsk3 is not installed — run `pip install pytsk3` to enable image support."
        )

    target = Path(path)
    if not target.is_file():
        raise ForensicImageError(f"Image file not found: {target}")

    if target.suffix in _EWF_PATTERN_SUFFIXES:
        if not _HAS_EWF:
            raise ForensicImageError(
                "libewf-python (pyewf) is required to open E01 images."
            )
        segments = _discover_ewf_segments(target)
        ewf_handle = pyewf.handle()
        try:
            ewf_handle.open(segments)
        except IOError as exc:
            raise ForensicImageError(f"Failed to open EWF: {exc}") from exc
        return _EWFImgInfo(ewf_handle)

    # Raw image — let TSK do it directly.
    try:
        return pytsk3.Img_Info(str(target))
    except IOError as exc:
        raise ForensicImageError(f"Failed to open raw image: {exc}") from exc


def hash_image_segments(path: str | Path) -> dict[str, str]:
    """Return ``{segment_path: sha256}`` so we can record the chain of custody."""
    from utils.hashing import sha256_file

    target = Path(path)
    if target.suffix in _EWF_PATTERN_SUFFIXES:
        segments = _discover_ewf_segments(target)
    else:
        segments = [str(target)]
    return {seg: sha256_file(seg) for seg in segments}
