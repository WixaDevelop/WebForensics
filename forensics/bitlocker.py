"""BitLocker partition probing + unlocking via libbde (``pybde``).

Modern Windows installations leave the system drive encrypted with
BitLocker. ``pytsk3`` correctly detects the encryption but cannot read
the volume — we have to unwrap it first.

Flow:

1.  :func:`detect_bitlocker_partitions` walks the partition table of a
    forensic image and returns every ALLOC partition whose first bytes
    carry the ``-FVE-FS-`` BitLocker signature.

2.  :func:`unlock_bitlocker_partition` takes one of those entries plus a
    :class:`BitLockerCredentials` payload, opens the encrypted region
    via ``pybde``, supplies the credentials, and returns a
    ``pytsk3.Img_Info``-compatible handle that exposes the *decrypted*
    bytes. The result drops straight into the rest of the locator.

If ``pybde`` is unavailable, every entry point raises :class:`BitLockerError`
with a clear message — callers can use that to tell the analyst what to
install or how to mount the volume externally.
"""

from __future__ import annotations

import io
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger(__name__)


class BitLockerError(RuntimeError):
    """Raised when we can't open or unlock a BitLocker volume."""


try:  # pragma: no cover — optional native dep
    import pybde  # type: ignore[import-not-found]
    _HAS_BDE = True
except Exception:  # noqa: BLE001
    _HAS_BDE = False

try:  # pragma: no cover — optional native dep
    import pytsk3  # type: ignore[import-not-found]
    _HAS_TSK = True
except Exception:  # noqa: BLE001
    _HAS_TSK = False


BITLOCKER_SIGNATURE = b"-FVE-FS-"  # offset 3 of the volume boot record


# ---------------------------------------------------------------------------
# Credentials
# ---------------------------------------------------------------------------


@dataclass
class BitLockerCredentials:
    """One or more secrets the analyst supplied to unlock the volume.

    All fields are optional and we try every supplied form in turn — the
    first successful unlock wins. This matches how analysts typically
    have the credentials: maybe the user's login password, maybe the
    48-digit recovery key from AD, maybe both.
    """

    password: Optional[str] = None
    recovery_password: Optional[str] = None  # The 48-digit dashed form.
    startup_key_path: Optional[Path] = None  # ``.bek`` file.
    full_volume_key_hex: Optional[str] = None  # Pre-extracted FVEK in hex.

    def is_empty(self) -> bool:
        return not any((
            self.password,
            self.recovery_password,
            self.startup_key_path,
            self.full_volume_key_hex,
        ))

    def summary(self) -> str:
        parts: list[str] = []
        if self.password:
            parts.append("password")
        if self.recovery_password:
            parts.append("recovery-key")
        if self.startup_key_path:
            parts.append(f"startup-key={self.startup_key_path.name}")
        if self.full_volume_key_hex:
            parts.append("fvek")
        return ", ".join(parts) or "(none)"


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


@dataclass
class BitLockerPartition:
    """A locked partition discovered inside a forensic image."""

    addr: int                  # TSK partition index
    start_sector: int          # Sector offset within the image
    length_sectors: int
    sector_size: int = 512
    description: str = ""

    @property
    def byte_offset(self) -> int:
        return self.start_sector * self.sector_size

    @property
    def byte_length(self) -> int:
        return self.length_sectors * self.sector_size


def detect_bitlocker_partitions(img) -> List[BitLockerPartition]:
    """Return every BitLocker-encrypted partition inside *img*.

    *img* is a ``pytsk3.Img_Info`` (typically an EWF or raw image).
    Detection is signature-based — we read 16 bytes at each partition
    start and look for ``-FVE-FS-``. That catches the case where TSK
    surfaces "Encryption detected (BitLocker)" but also flags volumes
    where TSK returned a different error.
    """
    if not _HAS_TSK:
        raise BitLockerError("pytsk3 is not installed; cannot enumerate partitions.")
    try:
        vol = pytsk3.Volume_Info(img)
    except IOError as exc:
        logger.debug("No partition table on image: %s", exc)
        return []

    out: List[BitLockerPartition] = []
    for part in vol:
        if part.len <= 0 or part.flags != pytsk3.TSK_VS_PART_FLAG_ALLOC:
            continue
        offset = part.start * 512
        try:
            data = img.read(offset, 16)
        except IOError:
            continue
        # The BitLocker signature lives at offset 3 inside the volume
        # boot record. The first three bytes are the x86 jump opcode.
        if BITLOCKER_SIGNATURE in data:
            desc = ""
            try:
                desc = part.desc.decode("utf-8", errors="replace") if part.desc else ""
            except AttributeError:
                pass
            out.append(BitLockerPartition(
                addr=part.addr,
                start_sector=part.start,
                length_sectors=part.len,
                description=desc,
            ))
    return out


# ---------------------------------------------------------------------------
# Unlock + pytsk3 adapter
# ---------------------------------------------------------------------------


class _PartitionFileObject:
    """File-like view over a slice of a ``pytsk3.Img_Info``.

    ``pybde`` reads its encrypted bytes through a file-like object, so
    we expose the encrypted partition that way. The slice is bounded:
    ``read`` past the partition end returns an empty bytes object so
    libbde stops cleanly.
    """

    def __init__(self, img, offset: int, length: int) -> None:
        self._img = img
        self._offset = offset
        self._length = length
        self._pos = 0

    def read(self, size: int = -1) -> bytes:
        if self._pos >= self._length:
            return b""
        if size < 0 or self._pos + size > self._length:
            size = self._length - self._pos
        data = self._img.read(self._offset + self._pos, size)
        self._pos += len(data)
        return data

    def seek(self, offset: int, whence: int = 0) -> int:
        if whence == 0:
            new = offset
        elif whence == 1:
            new = self._pos + offset
        elif whence == 2:
            new = self._length + offset
        else:
            raise ValueError(f"invalid whence: {whence}")
        if new < 0:
            new = 0
        if new > self._length:
            new = self._length
        self._pos = new
        return self._pos

    def tell(self) -> int:
        return self._pos

    def get_size(self) -> int:
        return self._length

    def close(self) -> None:
        # Nothing to release on this side; ``_img`` is owned upstream.
        pass


if _HAS_TSK:

    class _BDEImgInfo(pytsk3.Img_Info):
        """Bridge that lets ``pytsk3`` see the decrypted volume as a disk."""

        def __init__(self, bde_volume) -> None:
            self._bde = bde_volume
            super().__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

        def read(self, offset: int, size: int) -> bytes:
            self._bde.seek(offset)
            return self._bde.read(size)

        def get_size(self) -> int:
            return self._bde.get_size()

        def close(self) -> None:  # pragma: no cover — TSK owns the lifetime
            try:
                self._bde.close()
            except Exception:  # noqa: BLE001
                pass

else:  # pragma: no cover
    _BDEImgInfo = None  # type: ignore[assignment]


def _apply_credentials(volume, creds: BitLockerCredentials) -> None:
    """Push every populated credential into the pybde volume."""
    if creds.password:
        try:
            volume.set_password(creds.password)
        except Exception as exc:  # noqa: BLE001
            logger.debug("set_password failed: %s", exc)
    if creds.recovery_password:
        try:
            volume.set_recovery_password(creds.recovery_password)
        except Exception as exc:  # noqa: BLE001
            logger.debug("set_recovery_password failed: %s", exc)
    if creds.startup_key_path:
        try:
            volume.read_startup_key(str(creds.startup_key_path))
        except Exception as exc:  # noqa: BLE001
            logger.debug("read_startup_key failed: %s", exc)
    if creds.full_volume_key_hex:
        try:
            key = bytes.fromhex(creds.full_volume_key_hex.replace(":", "").replace(" ", ""))
            # libbde expects a (full volume key, tweak key) pair for some modes
            volume.set_keys(key, b"")
        except Exception as exc:  # noqa: BLE001
            logger.debug("set_keys failed: %s", exc)


def unlock_bitlocker_partition(
    img,
    partition: BitLockerPartition,
    creds: BitLockerCredentials,
):
    """Open *partition*, supply *creds*, and return a pytsk3-compatible handle.

    Tries libbde first; if libbde refuses the volume (typical for Win10
    images with one bad-version metadata entry), falls back to our
    in-house native parser. Raises :class:`BitLockerError` with all the
    reasons concatenated if every backend fails.
    """
    if not _HAS_TSK:
        raise BitLockerError("pytsk3 is not installed.")
    if creds.is_empty():
        raise BitLockerError("No BitLocker credentials supplied.")

    errors: list[str] = []

    # --- Backend 1: libbde (pybde) ---
    if _HAS_BDE:
        encrypted = _PartitionFileObject(img, partition.byte_offset, partition.byte_length)
        volume = pybde.volume()
        try:
            volume.open_file_object(encrypted)
            _apply_credentials(volume, creds)
            volume.unlock()
            if not volume.is_locked():
                logger.info(
                    "BitLocker volume %s unlocked via libbde (size=%d bytes)",
                    partition.description or partition.addr, volume.get_size(),
                )
                return _BDEImgInfo(volume)
            errors.append("libbde: volume still locked after applying credentials")
        except IOError as exc:
            errors.append(f"libbde: {exc}")
        finally:
            try:
                if volume.is_locked():
                    volume.close()
            except Exception:  # noqa: BLE001
                pass
    else:
        errors.append("libbde: not installed")

    # --- Backend 2: native parser (only useful with a recovery key) ---
    if creds.recovery_password:
        try:
            from forensics.bitlocker_native import (
                NativeBitLockerVolume,
                try_native_unlock_with_recovery_key,
            )
        except ImportError as exc:
            errors.append(f"native: import failed ({exc})")
        else:
            try:
                native_result = _try_native_unlock(img, partition, creds.recovery_password)
            except Exception as exc:  # noqa: BLE001
                errors.append(f"native: parser exception: {exc}")
            else:
                if native_result.success:
                    logger.info(
                        "BitLocker volume %s unlocked via native parser (%s)",
                        partition.description or partition.addr,
                        native_result.description,
                    )
                    fo = _PartitionFileObject(img, partition.byte_offset, partition.byte_length)
                    native_volume = NativeBitLockerVolume(fo, native_result)
                    return _NativeImgInfo(native_volume)
                errors.append(f"native: {native_result.reason}")
    else:
        errors.append("native: skipped (only the recovery-key backend is wired in)")

    raise BitLockerError(
        f"BitLocker unlock failed ({creds.summary()}). Backends tried:\n  - "
        + "\n  - ".join(errors)
    )


def _try_native_unlock(img, partition, recovery_password: str):
    """Read metadata block 1 and ask the native parser to derive FVEK."""
    import struct
    from forensics.bitlocker_native import try_native_unlock_with_recovery_key

    # The boot sector at the partition start carries the three FVE
    # metadata-block offsets at +0xB0 / +0xB8 / +0xC0. Read enough to
    # cover all three plus the largest reasonable metadata block.
    boot = _read_partition(img, partition, 0, 4096)
    md1_offset = struct.unpack("<Q", boot[0xB0:0xB8])[0]
    metadata = _read_partition(img, partition, md1_offset, 65536)
    return try_native_unlock_with_recovery_key(metadata, recovery_password)


def _read_partition(img, partition, offset: int, size: int) -> bytes:
    return img.read(partition.byte_offset + offset, size)


if _HAS_TSK:

    class _NativeImgInfo(pytsk3.Img_Info):
        """Bridge for our pure-Python decryptor into pytsk3."""

        def __init__(self, native_volume) -> None:
            self._native = native_volume
            super().__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

        def read(self, offset: int, size: int) -> bytes:
            return self._native.read(offset, size)

        def get_size(self) -> int:
            return self._native.get_size()

        def close(self) -> None:  # pragma: no cover
            pass

else:  # pragma: no cover
    _NativeImgInfo = None  # type: ignore[assignment]
