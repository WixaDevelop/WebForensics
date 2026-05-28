"""Enumerate Volume Shadow Copies on a *mounted* Windows volume.

Used by the folder-auto-detect flow: when the analyst points at a
drive root like ``F:\\`` we ask Windows itself which shadow copies
exist for that volume, then expose each one as an additional target
for the recursive profile scan.

This complements the E01-direct VSS path (in ``forensics.snapshots``),
which works on raw NTFS bytes inside an image. When the user has
already mounted + unlocked the image externally and the snapshots are
managed by the host's VSS service, this module is the right entry
point.

Two requirements that fail loudly when missing:

* Windows host (``vssadmin`` / WMI are Windows-only).
* Administrator privileges (vssadmin refuses otherwise).
"""

from __future__ import annotations

import ctypes
import json
import logging
import os
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger(__name__)


@dataclass
class LocalShadow:
    """One VSS shadow copy discovered on a mounted volume."""

    id: str
    device_object: str       # \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN
    original_volume: str     # \\?\Volume{GUID}
    install_date: Optional[datetime]
    drive_letter: Optional[str] = None  # convenience: which mounted drive it came from

    @property
    def label(self) -> str:
        if self.install_date is None:
            return f"shadow-{self.id[:8]}"
        return self.install_date.strftime("shadow-%Y%m%d-%H%M%S")

    def access_path(self) -> str:
        """Return a path the analyst can pass to ``os.walk``.

        Shadow copies are exposed by Windows as device objects, not as
        drive letters. To walk them with normal Python, append a
        backslash and a separator-friendly suffix.
        """
        return self.device_object.rstrip("\\") + "\\"


def _is_admin() -> bool:
    if os.name != "nt":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001
        return False


def _to_unc_drive(path: str | Path) -> Optional[str]:
    """Return the Windows drive letter for *path* (e.g. ``F:``) or ``None``."""
    if os.name != "nt":
        return None
    p = Path(path).resolve()
    drive = p.drive  # 'F:' on Windows, '' on POSIX
    if drive and len(drive) >= 2 and drive[1] == ":":
        return drive
    return None


def list_shadows_for(path: str | Path) -> List[LocalShadow]:
    """List VSS shadow copies that cover the volume containing *path*.

    Returns an empty list on POSIX, non-admin runs, or volumes without
    snapshots. Errors are logged but never raised — the caller can
    proceed with the live volume scan untouched.
    """
    if os.name != "nt":
        return []
    drive = _to_unc_drive(path)
    if not drive:
        return []

    if not _is_admin():
        logger.info(
            "VSS enumeration on %s skipped: not running as administrator.", drive,
        )
        return []

    # Use PowerShell + CIM (Win32_ShadowCopy) to get a stable JSON
    # response that does not depend on the system's display language.
    # We filter by VolumeName matching the requested volume's GUID, so
    # only shadows for that specific drive come back.
    ps_script = r"""
$drive = $args[0]
$vol = Get-WmiObject Win32_Volume -Filter "DriveLetter = '$drive'" | Select-Object -First 1
if (-not $vol) { Write-Output '[]'; exit 0 }
$volId = $vol.DeviceID
Get-WmiObject Win32_ShadowCopy |
    Where-Object { $_.VolumeName -eq $volId } |
    ForEach-Object {
        [PSCustomObject]@{
            ID = $_.ID
            DeviceObject = $_.DeviceObject
            VolumeName = $_.VolumeName
            InstallDate = $_.InstallDate
        }
    } | ConvertTo-Json -Compress
"""
    try:
        completed = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive",
             "-ExecutionPolicy", "Bypass", "-Command", ps_script, drive],
            capture_output=True, text=True, timeout=60,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        logger.warning("VSS enumeration failed (%s): %s", drive, exc)
        return []
    if completed.returncode != 0:
        logger.warning(
            "VSS enumeration on %s returned exit %d: %s",
            drive, completed.returncode, completed.stderr[:200],
        )
        return []

    raw = completed.stdout.strip()
    if not raw or raw in ("[]", "null"):
        return []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        logger.warning("VSS enumeration JSON parse failed: %s\n%s", exc, raw[:500])
        return []
    if isinstance(data, dict):
        # Single result comes through as an object rather than a list.
        data = [data]

    out: List[LocalShadow] = []
    for entry in data:
        try:
            ident = str(entry.get("ID", "")).strip()
            device = str(entry.get("DeviceObject", "")).strip()
            volume = str(entry.get("VolumeName", "")).strip()
            installed_raw = entry.get("InstallDate", "")
            install_dt = _parse_cim_datetime(installed_raw)
        except Exception:  # noqa: BLE001 — never let one bad record drop the rest
            logger.debug("VSS entry skipped: %r", entry, exc_info=True)
            continue
        if not device:
            continue
        out.append(LocalShadow(
            id=ident,
            device_object=device,
            original_volume=volume,
            install_date=install_dt,
            drive_letter=drive,
        ))
    # Newest first — analyst usually wants recent state.
    out.sort(key=lambda s: s.install_date or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
    return out


def _parse_cim_datetime(value) -> Optional[datetime]:
    """Parse the variety of date formats CIM/WMI emits to JSON."""
    if not value:
        return None
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    s = str(value).strip()
    # ConvertTo-Json sometimes serializes DateTime as /Date(milliseconds)/.
    if s.startswith("/Date(") and s.endswith(")/"):
        try:
            ms = int(s[6:-2].split("+", 1)[0].split("-", 1)[0])
            return datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc)
        except (ValueError, OverflowError):
            return None
    # WMI native: YYYYMMDDhhmmss.ffffff+TZ
    if len(s) >= 14 and s[:8].isdigit():
        try:
            return datetime.strptime(s[:14], "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    # ISO format fallback.
    try:
        return datetime.fromisoformat(s.rstrip("Z").split(".")[0])
    except ValueError:
        return None


@dataclass
class ShadowAvailability:
    """Summary returned to the UI before launching a folder scan."""

    is_windows: bool
    is_admin: bool
    drive: Optional[str]
    shadows: List[LocalShadow]

    @property
    def usable(self) -> bool:
        return bool(self.shadows)

    @property
    def message_for_user(self) -> str:
        if not self.is_windows:
            return "VSS enumeration is only available on Windows."
        if not self.drive:
            return "Not a Windows drive — VSS enumeration skipped."
        if not self.is_admin:
            return (
                "Found Windows drive but WebForensics is not running as admin. "
                "Re-launch as administrator to enumerate VSS snapshots."
            )
        if not self.shadows:
            return f"No VSS shadow copies on {self.drive}."
        return f"{len(self.shadows)} VSS shadow copy/copies on {self.drive}."


def check_shadow_availability(path: str | Path) -> ShadowAvailability:
    """Probe the host for shadows that cover *path*'s drive."""
    drive = _to_unc_drive(path)
    is_admin = _is_admin()
    shadows: List[LocalShadow] = []
    if os.name == "nt" and drive and is_admin:
        shadows = list_shadows_for(path)
    return ShadowAvailability(
        is_windows=(os.name == "nt"),
        is_admin=is_admin,
        drive=drive,
        shadows=shadows,
    )
