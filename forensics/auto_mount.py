"""Orchestrate a full mount → BitLocker-unlock flow from inside WebForensics.

The pipeline on Windows is:

1. Find a mounter on disk (Arsenal Image Mounter or OSFMount).
2. Mount the E01 read-only as a virtual disk.
3. Find the new disk number Windows just attached.
4. For each drive letter on that disk, query ``manage-bde -status``.
5. For drives reporting *Lock Status: Locked*, run ``manage-bde -unlock``
   with the supplied recovery password.
6. Return every drive letter the analyst can now read.
7. On cleanup, dismount the image.

Requirements checked up-front and surfaced cleanly when missing:

* Windows (POSIX returns a friendly error).
* Administrator rights (``manage-bde`` and the mounters need it).
* Arsenal Image Mounter **or** OSFMount installed.
"""

from __future__ import annotations

import ctypes
import logging
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Environment probes
# ---------------------------------------------------------------------------


def is_admin() -> bool:
    if os.name != "nt":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001
        return False


@dataclass
class MounterTool:
    name: str
    executable: Path
    download_url: str


_ARSENAL_CANDIDATES = (
    r"C:\Program Files\Arsenal Recon\Arsenal Image Mounter\aim_cli.exe",
    r"C:\Program Files (x86)\Arsenal Recon\Arsenal Image Mounter\aim_cli.exe",
)
_OSFMOUNT_CANDIDATES = (
    r"C:\Program Files\OSFMount\OSFMount.com",
    r"C:\Program Files (x86)\OSFMount\OSFMount.com",
)
ARSENAL_DOWNLOAD = "https://arsenalrecon.com/downloads"
OSFMOUNT_DOWNLOAD = "https://www.osforensics.com/tools/mount-disk-images.html"


def find_mounter() -> Optional[MounterTool]:
    """Return the first installed mounter we can drive, or ``None``."""
    if os.name != "nt":
        return None
    for candidate in _ARSENAL_CANDIDATES:
        p = Path(candidate)
        if p.is_file():
            return MounterTool("Arsenal Image Mounter", p, ARSENAL_DOWNLOAD)
    aim = shutil.which("aim_cli.exe")
    if aim:
        return MounterTool("Arsenal Image Mounter", Path(aim), ARSENAL_DOWNLOAD)
    for candidate in _OSFMOUNT_CANDIDATES:
        p = Path(candidate)
        if p.is_file():
            return MounterTool("OSFMount", p, OSFMOUNT_DOWNLOAD)
    osfm = shutil.which("OSFMount.com")
    if osfm:
        return MounterTool("OSFMount", Path(osfm), OSFMOUNT_DOWNLOAD)
    return None


# ---------------------------------------------------------------------------
# Mount + unlock orchestration
# ---------------------------------------------------------------------------


@dataclass
class MountAttempt:
    """Result of one full mount-and-unlock pass."""

    success: bool
    drive_letters: List[str] = field(default_factory=list)
    unlocked_drives: List[str] = field(default_factory=list)
    disk_number: Optional[int] = None
    mounter_name: str = ""
    cleanup: Optional["_Cleanup"] = None
    error: str = ""
    notes: List[str] = field(default_factory=list)

    def __bool__(self) -> bool:
        return self.success


@dataclass
class _Cleanup:
    """State needed to undo a mount on session close (best-effort)."""

    mounter: MounterTool
    disk_number: Optional[int]
    image_path: Path
    unlocked_drives: List[str] = field(default_factory=list)

    def run(self) -> None:
        # Lock the BitLocker drives back so they don't stay accessible.
        for drive in self.unlocked_drives:
            try:
                _run(["manage-bde", "-lock", drive], timeout=30)
            except Exception:  # noqa: BLE001
                pass
        # Dismount the image. Each tool has its own incantation.
        try:
            if self.mounter.name == "Arsenal Image Mounter":
                if self.disk_number is not None:
                    _run([str(self.mounter.executable), "--dismount",
                          f"--device={self.disk_number}"], timeout=60)
                else:
                    _run([str(self.mounter.executable), "--dismount",
                          f"--filename={self.image_path}"], timeout=60)
            elif self.mounter.name == "OSFMount":
                if self.disk_number is not None:
                    _run([str(self.mounter.executable), "-d",
                          "-m", f"#{self.disk_number}"], timeout=60)
        except Exception:  # noqa: BLE001
            pass


def auto_unlock_image(
    image_path: str | Path,
    recovery_password: Optional[str] = None,
) -> MountAttempt:
    """Mount *image_path* and unlock any BitLocker drives it carries.

    Always check :attr:`MountAttempt.success` before reading drives.
    Call ``MountAttempt.cleanup.run()`` when you're done with the
    mounted volume.
    """
    if os.name != "nt":
        return MountAttempt(success=False, error="Auto-mount está disponible solo en Windows.")
    if not is_admin():
        return MountAttempt(success=False, error=(
            "Se requieren permisos de Administrador. Cierra WebForensics y "
            "vuelve a abrirlo con clic derecho → 'Ejecutar como administrador'."
        ))

    mounter = find_mounter()
    if mounter is None:
        return MountAttempt(success=False, error=(
            "No se encontró Arsenal Image Mounter ni OSFMount instalados. "
            "Instala uno de los dos para que la app pueda montar imágenes E01."
        ))

    image_path = Path(image_path)
    if not image_path.is_file():
        return MountAttempt(success=False, error=f"Imagen no encontrada: {image_path}",
                            mounter_name=mounter.name)

    # Snapshot disk numbers so we can identify the new one after mount.
    disks_before = _list_disk_numbers()
    notes: List[str] = []

    # --- Mount -------------------------------------------------------
    try:
        if mounter.name == "Arsenal Image Mounter":
            mount_proc = _run([str(mounter.executable), "--mount", "--readonly",
                               f"--filename={image_path}"], timeout=180)
        else:  # OSFMount
            mount_proc = _run([str(mounter.executable), "-a", "-t", "file",
                               "-f", str(image_path), "-o", "ro", "-v", "all"],
                              timeout=180)
    except subprocess.TimeoutExpired:
        return MountAttempt(success=False, mounter_name=mounter.name,
                            error=f"{mounter.name} no respondió (timeout).")

    if mount_proc.returncode != 0:
        return MountAttempt(success=False, mounter_name=mounter.name, error=(
            f"{mounter.name} devolvió código {mount_proc.returncode}. "
            f"Salida: {(mount_proc.stderr or mount_proc.stdout).strip()[:300]}"
        ))

    # Try to extract a disk number from the mounter's output. Arsenal
    # prints "Disk number: N" or "Device created at \\.\PhysicalDriveN".
    disk_n: Optional[int] = None
    blob = (mount_proc.stdout or "") + (mount_proc.stderr or "")
    m = re.search(r"[Dd]isk[\s_]*[Nn]umber[:\s]+(\d+)", blob)
    if not m:
        m = re.search(r"PhysicalDrive(\d+)", blob)
    if m:
        disk_n = int(m.group(1))

    # If the mounter didn't tell us, ask Windows directly.
    if disk_n is None:
        new_disk = _wait_for_new_disk(disks_before, timeout_s=20)
        disk_n = new_disk
        if disk_n is not None:
            notes.append(f"Disk number {disk_n} detectado vía diff de Get-Disk.")

    if disk_n is None:
        return MountAttempt(success=False, mounter_name=mounter.name, error=(
            "La imagen se montó pero Windows no reportó un disco nuevo. "
            "Revisa Administración de Discos (diskmgmt.msc) manualmente."
        ))

    cleanup = _Cleanup(mounter=mounter, disk_number=disk_n, image_path=image_path)

    # Give Windows a moment to settle so drive letters appear.
    time.sleep(2)

    # --- Discover drives + unlock BitLocker --------------------------
    drive_letters = _drives_for_disk(disk_n)
    notes.append(f"Letras detectadas en disco {disk_n}: {drive_letters or '(ninguna)'}")

    # Look at every drive in the system that wasn't there before — BitLocker
    # volumes sometimes show up as new letters under the same disk number.
    all_locked = _all_locked_bitlocker_drives()
    notes.append(f"Drives con BitLocker locked: {all_locked or '(ninguno)'}")

    unlocked: List[str] = []
    if recovery_password:
        for drive in all_locked:
            ok, msg = _unlock_drive(drive, recovery_password)
            if ok:
                unlocked.append(drive)
                cleanup.unlocked_drives.append(drive)
                if drive not in drive_letters:
                    drive_letters.append(drive)
                notes.append(f"Desbloqueado: {drive}")
            else:
                notes.append(f"Falló unlock de {drive}: {msg[:200]}")
    elif all_locked:
        notes.append("Hay drives con BitLocker pero no se proporcionó recovery key.")

    if not drive_letters:
        cleanup.run()
        return MountAttempt(
            success=False, mounter_name=mounter.name, disk_number=disk_n,
            error=(
                f"La imagen se montó en disco {disk_n} pero no aparecieron "
                f"letras de unidad accesibles. " + (
                    "El BitLocker no se pudo desbloquear con la clave dada."
                    if all_locked and recovery_password else
                    "No hay particiones BitLocker para desbloquear con la clave proporcionada."
                )
            ),
            notes=notes,
        )

    return MountAttempt(
        success=True,
        drive_letters=drive_letters,
        unlocked_drives=unlocked,
        disk_number=disk_n,
        mounter_name=mounter.name,
        cleanup=cleanup,
        notes=notes,
    )


# ---------------------------------------------------------------------------
# Subprocess helpers
# ---------------------------------------------------------------------------


def _run(cmd, timeout: float = 120) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def _list_disk_numbers() -> set[int]:
    try:
        proc = _run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
             "Get-Disk | Select-Object -ExpandProperty Number"],
            timeout=30,
        )
        if proc.returncode == 0:
            return {int(line.strip()) for line in proc.stdout.splitlines() if line.strip().isdigit()}
    except Exception:  # noqa: BLE001
        pass
    return set()


def _wait_for_new_disk(before: set[int], timeout_s: float = 20) -> Optional[int]:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        now = _list_disk_numbers()
        new = now - before
        if new:
            return min(new)
        time.sleep(0.5)
    return None


def _drives_for_disk(disk_number: int) -> List[str]:
    """Drive letters currently assigned to *disk_number*."""
    script = (
        f"Get-Partition -DiskNumber {disk_number} -ErrorAction SilentlyContinue | "
        "Where-Object {{ $_.DriveLetter }} | "
        "Select-Object -ExpandProperty DriveLetter"
    )
    try:
        proc = _run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script])
        if proc.returncode == 0:
            return [
                f"{line.strip()}:" for line in proc.stdout.splitlines()
                if line.strip() and len(line.strip()) == 1 and line.strip().isalpha()
            ]
    except Exception:  # noqa: BLE001
        pass
    return []


def _all_locked_bitlocker_drives() -> List[str]:
    """All drives the system currently reports as BitLocker-locked.

    Uses Get-BitLockerVolume which is available on Windows 8.1+ Pro/Enterprise.
    Falls back to manage-bde -status enumeration otherwise.
    """
    locked: List[str] = []
    # Preferred: Get-BitLockerVolume.
    try:
        proc = _run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
             "Get-BitLockerVolume | Where-Object { $_.LockStatus -eq 'Locked' } | "
             "Select-Object -ExpandProperty MountPoint"],
            timeout=30,
        )
        if proc.returncode == 0:
            for line in proc.stdout.splitlines():
                s = line.strip().rstrip("\\")
                if len(s) >= 2 and s[1] == ":":
                    locked.append(s if s.endswith(":") else s + ":")
            if locked:
                return locked
    except Exception:  # noqa: BLE001
        pass
    # Fallback: scan each drive letter with manage-bde -status.
    for letter in "DEFGHIJKLMNOPQRSTUVWXYZ":
        drive = f"{letter}:"
        try:
            proc = _run(["manage-bde", "-status", drive], timeout=15)
        except Exception:  # noqa: BLE001
            continue
        if proc.returncode == 0 and "Locked" in (proc.stdout or ""):
            locked.append(drive)
    return locked


def _unlock_drive(drive_letter: str, recovery_password: str) -> tuple[bool, str]:
    """Run manage-bde to unlock *drive_letter* with the recovery password."""
    cmd = ["manage-bde", "-unlock", drive_letter,
           "-RecoveryPassword", recovery_password]
    try:
        proc = _run(cmd, timeout=60)
    except subprocess.TimeoutExpired:
        return False, "manage-bde no respondió (timeout)"
    if proc.returncode == 0:
        # Belt + braces — confirm by querying status afterwards.
        try:
            status = _run(["manage-bde", "-status", drive_letter], timeout=15)
            if "Unlocked" in (status.stdout or ""):
                return True, ""
        except Exception:  # noqa: BLE001
            pass
        return True, ""
    blob = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
    return False, blob[:400]
