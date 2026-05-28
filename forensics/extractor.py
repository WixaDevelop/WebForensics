"""Walk a forensic image and stage browser profiles for the existing extractors.

What we do, in order:

1.  ``open_image`` gets us a TSK ``Img_Info``.
2.  We enumerate partitions; for each readable filesystem we open an
    ``FS_Info`` and check it for browser data. NTFS, FAT32, exFAT and
    detection-pending variants are all accepted — the real filter is
    whether the candidate ``Users`` / ``Documents and Settings`` /
    ``AppData`` trees exist.
3.  We look at ``\\Users\\<acct>`` (modern Windows) and
    ``\\Documents and Settings\\<acct>`` (XP / Server 2003). If neither
    is present we walk the filesystem looking for any ``AppData`` dir —
    handy for partition-only or wiped images.
4.  Profile files we care about are *copied out* to a temp directory
    that mirrors the layout the live extractors expect. From there the
    existing ``ChromeBrowser`` / ``EdgeBrowser`` / ``FirefoxBrowser``
    work unchanged.
"""

from __future__ import annotations

import logging
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Iterator, List, Optional, Tuple

try:  # pragma: no cover — optional native deps
    import pytsk3  # type: ignore[import-not-found]
    _HAS_TSK = True
except Exception:  # noqa: BLE001
    _HAS_TSK = False

from forensics.bitlocker import (
    BitLockerCredentials,
    BitLockerError,
    BitLockerPartition,
    _PartitionFileObject,
    detect_bitlocker_partitions,
    unlock_bitlocker_partition,
)
from forensics.image import ForensicImageError, open_image
from forensics.snapshots import SnapshotError, SnapshotInfo, iter_snapshots

logger = logging.getLogger(__name__)


# Per-browser allow-lists.
#
# Chromium: keep the file list tight so the temp copy stays small, but
# include enough to feed every downstream extractor (history, cookies,
# logins, autofill, bookmarks, permissions via Preferences, sessions,
# extensions). LevelDB / IndexedDB / Cache are staged as whole directory
# trees because they need every shard to decode.
_CHROMIUM_FILES = (
    "History", "History-journal",
    "Cookies", "Cookies-journal",
    "Login Data", "Login Data-journal",
    "Login Data For Account", "Login Data For Account-journal",
    "Web Data", "Web Data-journal",
    "Bookmarks", "Bookmarks.bak",
    "Preferences", "Secure Preferences",
    "Favicons", "Favicons-journal",
    "Top Sites", "Top Sites-journal",
    "Shortcuts", "Shortcuts-journal",
    "Visited Links",
    "Last Session", "Last Tabs", "Current Session", "Current Tabs",
)
_CHROMIUM_NETWORK_FILES = ("Cookies", "Cookies-journal", "Network Persistent State")
_CHROMIUM_DIR_TREES = (
    "Local Storage",
    "Session Storage",
    "IndexedDB",
    "Sessions",
)
_FIREFOX_FILES = (
    "places.sqlite", "places.sqlite-wal", "places.sqlite-shm",
    "cookies.sqlite", "cookies.sqlite-wal", "cookies.sqlite-shm",
    "formhistory.sqlite",
    "permissions.sqlite", "permissions.sqlite-wal", "permissions.sqlite-shm",
    "favicons.sqlite",
    "logins.json", "key4.db", "extensions.json",
    "sessionstore.jsonlz4", "sessionstore.bak", "recovery.jsonlz4",
    "addons.json", "prefs.js",
)
_FIREFOX_DIR_TREES = (
    "sessionstore-backups",
    "storage",
)


# System accounts that never have a real browser profile — skip them quickly.
_SYSTEM_USERS = {
    "All Users", "Default", "Default User", "Default.migrated",
    "Public", "desktop.ini", "LocalService", "NetworkService", "systemprofile",
}

# Both modern and XP/Server-2003 user roots.
_USER_ROOTS = ("/Users", "/Documents and Settings")

# How deep we walk the FS when neither user root is found. Beyond ~5 levels
# AppData simply doesn't live anywhere reasonable; keeping a bound prevents
# pathological hangs on big images.
_DEEP_SCAN_MAX_DEPTH = 7


@dataclass
class LocatedProfile:
    """A profile staged into a temp folder, ready for the live extractors."""

    browser: str
    user: str           # Account name from the user root, or "unknown"
    profile_name: str   # ``Default``, ``Profile 1``, or Firefox profile name
    temp_path: Path     # Where we copied the files
    image_source: str   # Original image path for audit / hashing
    extra: dict = field(default_factory=dict)

    @property
    def display(self) -> str:
        return f"{self.browser}[{self.user}/{self.profile_name}]"


@dataclass
class ImageScanDiagnostic:
    """Human-readable trace of what the locator did and didn't find.

    Surfaced to the UI so the analyst sees *why* an image yielded zero
    profiles instead of a blank screen.
    """

    image_path: str = ""
    partitions_seen: int = 0
    filesystems_opened: int = 0
    fs_types: list[str] = field(default_factory=list)
    user_roots_seen: list[str] = field(default_factory=list)
    users_found: list[str] = field(default_factory=list)
    appdata_dirs_found: list[str] = field(default_factory=list)
    profiles_staged: int = 0
    notes: list[str] = field(default_factory=list)
    bitlocker_partitions: list[BitLockerPartition] = field(default_factory=list)
    bitlocker_unlocked: list[int] = field(default_factory=list)  # addrs that worked
    bitlocker_failed: list[str] = field(default_factory=list)    # reasons by addr
    snapshots_found: list[str] = field(default_factory=list)     # labels of staged snapshots

    @property
    def has_locked_bitlocker(self) -> bool:
        unlocked = set(self.bitlocker_unlocked)
        return any(p.addr not in unlocked for p in self.bitlocker_partitions)

    def to_text(self) -> str:
        lines = [f"Image: {self.image_path}"]
        lines.append(f"Partitions seen: {self.partitions_seen}")
        lines.append(f"Filesystems opened: {self.filesystems_opened}")
        if self.fs_types:
            lines.append("Filesystem types: " + ", ".join(self.fs_types))
        if self.bitlocker_partitions:
            unlocked = set(self.bitlocker_unlocked)
            lines.append("BitLocker partitions:")
            for p in self.bitlocker_partitions:
                state = "UNLOCKED" if p.addr in unlocked else "LOCKED"
                size_gb = p.byte_length / (1024 ** 3)
                lines.append(
                    f"  [{state}] addr={p.addr} desc={p.description!r} "
                    f"size={size_gb:.1f} GiB"
                )
            for reason in self.bitlocker_failed:
                lines.append(f"  unlock error: {reason}")
        if self.user_roots_seen:
            lines.append("User roots found: " + ", ".join(self.user_roots_seen))
        else:
            lines.append("User roots found: (none)")
        if self.users_found:
            lines.append("Users found: " + ", ".join(self.users_found))
        if self.appdata_dirs_found:
            lines.append("AppData dirs (deep-scan): " + ", ".join(self.appdata_dirs_found))
        if self.snapshots_found:
            lines.append("VSS snapshots scanned: " + ", ".join(self.snapshots_found))
        lines.append(f"Profiles staged: {self.profiles_staged}")
        for note in self.notes:
            lines.append(f"- {note}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Helpers around pytsk3
# ---------------------------------------------------------------------------


def _fs_type_name(fs) -> str:
    """Return a human-readable filesystem type from a pytsk3 FS_Info."""
    try:
        return str(fs.info.ftype).rsplit(".", 1)[-1]
    except Exception:  # noqa: BLE001
        return "unknown"


def _yield_snapshots(
    volume_file_object,
    diag: ImageScanDiagnostic,
) -> Iterator[Tuple["pytsk3.FS_Info", Optional[SnapshotInfo]]]:
    """Yield ``(fs, snapshot_info)`` for every VSS store on the volume."""
    try:
        for opened in iter_snapshots(volume_file_object):
            diag.filesystems_opened += 1
            diag.fs_types.append(f"{_fs_type_name(opened.fs)}({opened.info.label})")
            diag.snapshots_found.append(opened.info.label)
            yield opened.fs, opened.info
    except SnapshotError as exc:
        diag.notes.append(f"VSS enumeration skipped: {exc}")


def _iter_filesystems(
    img,
    diag: ImageScanDiagnostic,
    bitlocker_credentials: Optional[BitLockerCredentials] = None,
    include_snapshots: bool = True,
) -> Iterator[Tuple["pytsk3.FS_Info", Optional[SnapshotInfo]]]:
    """Yield every readable filesystem in *img*.

    We deliberately accept any filesystem the Sleuth Kit can open — not
    just NTFS. A surprising number of images come from FAT32 USB sticks
    or non-Windows hosts and we'd rather over-yield and let the path
    probe sort them out than silently drop a volume.

    When a partition is BitLocker-encrypted we try to unlock it with
    the supplied credentials before opening its filesystem. The
    diagnostic records every locked partition we saw, regardless of
    whether unlock succeeded.
    """
    try:
        volume = pytsk3.Volume_Info(img)
    except IOError:
        # No partition table — assume the image is a single filesystem.
        diag.notes.append("No partition table (Volume_Info failed); trying whole image as one FS.")
        try:
            fs = pytsk3.FS_Info(img)
            diag.filesystems_opened += 1
            diag.fs_types.append(_fs_type_name(fs))
            yield fs, None
            # Try to enumerate VSS snapshots from a file-like view of the whole image.
            if include_snapshots and fs.info.ftype == pytsk3.TSK_FS_TYPE_NTFS:
                fo = _PartitionFileObject(img, 0, img.get_size())
                yield from _yield_snapshots(fo, diag)
        except IOError as exc:
            diag.notes.append(f"Whole-image FS_Info failed: {exc}")
        return

    # Probe for BitLocker partitions up-front so the diagnostic reports
    # them even when no credentials were supplied.
    try:
        locked = detect_bitlocker_partitions(img)
        if locked:
            diag.bitlocker_partitions = locked
    except BitLockerError as exc:
        diag.notes.append(f"BitLocker probe skipped: {exc}")
        locked = []
    locked_by_addr = {p.addr: p for p in locked}

    for part in volume:
        diag.partitions_seen += 1
        if part.len <= 0 or part.flags == pytsk3.TSK_VS_PART_FLAG_UNALLOC:
            continue

        # Try the partition as a plain filesystem first.
        try:
            fs = pytsk3.FS_Info(img, offset=part.start * 512)
            diag.filesystems_opened += 1
            diag.fs_types.append(_fs_type_name(fs))
            yield fs, None
            # On NTFS, also enumerate VSS shadow copies if any.
            if include_snapshots and fs.info.ftype == pytsk3.TSK_FS_TYPE_NTFS:
                fo = _PartitionFileObject(img, part.start * 512, part.len * 512)
                yield from _yield_snapshots(fo, diag)
            continue
        except IOError as exc:
            err = str(exc)
            # Only treat as BitLocker if our signature probe confirmed it.
            # The MSR partition and similar high-entropy / zero-filled
            # regions trip pytsk3's "Possible encryption detected" warning
            # but they are not actually BitLocker — running unlock against
            # them just wastes time and pollutes the diagnostic.
            is_bitlocker = (
                part.addr in locked_by_addr
                or "BitLocker" in err  # libtsk explicitly named BitLocker
            )
            if not is_bitlocker:
                # Plain unreadable partition (e.g., LVM, MSR). Skip silently.
                continue

        # BitLocker path — try to unlock if credentials were supplied.
        partition = locked_by_addr.get(part.addr) or BitLockerPartition(
            addr=part.addr,
            start_sector=part.start,
            length_sectors=part.len,
            description=(part.desc.decode("utf-8", errors="replace") if part.desc else ""),
        )
        if bitlocker_credentials is None or bitlocker_credentials.is_empty():
            diag.notes.append(
                f"Partition {part.addr} ({partition.description}) is BitLocker-encrypted; "
                f"no credentials supplied."
            )
            continue
        try:
            unlocked_img = unlock_bitlocker_partition(img, partition, bitlocker_credentials)
        except BitLockerError as exc:
            diag.bitlocker_failed.append(f"partition {part.addr}: {exc}")
            continue
        try:
            fs = pytsk3.FS_Info(unlocked_img)
        except IOError as exc:
            diag.bitlocker_failed.append(
                f"partition {part.addr}: unlocked but FS open failed: {exc}"
            )
            continue
        diag.bitlocker_unlocked.append(part.addr)
        diag.filesystems_opened += 1
        diag.fs_types.append(_fs_type_name(fs) + "(BitLocker)")
        yield fs, None
        # BitLocker partitions can hold VSS snapshots too — once unlocked,
        # the unlocked Img_Info itself is our raw NTFS source. Stream a
        # file-like view of it for snapshot enumeration.
        if include_snapshots and fs.info.ftype == pytsk3.TSK_FS_TYPE_NTFS:
            fo = _PartitionFileObject(unlocked_img, 0, unlocked_img.get_size())
            yield from _yield_snapshots(fo, diag)


def _open_dir(fs: "pytsk3.FS_Info", path: str) -> Optional["pytsk3.Directory"]:
    try:
        return fs.open_dir(path=path)
    except IOError:
        return None


def _file_bytes(fs: "pytsk3.FS_Info", fs_file) -> bytes:
    """Read a TSK file completely into memory.

    Browser DBs are tens-of-MB at most so this stays well under our
    budget; streaming would only matter for full-disk carving.
    """
    try:
        size = fs_file.info.meta.size
    except AttributeError:
        return b""
    if not size or size <= 0:
        return b""
    chunks: list[bytes] = []
    offset = 0
    remaining = size
    while remaining > 0:
        read = min(remaining, 1 << 20)  # 1 MiB
        try:
            data = fs_file.read_random(offset, read)
        except IOError:
            break
        if not data:
            break
        chunks.append(data)
        offset += len(data)
        remaining -= len(data)
    return b"".join(chunks)


def _safe_iter_dir(directory: "pytsk3.Directory") -> Iterator[Tuple[object, str]]:
    for entry in directory:
        try:
            name = entry.info.name.name.decode("utf-8", errors="replace")
        except AttributeError:
            continue
        if name in (".", ".."):
            continue
        yield entry, name


def _is_dir(entry) -> bool:
    try:
        return bool(entry.info.meta) and entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR
    except AttributeError:
        return False


def _is_regular(entry) -> bool:
    try:
        return bool(entry.info.meta) and entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_REG
    except AttributeError:
        return False


# ---------------------------------------------------------------------------
# Locator
# ---------------------------------------------------------------------------


class ImageProfileLocator:
    """Walk an image and stage every browser profile we can find.

    Use as a context manager so the temp directory is wiped on exit::

        with ImageProfileLocator(path) as locator:
            for staged in locator.locate():
                ...
            diag = locator.diagnostic
    """

    def __init__(
        self,
        image_path: str | Path,
        bitlocker_credentials: Optional[BitLockerCredentials] = None,
    ) -> None:
        if not _HAS_TSK:
            raise ForensicImageError("pytsk3 not installed; cannot read images.")
        self.image_path = str(image_path)
        self._img = None
        self._tmpdir: Optional[Path] = None
        self.diagnostic = ImageScanDiagnostic(image_path=self.image_path)
        self.bitlocker_credentials = bitlocker_credentials
        self._current_snapshot: Optional[SnapshotInfo] = None

    def __enter__(self) -> "ImageProfileLocator":
        self._img = open_image(self.image_path)
        self._tmpdir = Path(tempfile.mkdtemp(prefix="wf_image_"))
        return self

    def __exit__(self, *_exc) -> None:
        if self._img is not None:
            try:
                self._img.close()
            except Exception:  # noqa: BLE001
                pass
            self._img = None
        if self._tmpdir is not None:
            shutil.rmtree(self._tmpdir, ignore_errors=True)
            self._tmpdir = None

    # --- Iteration --------------------------------------------------------

    def locate(self) -> Iterator[LocatedProfile]:
        if self._img is None or self._tmpdir is None:
            raise RuntimeError("locate() called outside the context manager")

        for fs, snap_info in _iter_filesystems(
            self._img, self.diagnostic, self.bitlocker_credentials,
        ):
            # Stash the active snapshot label so staging methods can
            # tag profile names + temp paths without threading a parameter
            # through every helper.
            self._current_snapshot = snap_info
            yielded_for_this_fs = 0

            # Pass 1: standard Windows user roots.
            for root in _USER_ROOTS:
                users_dir = _open_dir(fs, root)
                if users_dir is None:
                    continue
                self.diagnostic.user_roots_seen.append(root)
                for user_entry, user_name in _safe_iter_dir(users_dir):
                    if user_name in _SYSTEM_USERS or not _is_dir(user_entry):
                        continue
                    self.diagnostic.users_found.append(user_name)
                    for staged in self._scan_user(fs, user_name, root):
                        yielded_for_this_fs += 1
                        self.diagnostic.profiles_staged += 1
                        yield staged

            # Pass 2: fall back to deep-scanning the FS for AppData dirs.
            # This catches partition-only images, oddly-mounted profiles,
            # and non-standard installs that the Pass-1 paths miss.
            for appdata_path, user_name in self._deep_scan_appdata(fs):
                self.diagnostic.appdata_dirs_found.append(appdata_path)
                for staged in self._scan_appdata(fs, appdata_path, user_name):
                    yielded_for_this_fs += 1
                    self.diagnostic.profiles_staged += 1
                    yield staged

            if yielded_for_this_fs == 0:
                label = snap_info.label if snap_info else "live"
                self.diagnostic.notes.append(
                    f"Filesystem ({_fs_type_name(fs)}, {label}) had no browser profiles."
                )

    # --- Per-user scans ---------------------------------------------------

    def _scan_user(self, fs, user_name: str, user_root: str) -> Iterator[LocatedProfile]:
        appdata_local = f"{user_root}/{user_name}/AppData/Local"
        appdata_roam = f"{user_root}/{user_name}/AppData/Roaming"

        # XP / Server 2003 puts everything under "Local Settings" and "Application Data".
        if user_root == "/Documents and Settings":
            xp_local = f"{user_root}/{user_name}/Local Settings/Application Data"
            xp_roam = f"{user_root}/{user_name}/Application Data"
            yield from self._scan_appdata_pair(fs, user_name, xp_local, xp_roam)

        yield from self._scan_appdata_pair(fs, user_name, appdata_local, appdata_roam)

    def _scan_appdata(self, fs, appdata_root: str, user_name: str) -> Iterator[LocatedProfile]:
        """Scan a single AppData dir for browser profiles.

        Used by the deep-scan fallback when we can't pair Local + Roaming.
        We try both naming conventions: ``Local`` vs ``Roaming`` are
        usually siblings, so if we landed on one we still want to glance
        at the other.
        """
        # If the deep-scan handed us ``.../AppData``, look at both children.
        appdata = appdata_root.rstrip("/")
        local = f"{appdata}/Local"
        roaming = f"{appdata}/Roaming"
        yield from self._scan_appdata_pair(fs, user_name, local, roaming)

    def _scan_appdata_pair(
        self,
        fs,
        user_name: str,
        local: str,
        roaming: str,
    ) -> Iterator[LocatedProfile]:
        # Chrome-style "User Data/<Profile>" browsers (Local).
        chromium_browsers = {
            "Chrome":   f"{local}/Google/Chrome/User Data",
            "Edge":     f"{local}/Microsoft/Edge/User Data",
            "Brave":    f"{local}/BraveSoftware/Brave-Browser/User Data",
            "Vivaldi":  f"{local}/Vivaldi/User Data",
            "Chromium": f"{local}/Chromium/User Data",
        }
        for browser_name, user_data_path in chromium_browsers.items():
            yield from self._scan_chromium_user_data(fs, browser_name, user_name, user_data_path)

        # Opera variants flatten the layout — User Data *is* the profile dir,
        # so there's only ever a single profile per install. They live under
        # Roaming on modern Windows.
        opera_variants = {
            "Opera":    f"{roaming}/Opera Software/Opera Stable",
            "Opera GX": f"{roaming}/Opera Software/Opera GX Stable",
        }
        for browser_name, profile_path in opera_variants.items():
            profile_dir = _open_dir(fs, profile_path)
            if profile_dir is None:
                continue
            local_state_bytes = self._read_file(fs, f"{profile_path}/Local State")
            staged = self._stage_chromium(
                fs, browser_name, user_name, browser_name,
                profile_path, local_state_bytes,
            )
            if staged is not None:
                yield staged

        # Firefox and Tor Browser share the same on-disk format.
        firefox_root = f"{roaming}/Mozilla/Firefox/Profiles"
        ff_dir = _open_dir(fs, firefox_root)
        if ff_dir is not None:
            for entry, name in _safe_iter_dir(ff_dir):
                if not _is_dir(entry):
                    continue
                staged = self._stage_firefox(
                    fs, user_name, name, f"{firefox_root}/{name}", "Firefox",
                )
                if staged is not None:
                    yield staged

        # Tor Browser is usually portable; check the most common spots.
        # Note: ``local`` and ``roaming`` give us the per-user candidates,
        # but Tor is often unpacked into the Desktop or root of the user
        # directory — derive a user-root by chopping off /AppData/Local.
        user_dir = local.rsplit("/AppData", 1)[0]
        tor_candidates = [
            f"{user_dir}/Desktop/Tor Browser/Browser/TorBrowser/Data/Browser/profile.default",
            f"{local}/Tor Browser/Browser/TorBrowser/Data/Browser/profile.default",
            f"{user_dir}/Downloads/Tor Browser/Browser/TorBrowser/Data/Browser/profile.default",
        ]
        for tor_path in tor_candidates:
            tor_dir = _open_dir(fs, tor_path)
            if tor_dir is None:
                continue
            staged = self._stage_firefox(
                fs, user_name, "profile.default", tor_path, "Tor Browser",
            )
            if staged is not None:
                yield staged

    def _scan_chromium_user_data(
        self,
        fs,
        browser_name: str,
        user_name: str,
        user_data_path: str,
    ) -> Iterator[LocatedProfile]:
        user_data = _open_dir(fs, user_data_path)
        if user_data is None:
            return
        local_state_bytes = self._read_file(fs, f"{user_data_path}/Local State")
        for entry, name in _safe_iter_dir(user_data):
            if not _is_dir(entry):
                continue
            if name == "Default" or name.startswith("Profile "):
                staged = self._stage_chromium(
                    fs, browser_name, user_name, name,
                    f"{user_data_path}/{name}",
                    local_state_bytes,
                )
                if staged is not None:
                    yield staged

    # --- Deep scan --------------------------------------------------------

    def _deep_scan_appdata(self, fs) -> Iterator[Tuple[str, str]]:
        """Recursively walk the FS root for ``AppData`` directories.

        Yields ``(appdata_path, user_name)`` for each one found. Used as a
        last-resort fallback so partition-only / non-standard images still
        surface their profiles. Depth is capped to avoid pathological walks.
        """
        seen: set[str] = set()
        stack: list[Tuple[str, int]] = [("/", 0)]
        while stack:
            current, depth = stack.pop()
            if depth > _DEEP_SCAN_MAX_DEPTH:
                continue
            directory = _open_dir(fs, current)
            if directory is None:
                continue
            for entry, name in _safe_iter_dir(directory):
                if not _is_dir(entry):
                    continue
                # Skip well-known noise directories so we don't recurse forever.
                if name in (
                    "Windows", "$Recycle.Bin", "$RECYCLE.BIN",
                    "System Volume Information", "$Extend", "$OrphanFiles",
                    "ProgramData", "Program Files", "Program Files (x86)",
                    "Recovery", "PerfLogs", "MSOCache",
                ):
                    continue
                child = f"{current.rstrip('/')}/{name}"
                if name == "AppData":
                    if child in seen:
                        continue
                    seen.add(child)
                    # Best-effort user name = the directory holding AppData.
                    parent = current.rstrip("/").rsplit("/", 1)[-1] or "unknown"
                    yield child, parent
                    # Don't descend into AppData (the standard scan will).
                    continue
                stack.append((child, depth + 1))

    # --- Staging ----------------------------------------------------------

    def _snapshot_suffix(self) -> str:
        """Empty string for live volumes, ``"@<label>"`` for VSS snapshots."""
        snap = self._current_snapshot
        return f"@{snap.label}" if snap is not None else ""

    def _stage_chromium(
        self,
        fs,
        browser: str,
        user: str,
        profile_name: str,
        profile_path: str,
        local_state: bytes,
    ) -> Optional[LocatedProfile]:
        profile_dir = _open_dir(fs, profile_path)
        if profile_dir is None:
            return None

        # ``User Data`` is the parent of the profile and must contain ``Local State``
        # for the Chromium decryptor to find it. Snapshot-derived stages
        # get their own subtree so different snapshots of the same user
        # don't clobber each other.
        suffix = self._snapshot_suffix()
        staged_user = f"{user}{suffix}" if suffix else user
        out_root = self._tmpdir / browser / staged_user
        out_user_data = out_root / "User Data"
        out_profile = out_user_data / profile_name
        out_profile.mkdir(parents=True, exist_ok=True)

        if local_state:
            (out_user_data / "Local State").write_bytes(local_state)

        copied_any = False
        for entry, name in _safe_iter_dir(profile_dir):
            if name in _CHROMIUM_FILES and _is_regular(entry):
                data = _file_bytes(fs, entry)
                if data:
                    (out_profile / name).write_bytes(data)
                    copied_any = True
            elif name == "Network" and _is_dir(entry):
                self._stage_chromium_network(fs, f"{profile_path}/Network", out_profile / "Network")
                copied_any = True
            elif name == "Extensions" and _is_dir(entry):
                self._stage_extensions(fs, f"{profile_path}/Extensions", out_profile / "Extensions")
                copied_any = True
            elif name in _CHROMIUM_DIR_TREES and _is_dir(entry):
                self._stage_dir_tree(fs, f"{profile_path}/{name}", out_profile / name)
                copied_any = True

        if not copied_any:
            shutil.rmtree(out_profile, ignore_errors=True)
            return None
        return LocatedProfile(
            browser=browser,
            user=user,
            profile_name=f"{profile_name}{suffix}",
            temp_path=out_profile,
            image_source=self.image_path,
            extra={"snapshot": self._current_snapshot.label} if self._current_snapshot else {},
        )

    def _stage_chromium_network(self, fs, src_path: str, dst: Path) -> None:
        directory = _open_dir(fs, src_path)
        if directory is None:
            return
        dst.mkdir(parents=True, exist_ok=True)
        for entry, name in _safe_iter_dir(directory):
            if name in _CHROMIUM_NETWORK_FILES and _is_regular(entry):
                data = _file_bytes(fs, entry)
                if data:
                    (dst / name).write_bytes(data)

    def _stage_extensions(self, fs, src_path: str, dst: Path) -> None:
        # For extensions we only need manifest.json files — copy the whole
        # layout but stop at one manifest per version to keep it small.
        ext_dir = _open_dir(fs, src_path)
        if ext_dir is None:
            return
        dst.mkdir(parents=True, exist_ok=True)
        for ext_entry, ext_id in _safe_iter_dir(ext_dir):
            if not _is_dir(ext_entry):
                continue
            ext_path = src_path + "/" + ext_id
            inner = _open_dir(fs, ext_path)
            if inner is None:
                continue
            ext_dst = dst / ext_id
            ext_dst.mkdir(parents=True, exist_ok=True)
            for ver_entry, version in _safe_iter_dir(inner):
                if not _is_dir(ver_entry):
                    continue
                ver_path = ext_path + "/" + version
                ver_dir = _open_dir(fs, ver_path)
                if ver_dir is None:
                    continue
                ver_dst = ext_dst / version
                ver_dst.mkdir(parents=True, exist_ok=True)
                for file_entry, file_name in _safe_iter_dir(ver_dir):
                    if file_name == "manifest.json" and _is_regular(file_entry):
                        data = _file_bytes(fs, file_entry)
                        if data:
                            (ver_dst / file_name).write_bytes(data)

    def _stage_dir_tree(
        self,
        fs,
        src_path: str,
        dst: Path,
        max_depth: int = 6,
    ) -> None:
        """Mirror a directory tree from the image into the temp area.

        Used for Local Storage / Session Storage / IndexedDB / Sessions —
        every shard matters for these so we copy the lot. Depth is capped
        because a corrupted FS can otherwise loop forever.
        """
        stack: list[Tuple[str, Path, int]] = [(src_path, dst, 0)]
        while stack:
            src, out, depth = stack.pop()
            if depth > max_depth:
                continue
            directory = _open_dir(fs, src)
            if directory is None:
                continue
            out.mkdir(parents=True, exist_ok=True)
            for entry, name in _safe_iter_dir(directory):
                if _is_regular(entry):
                    data = _file_bytes(fs, entry)
                    if data:
                        try:
                            (out / name).write_bytes(data)
                        except OSError:
                            # Long names / illegal chars on Windows — skip.
                            continue
                elif _is_dir(entry):
                    stack.append((f"{src}/{name}", out / name, depth + 1))

    def _stage_firefox(
        self,
        fs,
        user: str,
        profile_name: str,
        profile_path: str,
        browser_label: str = "Firefox",
    ) -> Optional[LocatedProfile]:
        profile_dir = _open_dir(fs, profile_path)
        if profile_dir is None:
            return None
        suffix = self._snapshot_suffix()
        staged_user = f"{user}{suffix}" if suffix else user
        out_path = self._tmpdir / browser_label / staged_user / profile_name
        out_path.mkdir(parents=True, exist_ok=True)
        copied_any = False
        for entry, name in _safe_iter_dir(profile_dir):
            if name in _FIREFOX_FILES and _is_regular(entry):
                data = _file_bytes(fs, entry)
                if data:
                    (out_path / name).write_bytes(data)
                    copied_any = True
            elif name in _FIREFOX_DIR_TREES and _is_dir(entry):
                self._stage_dir_tree(fs, f"{profile_path}/{name}", out_path / name)
                copied_any = True
        if not copied_any:
            shutil.rmtree(out_path, ignore_errors=True)
            return None
        return LocatedProfile(
            browser=browser_label,
            user=user,
            profile_name=f"{profile_name}{suffix}",
            temp_path=out_path,
            image_source=self.image_path,
            extra={"snapshot": self._current_snapshot.label} if self._current_snapshot else {},
        )

    def _read_file(self, fs, path: str) -> bytes:
        try:
            f = fs.open(path)
        except IOError:
            return b""
        return _file_bytes(fs, f)


# ---------------------------------------------------------------------------
# Stand-alone probes (no staging)
# ---------------------------------------------------------------------------


@dataclass
class ImageProbeResult:
    """Lightweight summary of what's inside an image without staging."""

    bitlocker_partitions: list[BitLockerPartition] = field(default_factory=list)
    other_partitions: int = 0
    #: ``True`` when at least one BitLocker partition uses a format that
    #: libbde-python cannot parse. In that case the analyst must unlock
    #: the volume externally (Windows BitLocker / dislocker / Arsenal
    #: Image Mounter) and rerun WebForensics against the mounted drive.
    libbde_incompatible: bool = False
    libbde_error: str = ""


def probe_image(image_path: str | Path) -> ImageProbeResult:
    """Quickly enumerate partitions and detect BitLocker without staging.

    Used by the UI so we can prompt for BitLocker credentials *before*
    spinning up the long-running extraction worker. Cheap: opens the
    image, reads 16 bytes per partition for the BitLocker signature,
    then closes.

    When BitLocker partitions are found we also check whether the
    installed ``libbde`` can parse their metadata. Newer BitLocker
    variants (Windows 10/11 with XTS-AES + new entry types) can defeat
    libbde even with a valid recovery key, so the result carries an
    explicit flag the UI can use to tell the analyst what to do.
    """
    if not _HAS_TSK:
        raise ForensicImageError("pytsk3 not installed; cannot read images.")
    img = open_image(image_path)
    try:
        try:
            locked = detect_bitlocker_partitions(img)
        except BitLockerError:
            locked = []
        try:
            volume = pytsk3.Volume_Info(img)
            other = sum(
                1 for p in volume
                if p.len > 0 and p.flags == pytsk3.TSK_VS_PART_FLAG_ALLOC
            )
        except IOError:
            other = 0

        # If we found any BitLocker partitions, do a no-credentials open
        # to see whether libbde can even parse the metadata. We only
        # need to test one — the others are very likely the same format.
        libbde_incompatible = False
        libbde_error = ""
        if locked:
            try:
                import pybde
                from forensics.bitlocker import _PartitionFileObject
                fo = _PartitionFileObject(img, locked[0].byte_offset, locked[0].byte_length)
                vol = pybde.volume()
                try:
                    vol.open_file_object(fo)
                    # libbde could read the metadata: it's a supported format.
                    vol.close()
                except IOError as exc:
                    msg = str(exc)
                    if (
                        "unsupported FVE metadata entry version" in msg
                        or "unable to read primary metadata block" in msg
                        or "unsupported encryption method" in msg
                    ):
                        libbde_incompatible = True
                        libbde_error = msg
            except ImportError:
                # pybde isn't installed at all — extractor will report
                # that separately when it actually tries to unlock.
                pass

        return ImageProbeResult(
            bitlocker_partitions=locked,
            other_partitions=other,
            libbde_incompatible=libbde_incompatible,
            libbde_error=libbde_error,
        )
    finally:
        try:
            img.close()
        except Exception:  # noqa: BLE001
            pass
