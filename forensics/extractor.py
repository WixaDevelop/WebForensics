"""Walk a forensic image and stage browser profiles for the existing extractors.

What we do, in order:

1.  ``open_image`` gets us a TSK ``Img_Info``.
2.  We enumerate partitions; for each NTFS partition we open an ``FS_Info``.
3.  We list ``/Users/`` (skipping the system accounts) and, for every user,
    look at the usual paths for Chrome, Edge and Firefox.
4.  Profile files we care about are *copied out* to a temp directory that
    mirrors the layout the live extractors expect. From there, the existing
    ``ChromeBrowser`` / ``EdgeBrowser`` / ``FirefoxBrowser`` work unchanged.

We deliberately keep the file copy minimal — only the SQLite databases,
``Local State``, ``Bookmarks`` JSON, ``extensions.json`` and the
``Extensions/`` directory. Pulling the whole profile would be huge.
"""

from __future__ import annotations

import logging
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Iterator, Optional

try:  # pragma: no cover — optional native deps
    import pytsk3  # type: ignore[import-not-found]
    _HAS_TSK = True
except Exception:  # noqa: BLE001
    _HAS_TSK = False

from forensics.image import ForensicImageError, open_image

logger = logging.getLogger(__name__)


# Per-browser allow-list. Anything not in here we ignore — it would just bloat
# the copy and is irrelevant to the artifact extractors.
_CHROMIUM_FILES = (
    "History", "History-journal",
    "Cookies", "Cookies-journal",
    "Login Data", "Login Data-journal",
    "Web Data", "Web Data-journal",
    "Bookmarks",
)
_CHROMIUM_NETWORK_FILES = ("Cookies", "Cookies-journal")
_FIREFOX_FILES = (
    "places.sqlite", "places.sqlite-wal", "places.sqlite-shm",
    "cookies.sqlite", "cookies.sqlite-wal", "cookies.sqlite-shm",
    "formhistory.sqlite",
    "logins.json", "key4.db", "extensions.json",
)


# System accounts that never have a real browser profile — skip them quickly.
_SYSTEM_USERS = {
    "All Users", "Default", "Default User", "Default.migrated",
    "Public", "desktop.ini",
}


@dataclass
class LocatedProfile:
    """A profile staged into a temp folder, ready for the live extractors."""

    browser: str
    user: str           # Windows account name from \Users\
    profile_name: str   # ``Default``, ``Profile 1``, or Firefox profile name
    temp_path: Path     # Where we copied the files
    image_source: str   # Original image path for audit / hashing
    extra: dict = field(default_factory=dict)

    @property
    def display(self) -> str:
        return f"{self.browser}[{self.user}/{self.profile_name}]"


# ---------------------------------------------------------------------------
# Helpers around pytsk3
# ---------------------------------------------------------------------------


def _iter_ntfs_volumes(img) -> Iterator["pytsk3.FS_Info"]:
    """Yield mountable NTFS volumes for *img*.

    Tries the standard partition-table path first and falls back to opening
    the image as a single volume — useful for partition-image dumps.
    """
    try:
        volume = pytsk3.Volume_Info(img)
    except IOError:
        # No partition table — assume the image is a single filesystem.
        try:
            yield pytsk3.FS_Info(img)
        except IOError:
            return
        return

    for part in volume:
        # Skip unallocated / metadata-only entries.
        if part.len <= 0 or part.flags == pytsk3.TSK_VS_PART_FLAG_UNALLOC:
            continue
        try:
            fs = pytsk3.FS_Info(img, offset=part.start * 512)
        except IOError:
            continue
        # We only care about NTFS volumes on Windows machines.
        if fs.info.ftype == pytsk3.TSK_FS_TYPE_NTFS:
            yield fs


def _open_dir(fs: "pytsk3.FS_Info", path: str) -> Optional["pytsk3.Directory"]:
    try:
        return fs.open_dir(path=path)
    except IOError:
        return None


def _file_bytes(fs: "pytsk3.FS_Info", fs_file) -> bytes:
    """Read a TSK file completely into memory.

    Browser DBs are tens-of-MB at most so this stays well under our budget;
    streaming would only matter for full-disk carving.
    """
    size = fs_file.info.meta.size
    if size <= 0:
        return b""
    chunks: list[bytes] = []
    offset = 0
    remaining = size
    while remaining > 0:
        read = min(remaining, 1 << 20)  # 1 MiB
        data = fs_file.read_random(offset, read)
        if not data:
            break
        chunks.append(data)
        offset += len(data)
        remaining -= len(data)
    return b"".join(chunks)


def _safe_iter_dir(directory: "pytsk3.Directory") -> Iterator:
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
        return entry.info.meta and entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR
    except AttributeError:
        return False


def _is_regular(entry) -> bool:
    try:
        return entry.info.meta and entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_REG
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
    """

    def __init__(self, image_path: str | Path) -> None:
        if not _HAS_TSK:
            raise ForensicImageError("pytsk3 not installed; cannot read images.")
        self.image_path = str(image_path)
        self._img = None
        self._tmpdir: Optional[Path] = None

    def __enter__(self) -> "ImageProfileLocator":
        self._img = open_image(self.image_path)
        self._tmpdir = Path(tempfile.mkdtemp(prefix="wf_image_"))
        return self

    def __exit__(self, *_exc) -> None:
        # Close TSK / pyewf cleanly.
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

        for fs in _iter_ntfs_volumes(self._img):
            users_dir = _open_dir(fs, "/Users")
            if users_dir is None:
                continue
            for user_entry, user_name in _safe_iter_dir(users_dir):
                if user_name in _SYSTEM_USERS or not _is_dir(user_entry):
                    continue
                yield from self._scan_user(fs, user_name)

    # --- Per-user scans ---------------------------------------------------

    def _scan_user(self, fs, user_name: str) -> Iterator[LocatedProfile]:
        # Browsers that follow the Chrome-style "User Data/<Profile>" layout.
        chromium_browsers = {
            "Chrome":   f"/Users/{user_name}/AppData/Local/Google/Chrome/User Data",
            "Edge":     f"/Users/{user_name}/AppData/Local/Microsoft/Edge/User Data",
            "Brave":    f"/Users/{user_name}/AppData/Local/BraveSoftware/Brave-Browser/User Data",
            "Vivaldi":  f"/Users/{user_name}/AppData/Local/Vivaldi/User Data",
        }
        for browser_name, user_data_path in chromium_browsers.items():
            yield from self._scan_chromium_user_data(fs, browser_name, user_name, user_data_path)

        # Opera variants flatten the layout — User Data *is* the profile dir,
        # so there's only ever a single profile per install.
        opera_variants = {
            "Opera":    f"/Users/{user_name}/AppData/Roaming/Opera Software/Opera Stable",
            "Opera GX": f"/Users/{user_name}/AppData/Roaming/Opera Software/Opera GX Stable",
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
        firefox_root = f"/Users/{user_name}/AppData/Roaming/Mozilla/Firefox/Profiles"
        ff_dir = _open_dir(fs, firefox_root)
        if ff_dir is not None:
            for entry, name in _safe_iter_dir(ff_dir):
                if not _is_dir(entry):
                    continue
                staged = self._stage_firefox(fs, user_name, name, f"{firefox_root}/{name}", "Firefox")
                if staged is not None:
                    yield staged

        # Tor Browser is usually portable, but check common install spots.
        tor_candidates = [
            f"/Users/{user_name}/Desktop/Tor Browser/Browser/TorBrowser/Data/Browser/profile.default",
            f"/Users/{user_name}/AppData/Local/Tor Browser/Browser/TorBrowser/Data/Browser/profile.default",
        ]
        for tor_path in tor_candidates:
            tor_dir = _open_dir(fs, tor_path)
            if tor_dir is None:
                continue
            staged = self._stage_firefox(fs, user_name, "profile.default", tor_path, "Tor Browser")
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

    # --- Staging ----------------------------------------------------------

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
        # for the Chromium decryptor to find it.
        out_root = self._tmpdir / browser / user
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

        if not copied_any:
            shutil.rmtree(out_profile, ignore_errors=True)
            return None
        return LocatedProfile(
            browser=browser,
            user=user,
            profile_name=profile_name,
            temp_path=out_profile,
            image_source=self.image_path,
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
        out_path = self._tmpdir / browser_label / user / profile_name
        out_path.mkdir(parents=True, exist_ok=True)
        copied_any = False
        for entry, name in _safe_iter_dir(profile_dir):
            if name in _FIREFOX_FILES and _is_regular(entry):
                data = _file_bytes(fs, entry)
                if data:
                    (out_path / name).write_bytes(data)
                    copied_any = True
        if not copied_any:
            shutil.rmtree(out_path, ignore_errors=True)
            return None
        return LocatedProfile(
            browser=browser_label,
            user=user,
            profile_name=profile_name,
            temp_path=out_path,
            image_source=self.image_path,
        )

    def _read_file(self, fs, path: str) -> bytes:
        try:
            f = fs.open(path)
        except IOError:
            return b""
        return _file_bytes(fs, f)
