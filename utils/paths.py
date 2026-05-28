"""Default filesystem locations of browser profiles on Windows.

These helpers only *describe* where profiles normally live; they do not assume
the user is on Windows — on other platforms they fall back to the relevant
``$HOME`` subdirectories so the auto-detector still works in development.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import List


def _env_path(name: str) -> Path:
    """Return the value of an environment variable as a Path (may not exist)."""
    return Path(os.environ.get(name, ""))


def _windows_roots() -> dict[str, Path]:
    return {
        "local": _env_path("LOCALAPPDATA"),
        "roaming": _env_path("APPDATA"),
    }


def _posix_roots() -> dict[str, Path]:
    home = Path.home()
    if sys.platform == "darwin":
        return {
            "local": home / "Library" / "Application Support",
            "roaming": home / "Library" / "Application Support",
        }
    # Linux / other
    return {
        "local": home / ".config",
        "roaming": home / ".config",
    }


def system_roots() -> dict[str, Path]:
    """Per-OS base directories where browsers store user data."""
    return _windows_roots() if sys.platform == "win32" else _posix_roots()


# Each entry is a list of *candidate* user-data directories that hold one or
# more Chromium-style profile folders ("Default", "Profile 1", ...).
def chrome_user_data_dirs() -> List[Path]:
    roots = system_roots()
    if sys.platform == "win32":
        return [roots["local"] / "Google" / "Chrome" / "User Data"]
    if sys.platform == "darwin":
        return [roots["local"] / "Google" / "Chrome"]
    return [
        Path.home() / ".config" / "google-chrome",
        Path.home() / ".config" / "chromium",
    ]


def edge_user_data_dirs() -> List[Path]:
    roots = system_roots()
    if sys.platform == "win32":
        return [roots["local"] / "Microsoft" / "Edge" / "User Data"]
    if sys.platform == "darwin":
        return [roots["local"] / "Microsoft Edge"]
    return [Path.home() / ".config" / "microsoft-edge"]


def brave_user_data_dirs() -> List[Path]:
    roots = system_roots()
    if sys.platform == "win32":
        return [roots["local"] / "BraveSoftware" / "Brave-Browser" / "User Data"]
    if sys.platform == "darwin":
        return [roots["local"] / "BraveSoftware" / "Brave-Browser"]
    return [Path.home() / ".config" / "BraveSoftware" / "Brave-Browser"]


def opera_user_data_dirs() -> List[Path]:
    roots = system_roots()
    # Opera is one of the few Chromium browsers that uses Roaming on Windows,
    # and treats the profile dir as the User Data dir (no Default subfolder).
    if sys.platform == "win32":
        return [roots["roaming"] / "Opera Software" / "Opera Stable"]
    if sys.platform == "darwin":
        return [roots["local"] / "com.operasoftware.Opera"]
    return [Path.home() / ".config" / "opera"]


def opera_gx_user_data_dirs() -> List[Path]:
    roots = system_roots()
    if sys.platform == "win32":
        return [roots["roaming"] / "Opera Software" / "Opera GX Stable"]
    if sys.platform == "darwin":
        return [roots["local"] / "com.operasoftware.OperaGX"]
    return [Path.home() / ".config" / "opera-gx"]


def vivaldi_user_data_dirs() -> List[Path]:
    roots = system_roots()
    if sys.platform == "win32":
        return [roots["local"] / "Vivaldi" / "User Data"]
    if sys.platform == "darwin":
        return [roots["local"] / "Vivaldi"]
    return [Path.home() / ".config" / "vivaldi"]


def tor_profiles_dirs() -> List[Path]:
    """Tor Browser ships its own Firefox profile inside its install dir.

    There is no fixed install location so we list the common ones — the
    analyst can still point at a custom path via the manual loader.
    """
    candidates: list[Path] = []
    if sys.platform == "win32":
        roots = system_roots()
        candidates += [
            roots["local"] / "Tor Browser" / "Browser" / "TorBrowser" / "Data" / "Browser" / "profile.default",
            Path("C:/Tor Browser/Browser/TorBrowser/Data/Browser/profile.default"),
            Path.home() / "Desktop" / "Tor Browser" / "Browser" / "TorBrowser" / "Data" / "Browser" / "profile.default",
        ]
    elif sys.platform == "darwin":
        candidates += [
            Path("/Applications/Tor Browser.app/Contents/Resources/TorBrowser/Data/Browser/profile.default"),
        ]
    else:
        candidates += [
            Path.home() / ".tor-browser" / "app" / "Browser" / "TorBrowser" / "Data" / "Browser" / "profile.default",
            Path.home() / "tor-browser" / "Browser" / "TorBrowser" / "Data" / "Browser" / "profile.default",
        ]
    return candidates


def firefox_profiles_dirs() -> List[Path]:
    roots = system_roots()
    if sys.platform == "win32":
        return [roots["roaming"] / "Mozilla" / "Firefox" / "Profiles"]
    if sys.platform == "darwin":
        return [roots["local"] / "Firefox" / "Profiles"]
    return [Path.home() / ".mozilla" / "firefox"]


_SQLITE_MAGIC = b"SQLite format 3\x00"


def _has_sqlite_magic(path: Path) -> bool:
    """Return True when *path* starts with the standard SQLite header.

    The SQLite header is invariant — every real Chrome / Firefox DB has
    it, and decoy files (a random ``History`` placeholder, a stale
    forensic export saved as text, etc.) almost never do. Reading 16
    bytes is cheap and lets the recursive scanner reject false positives
    without an expensive ``open_browser_db`` round-trip.
    """
    try:
        with path.open("rb") as fh:
            return fh.read(16) == _SQLITE_MAGIC
    except OSError:
        return False


def is_chromium_profile_dir(path: Path) -> bool:
    """A Chromium profile directory contains a ``History`` SQLite file."""
    if not path.is_dir():
        return False
    history = path / "History"
    if not history.is_file():
        return False
    return _has_sqlite_magic(history)


def is_firefox_profile_dir(path: Path) -> bool:
    """Firefox profile directories contain ``places.sqlite``."""
    if not path.is_dir():
        return False
    places = path / "places.sqlite"
    if not places.is_file():
        return False
    return _has_sqlite_magic(places)


# Browser names that may appear as path components in installed / staged
# profile trees. Order matters: longer / more specific names first.
_BROWSER_PATH_HINTS: tuple[tuple[str, str], ...] = (
    ("opera gx",        "Opera GX"),
    ("operagx",         "Opera GX"),
    ("opera software",  "Opera"),
    ("opera stable",    "Opera"),
    ("opera",           "Opera"),
    ("tor browser",     "Tor Browser"),
    ("torbrowser",      "Tor Browser"),
    ("microsoft\\edge", "Edge"),
    ("microsoft/edge",  "Edge"),
    ("msedge",          "Edge"),
    ("edge",            "Edge"),
    ("bravesoftware",   "Brave"),
    ("brave-browser",   "Brave"),
    ("brave",           "Brave"),
    ("vivaldi",         "Vivaldi"),
    ("chromium",        "Chrome"),
    ("google\\chrome",  "Chrome"),
    ("google/chrome",   "Chrome"),
    ("chrome",          "Chrome"),
    ("mozilla\\firefox", "Firefox"),
    ("mozilla/firefox",  "Firefox"),
    ("firefox",         "Firefox"),
)


def infer_browser_from_path(path: Path) -> str | None:
    """Best-effort browser-name inference from path components.

    Returns ``None`` when nothing matches so callers can apply their own
    default (e.g. "Chrome" for Chromium-shaped profiles, "Firefox" for
    places.sqlite-shaped profiles).
    """
    needle = str(path).lower()
    for token, label in _BROWSER_PATH_HINTS:
        if token in needle:
            return label
    return None
