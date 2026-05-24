"""Tor Browser — Firefox derivative with a bundled profile.

Same on-disk format as Firefox (places.sqlite, cookies.sqlite, etc.) — the
only difference is *where* the profile lives. The browser ships with the
profile inside its own install directory, so we don't search the standard
Mozilla locations.

We do not attempt to detect a running tor-launcher state; this is purely
post-mortem profile reading like every other extractor.
"""

from __future__ import annotations

import configparser
import logging
from pathlib import Path
from typing import Iterable

from browsers.base import BrowserProfile
from browsers.firefox import FirefoxBrowser
from utils.paths import is_firefox_profile_dir, tor_profiles_dirs

logger = logging.getLogger(__name__)


class TorBrowser(FirefoxBrowser):
    """Firefox extractor pointed at Tor Browser's bundled profile."""

    name = "Tor Browser"

    def discover_profiles(self) -> list[BrowserProfile]:
        seen: set[Path] = set()
        out: list[BrowserProfile] = []
        for candidate in tor_profiles_dirs():
            if is_firefox_profile_dir(candidate) and candidate not in seen:
                seen.add(candidate)
                out.append(BrowserProfile(self.name, candidate.name, candidate))
            # Some Tor installs use a profiles.ini alongside the Data folder.
            ini = candidate.parent / "profiles.ini"
            if ini.is_file():
                out.extend(self._profiles_from_tor_ini(ini))
        # De-dup by resolved path.
        unique: dict[Path, BrowserProfile] = {}
        for prof in out:
            try:
                resolved = prof.path.resolve()
            except OSError:
                resolved = prof.path
            unique.setdefault(resolved, prof)
        return list(unique.values())

    def _profiles_from_tor_ini(self, ini_path: Path) -> Iterable[BrowserProfile]:
        parser = configparser.ConfigParser()
        try:
            parser.read(ini_path, encoding="utf-8")
        except (OSError, configparser.Error) as exc:
            logger.debug("Tor profiles.ini unreadable: %s", exc)
            return
        for section in parser.sections():
            if not section.lower().startswith("profile"):
                continue
            path = parser.get(section, "Path", fallback=None)
            if not path:
                continue
            is_rel = parser.getboolean(section, "IsRelative", fallback=True)
            full = (ini_path.parent / path).resolve() if is_rel else Path(path)
            if is_firefox_profile_dir(full):
                yield BrowserProfile(self.name, full.name, full)
