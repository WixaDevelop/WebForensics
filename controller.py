"""Application controller — single coordination point for the UI.

The UI never talks to a browser extractor directly; it goes through the
``ForensicsController``. This keeps the GUI free of business logic and makes
the extractors trivially scriptable / testable.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Callable, Iterable, Optional

from browsers import (
    BraveBrowser,
    ChromeBrowser,
    EdgeBrowser,
    FirefoxBrowser,
    OperaBrowser,
    OperaGXBrowser,
    TorBrowser,
    VivaldiBrowser,
)
from browsers.base import BrowserBase, BrowserProfile
from data.models import ProfileBundle
from forensics import BitLockerCredentials, ForensicImageError, ImageProfileLocator
from utils.paths import (
    infer_browser_from_path,
    is_chromium_profile_dir,
    is_firefox_profile_dir,
)

logger = logging.getLogger(__name__)


ProgressCallback = Callable[[str], None]


class ForensicsController:
    """Owns the browser registry and runs extractions on demand."""

    def __init__(self, browsers: Optional[Iterable[BrowserBase]] = None) -> None:
        self.browsers: list[BrowserBase] = list(browsers) if browsers else [
            ChromeBrowser(),
            EdgeBrowser(),
            BraveBrowser(),
            OperaBrowser(),
            OperaGXBrowser(),
            VivaldiBrowser(),
            FirefoxBrowser(),
            TorBrowser(),
        ]
        self._by_name = {b.name: b for b in self.browsers}

    # --- Discovery --------------------------------------------------------

    def discover_profiles(self) -> list[BrowserProfile]:
        """Auto-detect all profiles in their default OS locations."""
        found: list[BrowserProfile] = []
        for browser in self.browsers:
            try:
                found.extend(browser.discover_profiles())
            except Exception:  # noqa: BLE001 — never let one browser break discovery
                logger.exception("discover_profiles failed for %s", browser.name)
        return found

    def identify_profile(self, path: str | Path) -> BrowserProfile | None:
        """Detect which browser owns a user-selected folder."""
        target = Path(path)
        if not target.is_dir():
            return None
        for browser in self.browsers:
            try:
                profile = browser.profile_from_path(target)
            except Exception:  # noqa: BLE001
                logger.exception("profile_from_path failed for %s", browser.name)
                continue
            if profile is not None:
                return profile
        return None

    def discover_profiles_in_folder(
        self,
        folder: str | Path,
        max_depth: int = 10,
        progress: Optional[ProgressCallback] = None,
        include_vss: bool = False,
    ) -> list[BrowserProfile]:
        """Recursively scan *folder* for browser profiles.

        Designed for mounted images, USB sticks and ad-hoc evidence dumps
        where profiles can be nested at unknown depths and the standard
        ``%LOCALAPPDATA%`` layout is not present. A directory qualifies as
        a profile when it contains the corresponding signature file
        (``History`` for Chromium, ``places.sqlite`` for Firefox/Tor) and
        we infer the browser from the path components.
        """
        import os

        root = Path(folder).expanduser()
        if not root.is_dir():
            return []

        # Defaults if the inference returns nothing. Both signatures map
        # cleanly to one family — we only need the family-default fallback.
        chromium_default = "Chrome"
        firefox_default = "Firefox"

        # Dirs we never need to descend into — they are heavyweight branches
        # of a profile that cannot themselves be a profile, so skipping them
        # keeps the recursion bounded.
        skip_dirs = {
            "Cache", "Code Cache", "Service Worker", "GPUCache",
            "Local Storage", "Session Storage", "IndexedDB",
            "File System", "blob_storage", "shared_proto_db",
            "Crashpad", "DawnCache", "GraphiteDawnCache",
            "Sessions", "Cache_Data",
            "Extensions",  # contains many small subdirs, never a profile root
            "extensions",  # firefox lowercase variant
            "storage",     # firefox per-origin storage
            "datareporting", "sessionstore-backups",
            "$RECYCLE.BIN", "System Volume Information",
            "$Extend", "$OrphanFiles",
        }

        # Name prefixes that mark a directory as something WebForensics
        # itself created during a previous run — never report these.
        wf_temp_prefixes = ("wf_image_", "wf_carve_", "wf_session_")

        def _is_wf_temp(name: str) -> bool:
            return any(name.startswith(p) for p in wf_temp_prefixes)

        results: list[BrowserProfile] = []
        seen: set[Path] = set()

        for current, dirs, _files in os.walk(root):
            current_path = Path(current)
            # Never look inside our own temp output.
            if _is_wf_temp(current_path.name):
                dirs[:] = []
                continue
            try:
                depth = len(current_path.relative_to(root).parts)
            except ValueError:
                depth = max_depth
            if depth >= max_depth:
                dirs[:] = []
                continue
            # Drop known-uninteresting subtrees in place so os.walk skips them.
            dirs[:] = [
                d for d in dirs
                if d not in skip_dirs
                and not d.startswith(".")
                and not _is_wf_temp(d)
            ]

            # Chromium profile?
            if is_chromium_profile_dir(current_path) and current_path not in seen:
                browser = infer_browser_from_path(current_path) or chromium_default
                # Tor masquerades as Firefox via places.sqlite, so this branch
                # never claims Tor. Opera/OperaGX may be a leaf without
                # ``Default`` so the inference handles them.
                seen.add(current_path)
                profile_name = current_path.name
                if profile_name in ("Default", "User Data") or profile_name.startswith("Profile "):
                    # Use the parent's name when the leaf is generic, so the
                    # user can tell `Chrome/Default` from `Edge/Default`.
                    profile_name = f"{current_path.parent.name}/{current_path.name}"
                results.append(BrowserProfile(browser, profile_name, current_path))
                if progress:
                    progress(f"  found {browser} profile: {current_path}")
                # A profile directory will not contain another profile,
                # so prune the walk under it.
                dirs[:] = []
                continue

            # Firefox / Tor profile?
            if is_firefox_profile_dir(current_path) and current_path not in seen:
                browser = infer_browser_from_path(current_path) or firefox_default
                # Tor profiles look identical to Firefox; only the path can tell.
                if browser not in ("Firefox", "Tor Browser"):
                    browser = firefox_default
                seen.add(current_path)
                profile_name = current_path.name
                results.append(BrowserProfile(browser, profile_name, current_path))
                if progress:
                    progress(f"  found {browser} profile: {current_path}")
                dirs[:] = []
                continue

        if progress:
            progress(f"Folder scan complete: {len(results)} profile(s) under {root}")

        # Optionally enumerate VSS shadow copies on the same volume and
        # scan each one too. Profiles found in a snapshot are tagged in
        # their name with the snapshot timestamp.
        if include_vss:
            try:
                from forensics.vss_local import check_shadow_availability
            except ImportError:
                pass
            else:
                avail = check_shadow_availability(root)
                if progress:
                    progress(f"VSS: {avail.message_for_user}")
                for shadow in avail.shadows:
                    shadow_root = Path(shadow.access_path())
                    if progress:
                        progress(f"  scanning shadow {shadow.label} at {shadow_root}")
                    try:
                        sub_results = self.discover_profiles_in_folder(
                            shadow_root, max_depth=max_depth, progress=progress,
                            include_vss=False,
                        )
                    except Exception as exc:  # noqa: BLE001 — never let one bad shadow stop the rest
                        logger.exception("VSS scan failed for %s", shadow_root)
                        if progress:
                            progress(f"    error: {exc}")
                        continue
                    for prof in sub_results:
                        # Tag the profile so the UI groups by snapshot.
                        results.append(BrowserProfile(
                            browser=prof.browser,
                            name=f"{prof.name}@{shadow.label}",
                            path=prof.path,
                        ))
                if progress and avail.shadows:
                    progress(
                        f"VSS scan complete: {len(results)} profile(s) total "
                        f"after {len(avail.shadows)} snapshot(s)."
                    )
        return results

    # --- Extraction -------------------------------------------------------

    def extract(
        self,
        profile: BrowserProfile,
        progress: Optional[ProgressCallback] = None,
    ) -> ProfileBundle:
        """Run a full extraction for the given profile."""
        browser = self._by_name.get(profile.browser)
        if browser is None:
            raise KeyError(f"Unknown browser: {profile.browser}")
        if progress:
            progress(f"Extracting {profile.browser} — {profile.name}")
        bundle = browser.extract_all(profile)
        if progress:
            counts = ", ".join(f"{k}={v}" for k, v in bundle.summary().items() if v)
            progress(f"Done {profile.browser} — {profile.name}: {counts or 'no data'}")
        return bundle

    def extract_many(
        self,
        profiles: Iterable[BrowserProfile],
        progress: Optional[ProgressCallback] = None,
    ) -> list[ProfileBundle]:
        return [self.extract(p, progress) for p in profiles]

    # --- Forensic-image workflow ------------------------------------------

    def extract_image(
        self,
        image_path: str | Path,
        progress: Optional[ProgressCallback] = None,
        on_diagnostic: Optional[Callable[[object], None]] = None,
        bitlocker_credentials: Optional[BitLockerCredentials] = None,
    ) -> Iterable[ProfileBundle]:
        """Open a forensic image, stage every profile, run extractors.

        Yields ``ProfileBundle`` objects so the UI can ingest them as they
        appear instead of waiting for the whole disk to be processed.

        If *on_diagnostic* is provided it is called once after the scan
        completes with an :class:`ImageScanDiagnostic` so the caller can
        report partitions seen, filesystems opened and users found — even
        when no profiles came out.

        *bitlocker_credentials* are tried against every BitLocker-encrypted
        partition discovered in the image. Leave ``None`` to skip
        encrypted partitions silently (they will still show up in the
        diagnostic so the caller can prompt the analyst).
        """
        if progress:
            progress(f"Opening image: {image_path}")
        try:
            with ImageProfileLocator(image_path, bitlocker_credentials) as locator:
                try:
                    for staged in locator.locate():
                        if progress:
                            progress(f"Found {staged.display}, extracting…")
                        profile = BrowserProfile(
                            browser=staged.browser,
                            name=f"{staged.user}/{staged.profile_name}",
                            path=staged.temp_path,
                        )
                        bundle = self.extract(profile, progress)
                        # Attach a marker so the UI can tag image-derived profiles.
                        bundle.errors.append(f"[image] source={staged.image_source}")
                        yield bundle
                finally:
                    if on_diagnostic is not None:
                        try:
                            on_diagnostic(locator.diagnostic)
                        except Exception:  # noqa: BLE001
                            logger.exception("on_diagnostic callback failed")
        except ForensicImageError as exc:
            logger.error("Image extraction failed: %s", exc)
            raise
