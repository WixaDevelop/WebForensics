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
from forensics import ForensicImageError, ImageProfileLocator

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
    ) -> Iterable[ProfileBundle]:
        """Open a forensic image, stage every profile, run extractors.

        Yields ``ProfileBundle`` objects so the UI can ingest them as they
        appear instead of waiting for the whole disk to be processed.
        """
        if progress:
            progress(f"Opening image: {image_path}")
        try:
            with ImageProfileLocator(image_path) as locator:
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
        except ForensicImageError as exc:
            logger.error("Image extraction failed: %s", exc)
            raise
