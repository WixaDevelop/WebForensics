"""Abstract base for browser extractors.

A *browser* knows how to enumerate its own profiles and pull each artifact
kind from a profile. Concrete subclasses implement the per-format details
(SQLite tables, JSON files, encryption); the controller treats them all
through this uniform interface.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from data.models import (
    AutofillEntry,
    Bookmark,
    CacheEntry,
    Cookie,
    Download,
    Extension,
    HistoryEntry,
    Login,
    OpenTab,
    Permission,
    ProfileBundle,
    WebStorageEntry,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class BrowserProfile:
    """Identifies a single profile on disk."""

    browser: str
    name: str  # Human-readable, e.g. "Default" or "Profile 1"
    path: Path

    @property
    def display(self) -> str:
        return f"{self.browser} — {self.name}"


class BrowserBase(ABC):
    """Abstract extractor; subclasses implement the per-artifact methods."""

    #: Display name (used in the UI tree and exports).
    name: str = "Browser"

    # --- Profile discovery -------------------------------------------------

    @abstractmethod
    def discover_profiles(self) -> list[BrowserProfile]:
        """Locate this browser's profiles in their default install locations."""

    @abstractmethod
    def profile_from_path(self, path: Path) -> BrowserProfile | None:
        """Wrap a user-selected folder as a profile, or ``None`` if invalid."""

    # --- Artifact extraction ----------------------------------------------

    def get_history(self, profile: BrowserProfile) -> Iterable[HistoryEntry]:
        return ()

    def get_cookies(self, profile: BrowserProfile) -> Iterable[Cookie]:
        return ()

    def get_downloads(self, profile: BrowserProfile) -> Iterable[Download]:
        return ()

    def get_logins(self, profile: BrowserProfile) -> Iterable[Login]:
        return ()

    def get_bookmarks(self, profile: BrowserProfile) -> Iterable[Bookmark]:
        return ()

    def get_autofill(self, profile: BrowserProfile) -> Iterable[AutofillEntry]:
        return ()

    def get_extensions(self, profile: BrowserProfile) -> Iterable[Extension]:
        return ()

    def get_cache_entries(self, profile: BrowserProfile) -> Iterable[CacheEntry]:
        return ()

    def get_web_storage(self, profile: BrowserProfile) -> Iterable[WebStorageEntry]:
        return ()

    def get_open_tabs(self, profile: BrowserProfile) -> Iterable[OpenTab]:
        return ()

    def get_permissions(self, profile: BrowserProfile) -> Iterable[Permission]:
        return ()

    def get_carved_history(self, profile: BrowserProfile) -> Iterable[HistoryEntry]:
        """Optional: yield deleted-but-recoverable history entries.

        Subclasses that know their underlying SQLite layout can override this
        to invoke ``forensics.sqlite_carver``. Default is no carving.
        """
        return ()

    # --- Orchestration ----------------------------------------------------

    def extract_all(self, profile: BrowserProfile) -> ProfileBundle:
        """Run every extractor, capturing per-artifact errors in the bundle."""
        bundle = ProfileBundle(
            browser=self.name,
            profile=profile.name,
            path=str(profile.path),
        )
        extractors = (
            ("history", self.get_history),
            ("cookies", self.get_cookies),
            ("downloads", self.get_downloads),
            ("logins", self.get_logins),
            ("bookmarks", self.get_bookmarks),
            ("autofill", self.get_autofill),
            ("extensions", self.get_extensions),
            ("cache_entries", self.get_cache_entries),
            ("web_storage", self.get_web_storage),
            ("open_tabs", self.get_open_tabs),
            ("permissions", self.get_permissions),
        )
        for kind, fn in extractors:
            try:
                items = list(fn(profile))
                setattr(bundle, kind, items)
            except Exception as exc:  # noqa: BLE001 — surface, never crash
                logger.exception("%s.%s failed for %s", self.name, kind, profile.path)
                bundle.errors.append(f"{kind}: {exc}")

        # Carving runs last and is purely additive — failures only become
        # bundle warnings; we never let them taint the live history.
        try:
            carved = list(self.get_carved_history(profile))
        except Exception as exc:  # noqa: BLE001
            logger.exception("%s.carving failed for %s", self.name, profile.path)
            bundle.errors.append(f"carving: {exc}")
            carved = []
        if carved:
            bundle.history = list(bundle.history) + carved
            bundle.errors.append(f"carved {len(carved)} deleted history records")
        return bundle
