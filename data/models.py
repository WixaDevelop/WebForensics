"""Typed records produced by the browser extractors.

Every artifact is a frozen ``dataclass`` — extractors create them, the UI and
exporters consume them through ``to_dict()``. Keeping the shape uniform across
Chromium and Firefox lets the UI use the same table widget for every browser.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Optional


def _iso(dt: Optional[datetime]) -> str:
    return dt.isoformat() if dt else ""


@dataclass(frozen=True)
class ArtifactBase:
    """Fields common to every artifact — identifies the source profile."""

    browser: str
    profile: str

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        # Render datetimes as ISO strings for export-friendliness.
        for key, value in list(data.items()):
            if isinstance(value, datetime):
                data[key] = _iso(value)
        return data


@dataclass(frozen=True)
class HistoryEntry(ArtifactBase):
    url: str = ""
    title: str = ""
    visit_count: int = 0
    typed_count: int = 0
    last_visit: Optional[datetime] = None
    visit_type: str = ""  # link, typed, bookmark, etc.
    deleted: bool = False  # True if recovered from WAL / freelist (carving)
    from_visit_url: str = ""  # referrer URL (navigation graph)
    category: str = ""        # classifier output: banking / social / im / ...


@dataclass(frozen=True)
class Cookie(ArtifactBase):
    host: str = ""
    name: str = ""
    value: str = ""
    path: str = "/"
    expires: Optional[datetime] = None
    created: Optional[datetime] = None
    last_access: Optional[datetime] = None
    secure: bool = False
    http_only: bool = False
    same_site: str = ""
    encrypted: bool = False  # True when value could not be decrypted
    deleted: bool = False    # True if carved from WAL / freelist


@dataclass(frozen=True)
class Download(ArtifactBase):
    url: str = ""
    target_path: str = ""
    referrer: str = ""
    mime_type: str = ""
    total_bytes: int = 0
    received_bytes: int = 0
    state: str = ""  # in_progress, complete, cancelled, interrupted
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    deleted: bool = False  # True if carved from WAL / freelist
    category: str = ""


@dataclass(frozen=True)
class Login(ArtifactBase):
    origin_url: str = ""
    action_url: str = ""
    username: str = ""
    password: str = ""
    date_created: Optional[datetime] = None
    date_last_used: Optional[datetime] = None
    times_used: int = 0
    encrypted: bool = False  # True when password could not be decrypted


@dataclass(frozen=True)
class Bookmark(ArtifactBase):
    folder: str = ""
    name: str = ""
    url: str = ""
    date_added: Optional[datetime] = None
    date_modified: Optional[datetime] = None
    category: str = ""


@dataclass(frozen=True)
class AutofillEntry(ArtifactBase):
    field_name: str = ""
    value: str = ""
    count: int = 0
    first_used: Optional[datetime] = None
    last_used: Optional[datetime] = None


@dataclass(frozen=True)
class Extension(ArtifactBase):
    extension_id: str = ""
    name: str = ""
    version: str = ""
    description: str = ""
    enabled: bool = True
    install_path: str = ""


@dataclass(frozen=True)
class CacheEntry(ArtifactBase):
    """One cached HTTP response — URL, MIME and timing only.

    We deliberately do not store the cached payload itself; for forensic
    purposes the metadata + URL is what proves the user fetched something.
    """

    url: str = ""
    mime_type: str = ""
    size: int = 0
    fetched_at: Optional[datetime] = None
    last_used: Optional[datetime] = None
    status_code: int = 0
    source: str = ""  # chromium_simplecache | firefox_cache2


@dataclass(frozen=True)
class WebStorageEntry(ArtifactBase):
    origin: str = ""
    kind: str = "localstorage"   # localstorage | sessionstorage | indexeddb
    key: str = ""
    value: str = ""
    last_modified: Optional[datetime] = None
    source: str = ""             # file the entry was extracted from


@dataclass(frozen=True)
class OpenTab(ArtifactBase):
    session: str = "current"     # current | last
    window_idx: int = 0
    tab_idx: int = 0
    url: str = ""
    title: str = ""
    last_active: Optional[datetime] = None
    pinned: bool = False


@dataclass(frozen=True)
class Permission(ArtifactBase):
    origin: str = ""
    permission: str = ""         # notifications | geolocation | camera | mic | midi | usb | ...
    setting: str = ""            # allow | block | ask | session
    last_modified: Optional[datetime] = None


# Convenience: ordered list of artifact kinds the UI iterates over.
ARTIFACT_KINDS: tuple[str, ...] = (
    "history",
    "cookies",
    "downloads",
    "logins",
    "bookmarks",
    "autofill",
    "extensions",
    "cache_entries",
    "web_storage",
    "open_tabs",
    "permissions",
)


@dataclass
class ProfileBundle:
    """The full extraction result for a single profile."""

    browser: str
    profile: str
    path: str
    history: list[HistoryEntry] = field(default_factory=list)
    cookies: list[Cookie] = field(default_factory=list)
    downloads: list[Download] = field(default_factory=list)
    logins: list[Login] = field(default_factory=list)
    bookmarks: list[Bookmark] = field(default_factory=list)
    autofill: list[AutofillEntry] = field(default_factory=list)
    extensions: list[Extension] = field(default_factory=list)
    cache_entries: list[CacheEntry] = field(default_factory=list)
    web_storage: list[WebStorageEntry] = field(default_factory=list)
    open_tabs: list[OpenTab] = field(default_factory=list)
    permissions: list[Permission] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def get(self, kind: str) -> list[ArtifactBase]:
        return getattr(self, kind, [])

    def summary(self) -> dict[str, int]:
        return {kind: len(self.get(kind)) for kind in ARTIFACT_KINDS}
