"""Chromium-family extractor (Chrome, Edge, and any fork that keeps the same
layout).

The artifacts live in the user's *profile* directory (``Default``,
``Profile 1``, ...). Encrypted secrets are unwrapped with ``ChromiumDecryptor``
which reads the AES key from the ``Local State`` file one level up.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from pathlib import Path
from typing import Iterable, Iterator, List, Optional

from browsers.base import BrowserBase, BrowserProfile
from data.decryptor import ChromiumDecryptor
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
    WebStorageEntry,
)
from data.sqlite_handler import column_exists, open_browser_db, table_exists
from utils.paths import is_chromium_profile_dir
from utils.time_utils import chromium_to_datetime

logger = logging.getLogger(__name__)


# Chromium encodes ``transition`` as a 32-bit packed value where the low byte
# is the *core* visit type. Reference: ui/base/page_transition_types.h.
_VISIT_TYPES = {
    0: "link",
    1: "typed",
    2: "auto_bookmark",
    3: "auto_subframe",
    4: "manual_subframe",
    5: "generated",
    6: "auto_toplevel",
    7: "form_submit",
    8: "reload",
    9: "keyword",
    10: "keyword_generated",
}


def _visit_type(transition: Optional[int]) -> str:
    if transition is None:
        return ""
    return _VISIT_TYPES.get(int(transition) & 0xFF, str(transition & 0xFF))


# Chromium's downloads table uses an integer state; map to a readable label.
_DOWNLOAD_STATES = {
    0: "in_progress",
    1: "complete",
    2: "cancelled",
    3: "interrupted",
    4: "interrupted",  # historical: == bad value
}


class ChromiumBrowser(BrowserBase):
    """Base extractor for Chromium-derived browsers.

    Subclasses override :attr:`name` and :meth:`user_data_dirs` only.
    """

    #: Override in subclasses with the candidate ``User Data`` paths.
    def user_data_dirs(self) -> List[Path]:  # pragma: no cover — overridden
        return []

    # --- Profile discovery -------------------------------------------------

    def discover_profiles(self) -> list[BrowserProfile]:
        profiles: list[BrowserProfile] = []
        for user_data in self.user_data_dirs():
            if not user_data.is_dir():
                continue
            for child in sorted(user_data.iterdir()):
                if is_chromium_profile_dir(child):
                    profiles.append(BrowserProfile(self.name, child.name, child))
        return profiles

    def profile_from_path(self, path: Path) -> BrowserProfile | None:
        if is_chromium_profile_dir(path):
            return BrowserProfile(self.name, path.name, path)
        return None

    # --- Helpers ----------------------------------------------------------

    def _decryptor_for(self, profile: BrowserProfile) -> ChromiumDecryptor:
        # ``Local State`` sits in the parent (``User Data``) directory.
        return ChromiumDecryptor(profile.path.parent / "Local State")

    def _meta(self, profile: BrowserProfile) -> dict[str, str]:
        return {"browser": self.name, "profile": profile.name}

    # --- History + downloads (History DB) ---------------------------------

    def get_history(self, profile: BrowserProfile) -> Iterator[HistoryEntry]:
        db = profile.path / "History"
        if not db.is_file():
            return
        meta = self._meta(profile)
        with open_browser_db(db) as conn:
            if not table_exists(conn, "urls"):
                return
            # Pull the most recent visit's transition AND its referrer URL.
            # ``visits.from_visit`` references another row in ``visits``; we
            # follow it through ``urls`` to recover the source URL.
            query = """
                SELECT u.url, u.title, u.visit_count, u.typed_count, u.last_visit_time,
                       (SELECT transition FROM visits v
                        WHERE v.url = u.id ORDER BY v.visit_time DESC LIMIT 1) AS transition,
                       (SELECT u2.url
                        FROM visits v1
                        LEFT JOIN visits v2 ON v2.id = v1.from_visit
                        LEFT JOIN urls u2  ON u2.id = v2.url
                        WHERE v1.url = u.id AND v1.from_visit != 0
                        ORDER BY v1.visit_time DESC LIMIT 1) AS from_visit_url
                FROM urls u
                ORDER BY u.last_visit_time DESC
            """
            for row in conn.execute(query):
                yield HistoryEntry(
                    **meta,
                    url=row["url"] or "",
                    title=row["title"] or "",
                    visit_count=row["visit_count"] or 0,
                    typed_count=row["typed_count"] or 0,
                    last_visit=chromium_to_datetime(row["last_visit_time"]),
                    visit_type=_visit_type(row["transition"]),
                    from_visit_url=row["from_visit_url"] or "",
                )

    def get_downloads(self, profile: BrowserProfile) -> Iterator[Download]:
        db = profile.path / "History"
        if not db.is_file():
            return
        meta = self._meta(profile)
        with open_browser_db(db) as conn:
            if not table_exists(conn, "downloads"):
                return
            # ``downloads_url_chains`` holds the redirect chain — index 0 is origin.
            has_chains = table_exists(conn, "downloads_url_chains")
            query = """
                SELECT d.id, d.target_path, d.start_time, d.end_time, d.received_bytes,
                       d.total_bytes, d.state, d.referrer, d.mime_type
                FROM downloads d
                ORDER BY d.start_time DESC
            """
            for row in conn.execute(query):
                url = ""
                if has_chains:
                    chain = conn.execute(
                        "SELECT url FROM downloads_url_chains "
                        "WHERE id = ? ORDER BY chain_index ASC LIMIT 1",
                        (row["id"],),
                    ).fetchone()
                    url = chain["url"] if chain else ""
                yield Download(
                    **meta,
                    url=url,
                    target_path=row["target_path"] or "",
                    referrer=row["referrer"] or "",
                    mime_type=row["mime_type"] or "",
                    total_bytes=row["total_bytes"] or 0,
                    received_bytes=row["received_bytes"] or 0,
                    state=_DOWNLOAD_STATES.get(row["state"], str(row["state"])),
                    start_time=chromium_to_datetime(row["start_time"]),
                    end_time=chromium_to_datetime(row["end_time"]),
                )

    # --- Cookies ----------------------------------------------------------

    def get_cookies(self, profile: BrowserProfile) -> Iterator[Cookie]:
        # M96+ moved cookies into ``Network/Cookies`` — check both.
        candidates = [profile.path / "Network" / "Cookies", profile.path / "Cookies"]
        db = next((c for c in candidates if c.is_file()), None)
        if db is None:
            return
        meta = self._meta(profile)
        decryptor = self._decryptor_for(profile)
        with open_browser_db(db) as conn:
            if not table_exists(conn, "cookies"):
                return
            # Column names changed over time; pick what's actually present.
            has_samesite = column_exists(conn, "cookies", "samesite")
            has_is_secure = column_exists(conn, "cookies", "is_secure")
            secure_col = "is_secure" if has_is_secure else "secure"
            httponly_col = "is_httponly" if column_exists(conn, "cookies", "is_httponly") else "httponly"
            samesite_select = "samesite" if has_samesite else "NULL AS samesite"
            query = f"""
                SELECT host_key, name, value, encrypted_value, path,
                       expires_utc, creation_utc, last_access_utc,
                       {secure_col} AS secure, {httponly_col} AS httponly, {samesite_select}
                FROM cookies
            """
            for row in conn.execute(query):
                yield self._cookie_from_row(row, decryptor, meta)

    def _cookie_from_row(
        self,
        row: sqlite3.Row,
        decryptor: ChromiumDecryptor,
        meta: dict[str, str],
    ) -> Cookie:
        plain_value = row["value"] or ""
        encrypted = False
        enc_blob = row["encrypted_value"]
        if not plain_value and enc_blob:
            decrypted = decryptor.decrypt_text(enc_blob)
            if decrypted is None:
                encrypted = True
            else:
                # Chromium M127+ prefixes the GCM plaintext with a 32-byte SHA256.
                plain_value = decrypted[32:] if len(decrypted) > 32 and decrypted[:1] == "" else decrypted
        return Cookie(
            **meta,
            host=row["host_key"] or "",
            name=row["name"] or "",
            value=plain_value,
            path=row["path"] or "/",
            expires=chromium_to_datetime(row["expires_utc"]),
            created=chromium_to_datetime(row["creation_utc"]),
            last_access=chromium_to_datetime(row["last_access_utc"]),
            secure=bool(row["secure"]),
            http_only=bool(row["httponly"]),
            same_site=str(row["samesite"]) if row["samesite"] is not None else "",
            encrypted=encrypted,
        )

    # --- Logins -----------------------------------------------------------

    def get_logins(self, profile: BrowserProfile) -> Iterator[Login]:
        db = profile.path / "Login Data"
        if not db.is_file():
            return
        meta = self._meta(profile)
        decryptor = self._decryptor_for(profile)
        with open_browser_db(db) as conn:
            if not table_exists(conn, "logins"):
                return
            query = """
                SELECT origin_url, action_url, username_value, password_value,
                       date_created, date_last_used, times_used
                FROM logins
            """
            for row in conn.execute(query):
                pwd = decryptor.decrypt_text(row["password_value"])
                yield Login(
                    **meta,
                    origin_url=row["origin_url"] or "",
                    action_url=row["action_url"] or "",
                    username=row["username_value"] or "",
                    password=pwd if pwd is not None else "",
                    date_created=chromium_to_datetime(row["date_created"]),
                    date_last_used=chromium_to_datetime(row["date_last_used"]),
                    times_used=row["times_used"] or 0,
                    encrypted=pwd is None,
                )

    # --- Bookmarks --------------------------------------------------------

    def get_bookmarks(self, profile: BrowserProfile) -> Iterable[Bookmark]:
        path = profile.path / "Bookmarks"
        if not path.is_file():
            return ()
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return ()
        meta = self._meta(profile)
        out: list[Bookmark] = []
        for root_name, node in (data.get("roots") or {}).items():
            if isinstance(node, dict):
                self._walk_bookmarks(node, root_name, meta, out)
        return out

    def _walk_bookmarks(
        self,
        node: dict,
        folder: str,
        meta: dict[str, str],
        out: list[Bookmark],
    ) -> None:
        node_type = node.get("type")
        name = node.get("name") or ""
        if node_type == "url":
            out.append(Bookmark(
                **meta,
                folder=folder,
                name=name,
                url=node.get("url") or "",
                date_added=chromium_to_datetime(_to_int(node.get("date_added"))),
                date_modified=chromium_to_datetime(_to_int(node.get("date_modified"))),
            ))
        elif node_type == "folder":
            subfolder = f"{folder}/{name}" if name else folder
            for child in node.get("children") or []:
                if isinstance(child, dict):
                    self._walk_bookmarks(child, subfolder, meta, out)

    # --- Autofill ---------------------------------------------------------

    def get_autofill(self, profile: BrowserProfile) -> Iterator[AutofillEntry]:
        db = profile.path / "Web Data"
        if not db.is_file():
            return
        meta = self._meta(profile)
        with open_browser_db(db) as conn:
            if not table_exists(conn, "autofill"):
                return
            query = """
                SELECT name, value, count, date_created, date_last_used
                FROM autofill
                ORDER BY date_last_used DESC
            """
            for row in conn.execute(query):
                # ``date_created`` here is *seconds* since Unix epoch (not WebKit).
                from utils.time_utils import unix_to_datetime
                yield AutofillEntry(
                    **meta,
                    field_name=row["name"] or "",
                    value=row["value"] or "",
                    count=row["count"] or 0,
                    first_used=unix_to_datetime(row["date_created"]),
                    last_used=unix_to_datetime(row["date_last_used"]),
                )

    # --- Cache ------------------------------------------------------------

    def get_cache_entries(self, profile: BrowserProfile) -> Iterable[CacheEntry]:
        from forensics.cache import parse_chromium_cache
        meta = self._meta(profile)
        out: list[CacheEntry] = []
        # Modern Chromium puts the cache at Profile/Cache/Cache_Data; older
        # builds used Profile/Cache directly. Check both.
        candidates = [
            profile.path / "Cache" / "Cache_Data",
            profile.path / "Cache",
            profile.path / "Code Cache" / "js",
            profile.path / "Code Cache" / "wasm",
        ]
        seen: set[str] = set()
        for cache_dir in candidates:
            if not cache_dir.is_dir():
                continue
            for record in parse_chromium_cache(cache_dir):
                url = record["url"]
                if url in seen:
                    continue
                seen.add(url)
                out.append(CacheEntry(
                    **meta,
                    url=url,
                    mime_type=record["mime_type"],
                    size=record["size"],
                    fetched_at=record["fetched_at"],
                    last_used=record["last_used"],
                    status_code=record["status_code"],
                    source=record["source"],
                ))
        return out

    # --- Web storage (LocalStorage / IndexedDB) ---------------------------

    def get_web_storage(self, profile: BrowserProfile) -> Iterable[WebStorageEntry]:
        from forensics.web_storage import parse_chromium_leveldb
        meta = self._meta(profile)
        out: list[WebStorageEntry] = []
        targets = (
            ("localstorage", profile.path / "Local Storage" / "leveldb"),
            ("sessionstorage", profile.path / "Session Storage"),
            ("indexeddb", profile.path / "IndexedDB"),
        )
        for kind, root in targets:
            if not root.is_dir():
                continue
            for record in parse_chromium_leveldb(root, kind):
                out.append(WebStorageEntry(
                    **meta,
                    origin=record.get("origin", ""),
                    kind=kind,
                    key=record.get("key", ""),
                    value=record.get("value", ""),
                    last_modified=record.get("last_modified"),
                    source=record.get("source", str(root)),
                ))
        return out

    # --- Open tabs / sessions --------------------------------------------

    def get_open_tabs(self, profile: BrowserProfile) -> Iterable[OpenTab]:
        from forensics.sessions import parse_chromium_session_files
        meta = self._meta(profile)
        out: list[OpenTab] = []
        for record in parse_chromium_session_files(profile.path):
            out.append(OpenTab(
                **meta,
                session=record.get("session", "current"),
                window_idx=int(record.get("window_idx") or 0),
                tab_idx=int(record.get("tab_idx") or 0),
                url=record.get("url", ""),
                title=record.get("title", ""),
                last_active=record.get("last_active"),
                pinned=bool(record.get("pinned")),
            ))
        return out

    # --- Permissions ------------------------------------------------------

    def get_permissions(self, profile: BrowserProfile) -> Iterable[Permission]:
        from forensics.permissions import parse_chromium_permissions
        meta = self._meta(profile)
        out: list[Permission] = []
        for record in parse_chromium_permissions(profile.path / "Preferences"):
            out.append(Permission(
                **meta,
                origin=record.get("origin", ""),
                permission=record.get("permission", ""),
                setting=record.get("setting", ""),
                last_modified=record.get("last_modified"),
            ))
        return out

    # --- Carving ----------------------------------------------------------

    def get_carved_history(self, profile: BrowserProfile) -> Iterable[HistoryEntry]:
        """Recover deleted Chromium history rows from unallocated space."""
        db = profile.path / "History"
        if not db.is_file():
            return ()
        from forensics.sqlite_carver import carve_chromium_history
        meta = self._meta(profile)
        out: list[HistoryEntry] = []
        # Dedup the carver's noisy yield by url+last_visit so a row recovered
        # from multiple page scans only shows up once.
        seen: set[tuple[str, int]] = set()
        try:
            carved = carve_chromium_history(db)
        except Exception as exc:  # noqa: BLE001
            logger.debug("Chromium carving failed for %s: %s", db, exc)
            return ()
        for record in carved:
            key = (record["url"], int(record.get("last_visit_chromium") or 0))
            if key in seen:
                continue
            seen.add(key)
            out.append(HistoryEntry(
                **meta,
                url=record["url"],
                title=record.get("title", ""),
                visit_count=int(record.get("visit_count") or 0),
                typed_count=int(record.get("typed_count") or 0),
                last_visit=chromium_to_datetime(record.get("last_visit_chromium") or 0),
                visit_type="carved",
                deleted=True,
            ))
        return out

    # --- Extensions -------------------------------------------------------

    def get_extensions(self, profile: BrowserProfile) -> Iterable[Extension]:
        ext_root = profile.path / "Extensions"
        if not ext_root.is_dir():
            return ()
        out: list[Extension] = []
        meta = self._meta(profile)
        for ext_dir in ext_root.iterdir():
            if not ext_dir.is_dir():
                continue
            # Each extension has one or more version subfolders containing manifest.json.
            for version_dir in ext_dir.iterdir():
                manifest = version_dir / "manifest.json"
                if not manifest.is_file():
                    continue
                try:
                    data = json.loads(manifest.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    continue
                out.append(Extension(
                    **meta,
                    extension_id=ext_dir.name,
                    name=str(data.get("name") or "").strip(),
                    version=str(data.get("version") or ""),
                    description=str(data.get("description") or "").strip(),
                    enabled=True,
                    install_path=str(version_dir),
                ))
        return out


def _to_int(value: object) -> Optional[int]:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None
