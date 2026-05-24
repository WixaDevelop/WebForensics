"""Mozilla Firefox extractor.

Firefox stores everything under a profile directory inside
``%APPDATA%\\Mozilla\\Firefox\\Profiles\\``. The interesting files are:

* ``places.sqlite``     — history, bookmarks, downloads (since v26)
* ``cookies.sqlite``    — cookies (plaintext, no decryption needed)
* ``formhistory.sqlite``— autofill
* ``logins.json`` + ``key4.db`` — saved passwords (we surface them but cannot
  decrypt without an NSS dependency; the password column is left empty and
  ``encrypted=True``).
* ``extensions.json``   — installed extensions metadata
"""

from __future__ import annotations

import configparser
import json
import logging
from pathlib import Path
from typing import Iterable, Iterator

from browsers.base import BrowserBase, BrowserProfile
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
from data.sqlite_handler import open_browser_db, table_exists
from utils.paths import firefox_profiles_dirs, is_firefox_profile_dir
from utils.time_utils import firefox_to_datetime, unix_to_datetime

logger = logging.getLogger(__name__)


# Firefox places.transition_type codes (see toolkit/components/places/nsINavHistoryService.idl).
_FF_VISIT_TYPES = {
    1: "link",
    2: "typed",
    3: "bookmark",
    4: "embed",
    5: "redirect_permanent",
    6: "redirect_temporary",
    7: "download",
    8: "framed_link",
    9: "reload",
}


class FirefoxBrowser(BrowserBase):
    name = "Firefox"

    # --- Profile discovery -------------------------------------------------

    def discover_profiles(self) -> list[BrowserProfile]:
        profiles: list[BrowserProfile] = []
        seen: set[Path] = set()

        # Preferred path: read ``profiles.ini`` so we get the user-visible names.
        for profile_root in firefox_profiles_dirs():
            ini = profile_root.parent / "profiles.ini"
            if ini.is_file():
                profiles.extend(self._profiles_from_ini(ini))

            # Fallback: walk the directory tree directly.
            if profile_root.is_dir():
                for child in profile_root.iterdir():
                    if is_firefox_profile_dir(child) and child not in seen:
                        seen.add(child)
                        profiles.append(BrowserProfile(self.name, child.name, child))

        # De-duplicate by resolved path while preserving order.
        unique: dict[Path, BrowserProfile] = {}
        for prof in profiles:
            try:
                resolved = prof.path.resolve()
            except OSError:
                resolved = prof.path
            unique.setdefault(resolved, prof)
        return list(unique.values())

    def _profiles_from_ini(self, ini_path: Path) -> Iterable[BrowserProfile]:
        parser = configparser.ConfigParser()
        try:
            parser.read(ini_path, encoding="utf-8")
        except (OSError, configparser.Error) as exc:
            logger.debug("profiles.ini unreadable: %s", exc)
            return
        for section in parser.sections():
            if not section.lower().startswith("profile"):
                continue
            path = parser.get(section, "Path", fallback=None)
            name = parser.get(section, "Name", fallback=path or section)
            is_relative = parser.getboolean(section, "IsRelative", fallback=True)
            if not path:
                continue
            full_path = (ini_path.parent / path).resolve() if is_relative else Path(path)
            if is_firefox_profile_dir(full_path):
                yield BrowserProfile(self.name, name, full_path)

    def profile_from_path(self, path: Path) -> BrowserProfile | None:
        if is_firefox_profile_dir(path):
            return BrowserProfile(self.name, path.name, path)
        return None

    # --- Helpers ----------------------------------------------------------

    def _meta(self, profile: BrowserProfile) -> dict[str, str]:
        return {"browser": self.name, "profile": profile.name}

    # --- History ----------------------------------------------------------

    def get_history(self, profile: BrowserProfile) -> Iterator[HistoryEntry]:
        db = profile.path / "places.sqlite"
        if not db.is_file():
            return
        meta = self._meta(profile)
        with open_browser_db(db) as conn:
            if not table_exists(conn, "moz_places"):
                return
            # Latest visit transition + the referrer URL via ``from_visit``.
            query = """
                SELECT p.url, p.title, p.visit_count, p.typed, p.last_visit_date,
                       (SELECT visit_type FROM moz_historyvisits v
                        WHERE v.place_id = p.id ORDER BY v.visit_date DESC LIMIT 1) AS visit_type,
                       (SELECT p2.url
                        FROM moz_historyvisits v1
                        LEFT JOIN moz_historyvisits v2 ON v2.id = v1.from_visit
                        LEFT JOIN moz_places p2 ON p2.id = v2.place_id
                        WHERE v1.place_id = p.id AND v1.from_visit != 0
                        ORDER BY v1.visit_date DESC LIMIT 1) AS from_visit_url
                FROM moz_places p
                WHERE p.hidden = 0
                ORDER BY p.last_visit_date DESC
            """
            for row in conn.execute(query):
                yield HistoryEntry(
                    **meta,
                    url=row["url"] or "",
                    title=row["title"] or "",
                    visit_count=row["visit_count"] or 0,
                    typed_count=int(row["typed"] or 0),
                    last_visit=firefox_to_datetime(row["last_visit_date"]),
                    visit_type=_FF_VISIT_TYPES.get(row["visit_type"], str(row["visit_type"] or "")),
                    from_visit_url=row["from_visit_url"] or "",
                )

    # --- Cookies ----------------------------------------------------------

    def get_cookies(self, profile: BrowserProfile) -> Iterator[Cookie]:
        db = profile.path / "cookies.sqlite"
        if not db.is_file():
            return
        meta = self._meta(profile)
        with open_browser_db(db) as conn:
            if not table_exists(conn, "moz_cookies"):
                return
            query = """
                SELECT host, name, value, path, expiry, creationTime, lastAccessed,
                       isSecure, isHttpOnly, sameSite
                FROM moz_cookies
            """
            for row in conn.execute(query):
                yield Cookie(
                    **meta,
                    host=row["host"] or "",
                    name=row["name"] or "",
                    value=row["value"] or "",
                    path=row["path"] or "/",
                    # ``expiry`` is seconds; the other two are microseconds.
                    expires=unix_to_datetime(row["expiry"]),
                    created=firefox_to_datetime(row["creationTime"]),
                    last_access=firefox_to_datetime(row["lastAccessed"]),
                    secure=bool(row["isSecure"]),
                    http_only=bool(row["isHttpOnly"]),
                    same_site=str(row["sameSite"] or ""),
                    encrypted=False,
                )

    # --- Downloads --------------------------------------------------------

    def get_downloads(self, profile: BrowserProfile) -> Iterator[Download]:
        # Modern Firefox keeps downloads inside places.sqlite as moz_annos
        # rows attached to moz_places entries with anno_attribute_id pointing
        # at the "downloads/destinationFileURI" attribute.
        db = profile.path / "places.sqlite"
        if not db.is_file():
            return
        meta = self._meta(profile)
        with open_browser_db(db) as conn:
            needed = ("moz_places", "moz_annos", "moz_anno_attributes")
            if not all(table_exists(conn, t) for t in needed):
                return
            query = """
                SELECT p.url AS source_url, a.content AS target, a.dateAdded, a.lastModified,
                       (SELECT a2.content FROM moz_annos a2
                        JOIN moz_anno_attributes aa2 ON aa2.id = a2.anno_attribute_id
                        WHERE a2.place_id = p.id AND aa2.name = 'downloads/metaData') AS meta_json
                FROM moz_places p
                JOIN moz_annos a ON a.place_id = p.id
                JOIN moz_anno_attributes aa ON aa.id = a.anno_attribute_id
                WHERE aa.name = 'downloads/destinationFileURI'
                ORDER BY a.dateAdded DESC
            """
            for row in conn.execute(query):
                # Extra metadata (size, mime) lives JSON-encoded in moz_annos.
                total = 0
                mime = ""
                state = ""
                if row["meta_json"]:
                    try:
                        meta_data = json.loads(row["meta_json"])
                        total = int(meta_data.get("fileSize") or 0)
                        mime = str(meta_data.get("contentType") or "")
                        state = "complete" if meta_data.get("state") in (1, "1") else ""
                    except (ValueError, TypeError):
                        pass
                yield Download(
                    **meta,
                    url=row["source_url"] or "",
                    target_path=row["target"] or "",
                    referrer="",
                    mime_type=mime,
                    total_bytes=total,
                    received_bytes=total,
                    state=state,
                    start_time=firefox_to_datetime(row["dateAdded"]),
                    end_time=firefox_to_datetime(row["lastModified"]),
                )

    # --- Logins -----------------------------------------------------------

    def get_logins(self, profile: BrowserProfile) -> Iterable[Login]:
        path = profile.path / "logins.json"
        if not path.is_file():
            return ()
        meta = self._meta(profile)

        # Try the real NSS-backed decryptor first; it falls back internally
        # to placeholder records when key4.db / libnss are missing.
        try:
            from data.nss_decryptor import NSSDecryptor
            decryptor = NSSDecryptor(profile.path)
            decrypted = decryptor.decrypt_logins()
        except Exception as exc:  # noqa: BLE001
            logger.debug("NSS decryption unavailable: %s", exc)
            decrypted = []

        if decrypted:
            return [
                Login(
                    **meta,
                    origin_url=row["origin_url"],
                    action_url=row["action_url"],
                    username=row["username"],
                    password=row["password"],
                    date_created=unix_to_datetime((row.get("time_created") or 0) / 1000.0),
                    date_last_used=unix_to_datetime((row.get("time_last_used") or 0) / 1000.0),
                    times_used=int(row.get("times_used") or 0),
                    encrypted=row["encrypted"],
                )
                for row in decrypted
            ]

        # Decryptor returned nothing — surface bare metadata so the analyst at
        # least sees there are saved logins.
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return ()
        out: list[Login] = []
        for entry in data.get("logins") or []:
            out.append(Login(
                **meta,
                origin_url=str(entry.get("hostname") or entry.get("origin") or ""),
                action_url=str(entry.get("formSubmitURL") or ""),
                username="",
                password="",
                date_created=unix_to_datetime((entry.get("timeCreated") or 0) / 1000.0),
                date_last_used=unix_to_datetime((entry.get("timeLastUsed") or 0) / 1000.0),
                times_used=int(entry.get("timesUsed") or 0),
                encrypted=True,
            ))
        return out

    # --- Bookmarks --------------------------------------------------------

    def get_bookmarks(self, profile: BrowserProfile) -> Iterator[Bookmark]:
        db = profile.path / "places.sqlite"
        if not db.is_file():
            return
        meta = self._meta(profile)
        with open_browser_db(db) as conn:
            if not (table_exists(conn, "moz_bookmarks") and table_exists(conn, "moz_places")):
                return
            # Recursively join each bookmark to its parent folder title.
            query = """
                SELECT b.title AS name, p.url AS url, b.dateAdded, b.lastModified,
                       parent.title AS folder
                FROM moz_bookmarks b
                LEFT JOIN moz_places p ON p.id = b.fk
                LEFT JOIN moz_bookmarks parent ON parent.id = b.parent
                WHERE b.type = 1 AND p.url IS NOT NULL
                ORDER BY b.dateAdded DESC
            """
            for row in conn.execute(query):
                yield Bookmark(
                    **meta,
                    folder=row["folder"] or "",
                    name=row["name"] or "",
                    url=row["url"] or "",
                    date_added=firefox_to_datetime(row["dateAdded"]),
                    date_modified=firefox_to_datetime(row["lastModified"]),
                )

    # --- Autofill ---------------------------------------------------------

    def get_autofill(self, profile: BrowserProfile) -> Iterator[AutofillEntry]:
        db = profile.path / "formhistory.sqlite"
        if not db.is_file():
            return
        meta = self._meta(profile)
        with open_browser_db(db) as conn:
            if not table_exists(conn, "moz_formhistory"):
                return
            query = """
                SELECT fieldname, value, timesUsed, firstUsed, lastUsed
                FROM moz_formhistory
                ORDER BY lastUsed DESC
            """
            for row in conn.execute(query):
                yield AutofillEntry(
                    **meta,
                    field_name=row["fieldname"] or "",
                    value=row["value"] or "",
                    count=row["timesUsed"] or 0,
                    # firstUsed/lastUsed are microseconds since the Unix epoch
                    # (PRTime), same as the rest of Firefox.
                    first_used=firefox_to_datetime(row["firstUsed"]),
                    last_used=firefox_to_datetime(row["lastUsed"]),
                )

    # --- Cache ------------------------------------------------------------

    def get_cache_entries(self, profile: BrowserProfile) -> Iterable[CacheEntry]:
        from forensics.cache import parse_firefox_cache
        meta = self._meta(profile)
        out: list[CacheEntry] = []
        # Firefox profiles point at the cache dir indirectly; the standard
        # paths are these. We try them in order and use whatever exists.
        candidates = [
            profile.path / "cache2",
            profile.path.parent.parent / "Local" / "Mozilla" / "Firefox" / "Profiles" / profile.path.name / "cache2",
        ]
        seen: set[str] = set()
        for cache_dir in candidates:
            if not cache_dir.is_dir():
                continue
            for record in parse_firefox_cache(cache_dir):
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

    # --- Web storage ------------------------------------------------------

    def get_web_storage(self, profile: BrowserProfile) -> Iterable[WebStorageEntry]:
        from forensics.web_storage import parse_firefox_storage
        meta = self._meta(profile)
        out: list[WebStorageEntry] = []
        for record in parse_firefox_storage(profile.path):
            out.append(WebStorageEntry(
                **meta,
                origin=record.get("origin", ""),
                kind=record.get("kind", "localstorage"),
                key=record.get("key", ""),
                value=record.get("value", ""),
                last_modified=record.get("last_modified"),
                source=record.get("source", ""),
            ))
        return out

    # --- Open tabs / sessions --------------------------------------------

    def get_open_tabs(self, profile: BrowserProfile) -> Iterable[OpenTab]:
        from forensics.sessions import parse_firefox_session
        meta = self._meta(profile)
        out: list[OpenTab] = []
        for record in parse_firefox_session(profile.path):
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
        from forensics.permissions import parse_firefox_permissions
        meta = self._meta(profile)
        out: list[Permission] = []
        for record in parse_firefox_permissions(profile.path / "permissions.sqlite"):
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
        db = profile.path / "places.sqlite"
        if not db.is_file():
            return ()
        from forensics.sqlite_carver import carve_firefox_history
        meta = self._meta(profile)
        out: list[HistoryEntry] = []
        seen: set[str] = set()
        try:
            carved = carve_firefox_history(db)
        except Exception as exc:  # noqa: BLE001
            logger.debug("Firefox carving failed for %s: %s", db, exc)
            return ()
        for record in carved:
            url = record["url"]
            if url in seen:
                continue
            seen.add(url)
            out.append(HistoryEntry(
                **meta,
                url=url,
                title=record.get("title", ""),
                visit_count=int(record.get("visit_count") or 0),
                visit_type="carved",
                deleted=True,
            ))
        return out

    # --- Extensions -------------------------------------------------------

    def get_extensions(self, profile: BrowserProfile) -> Iterable[Extension]:
        ext_file = profile.path / "extensions.json"
        if not ext_file.is_file():
            return ()
        try:
            data = json.loads(ext_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return ()
        meta = self._meta(profile)
        out: list[Extension] = []
        for entry in data.get("addons") or []:
            default = entry.get("defaultLocale") or {}
            out.append(Extension(
                **meta,
                extension_id=str(entry.get("id") or ""),
                name=str(default.get("name") or entry.get("id") or ""),
                version=str(entry.get("version") or ""),
                description=str(default.get("description") or ""),
                enabled=bool(entry.get("active")),
                install_path=str(entry.get("path") or ""),
            ))
        return out
