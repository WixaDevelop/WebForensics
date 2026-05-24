"""Session-level SQLite store.

This is the on-disk home of an analysis session. Extractors stream their
output into it; the UI reads through ``QSqlTableModel`` so only the rows
currently visible are materialised in memory. That's what lets the app
handle profiles with millions of history rows without crashing.

The store is also what gets saved to ``.wfs`` session files — opening one
just points the controller at an existing database.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import tempfile
import uuid
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

from data.models import (
    ARTIFACT_KINDS,
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

# Schema is grouped: one ``profiles`` row per loaded profile, one table per
# artifact kind, and a denormalised ``events`` table used for cross-artifact
# views (timeline + global search). The events table is fed by triggers so
# inserts into the artifact tables propagate automatically.
_SCHEMA = """
PRAGMA journal_mode = WAL;
PRAGMA synchronous  = NORMAL;
PRAGMA temp_store   = MEMORY;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS profiles (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    browser     TEXT NOT NULL,
    name        TEXT NOT NULL,
    path        TEXT NOT NULL,
    source      TEXT NOT NULL DEFAULT 'live',   -- live | image | session
    image_path  TEXT,
    loaded_at   TEXT NOT NULL DEFAULT (datetime('now')),
    summary     TEXT NOT NULL DEFAULT '{}',
    errors      TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS ix_profiles_browser ON profiles(browser);

CREATE TABLE IF NOT EXISTS history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_id      INTEGER NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    url             TEXT,
    title           TEXT,
    visit_count     INTEGER,
    typed_count     INTEGER,
    last_visit      TEXT,
    visit_type      TEXT,
    deleted         INTEGER NOT NULL DEFAULT 0,  -- carved from WAL / freelist
    from_visit_url  TEXT,                        -- referrer (where this URL came from)
    category        TEXT                         -- banking / social / im / ...
);
CREATE INDEX IF NOT EXISTS ix_history_profile ON history(profile_id);
CREATE INDEX IF NOT EXISTS ix_history_ts      ON history(last_visit);
CREATE INDEX IF NOT EXISTS ix_history_url     ON history(url);

CREATE TABLE IF NOT EXISTS cookies (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_id  INTEGER NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    host        TEXT,
    name        TEXT,
    value       TEXT,
    path        TEXT,
    expires     TEXT,
    created     TEXT,
    last_access TEXT,
    secure      INTEGER,
    http_only   INTEGER,
    same_site   TEXT,
    encrypted   INTEGER,
    deleted     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ix_cookies_profile ON cookies(profile_id);
CREATE INDEX IF NOT EXISTS ix_cookies_host    ON cookies(host);

CREATE TABLE IF NOT EXISTS downloads (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_id      INTEGER NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    url             TEXT,
    target_path     TEXT,
    referrer        TEXT,
    mime_type       TEXT,
    total_bytes     INTEGER,
    received_bytes  INTEGER,
    state           TEXT,
    start_time      TEXT,
    end_time        TEXT,
    deleted         INTEGER NOT NULL DEFAULT 0,
    category        TEXT
);
CREATE INDEX IF NOT EXISTS ix_downloads_profile ON downloads(profile_id);
CREATE INDEX IF NOT EXISTS ix_downloads_ts      ON downloads(start_time);

CREATE TABLE IF NOT EXISTS logins (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_id      INTEGER NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    origin_url      TEXT,
    action_url      TEXT,
    username        TEXT,
    password        TEXT,
    date_created    TEXT,
    date_last_used  TEXT,
    times_used      INTEGER,
    encrypted       INTEGER
);
CREATE INDEX IF NOT EXISTS ix_logins_profile ON logins(profile_id);
CREATE INDEX IF NOT EXISTS ix_logins_origin  ON logins(origin_url);

CREATE TABLE IF NOT EXISTS bookmarks (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_id      INTEGER NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    folder          TEXT,
    name            TEXT,
    url             TEXT,
    date_added      TEXT,
    date_modified   TEXT,
    category        TEXT
);
CREATE INDEX IF NOT EXISTS ix_bookmarks_profile ON bookmarks(profile_id);

CREATE TABLE IF NOT EXISTS autofill (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_id  INTEGER NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    field_name  TEXT,
    value       TEXT,
    count       INTEGER,
    first_used  TEXT,
    last_used   TEXT
);
CREATE INDEX IF NOT EXISTS ix_autofill_profile ON autofill(profile_id);

CREATE TABLE IF NOT EXISTS extensions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_id      INTEGER NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    extension_id    TEXT,
    name            TEXT,
    version         TEXT,
    description     TEXT,
    enabled         INTEGER,
    install_path    TEXT
);
CREATE INDEX IF NOT EXISTS ix_extensions_profile ON extensions(profile_id);

-- Unified event view used by Timeline and Global Search. Updated through
-- INSERT triggers below so we don't have to keep two write paths in sync.
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_id  INTEGER NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    kind        TEXT NOT NULL,           -- history | cookie | download | login | bookmark | autofill
    ts          TEXT,                    -- ISO-8601, sortable as string
    summary     TEXT NOT NULL,           -- human-readable one-liner
    detail      TEXT                     -- secondary line (host / username / etc.)
);
CREATE INDEX IF NOT EXISTS ix_events_ts        ON events(ts);
CREATE INDEX IF NOT EXISTS ix_events_profile   ON events(profile_id);
CREATE INDEX IF NOT EXISTS ix_events_kind      ON events(kind);

CREATE TRIGGER IF NOT EXISTS trg_events_history
AFTER INSERT ON history BEGIN
    INSERT INTO events(profile_id, kind, ts, summary, detail)
    VALUES (NEW.profile_id, 'history', NEW.last_visit,
            COALESCE(NEW.title, NEW.url, ''), NEW.url);
END;

CREATE TRIGGER IF NOT EXISTS trg_events_download
AFTER INSERT ON downloads BEGIN
    INSERT INTO events(profile_id, kind, ts, summary, detail)
    VALUES (NEW.profile_id, 'download', NEW.start_time,
            COALESCE(NEW.target_path, NEW.url, ''), NEW.url);
END;

CREATE TRIGGER IF NOT EXISTS trg_events_login
AFTER INSERT ON logins BEGIN
    INSERT INTO events(profile_id, kind, ts, summary, detail)
    VALUES (NEW.profile_id, 'login', NEW.date_created,
            NEW.username, NEW.origin_url);
END;

CREATE TRIGGER IF NOT EXISTS trg_events_bookmark
AFTER INSERT ON bookmarks BEGIN
    INSERT INTO events(profile_id, kind, ts, summary, detail)
    VALUES (NEW.profile_id, 'bookmark', NEW.date_added,
            COALESCE(NEW.name, NEW.url, ''), NEW.url);
END;

CREATE TRIGGER IF NOT EXISTS trg_events_cookie
AFTER INSERT ON cookies BEGIN
    INSERT INTO events(profile_id, kind, ts, summary, detail)
    VALUES (NEW.profile_id, 'cookie', NEW.created,
            NEW.name, NEW.host);
END;

-- =========================================================================
-- Forensic extensions: search terms, IOC matching, anti-forensics findings,
-- analyst tags / notes.
-- =========================================================================

CREATE TABLE IF NOT EXISTS search_terms (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_id  INTEGER NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    engine      TEXT,            -- google | bing | duckduckgo | youtube | yahoo | ...
    query       TEXT,            -- decoded search query
    url         TEXT,            -- the URL it was parsed from
    title       TEXT,
    ts          TEXT             -- ISO-8601, matches history.last_visit when sourced from there
);
CREATE INDEX IF NOT EXISTS ix_search_profile ON search_terms(profile_id);
CREATE INDEX IF NOT EXISTS ix_search_engine  ON search_terms(engine);
CREATE INDEX IF NOT EXISTS ix_search_query   ON search_terms(query);
CREATE INDEX IF NOT EXISTS ix_search_ts      ON search_terms(ts);

-- One row per IOC value the analyst loaded. ``kind`` is what to compare it to:
-- domain | url | hash | ip | email | username.
CREATE TABLE IF NOT EXISTS iocs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    value       TEXT NOT NULL,
    kind        TEXT NOT NULL,        -- domain | url | hash | ip | email | username
    severity    TEXT NOT NULL DEFAULT 'medium',  -- info | low | medium | high | critical
    source      TEXT,                 -- file name / feed name
    description TEXT,
    loaded_at   TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(value, kind)
);
CREATE INDEX IF NOT EXISTS ix_iocs_kind ON iocs(kind);

-- One row per artifact that matched an IOC. The UI joins through this to flag
-- artifact rows; we keep it denormalised so we can count hits per kind cheaply.
CREATE TABLE IF NOT EXISTS ioc_hits (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc_id          INTEGER NOT NULL REFERENCES iocs(id) ON DELETE CASCADE,
    artifact_kind   TEXT NOT NULL,    -- history | cookies | downloads | logins | bookmarks
    artifact_id     INTEGER NOT NULL, -- id within the per-kind table
    profile_id      INTEGER NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    matched_field   TEXT,             -- url | host | etc.
    matched_value   TEXT,             -- snapshot of the value that matched
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS ix_ioc_hits_artifact ON ioc_hits(artifact_kind, artifact_id);
CREATE INDEX IF NOT EXISTS ix_ioc_hits_profile  ON ioc_hits(profile_id);
CREATE INDEX IF NOT EXISTS ix_ioc_hits_ioc      ON ioc_hits(ioc_id);

-- Anti-forensics analyser output. ``severity`` mirrors the iocs scale so the UI
-- can use the same colouring logic.
CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_id  INTEGER REFERENCES profiles(id) ON DELETE CASCADE,
    category    TEXT NOT NULL,    -- timeline_gap | rowid_gap | cleared_history | future_cookie | ...
    severity    TEXT NOT NULL DEFAULT 'medium',
    title       TEXT NOT NULL,
    detail      TEXT,
    ts          TEXT,             -- when the suspicious thing happened, if applicable
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS ix_findings_profile  ON findings(profile_id);
CREATE INDEX IF NOT EXISTS ix_findings_category ON findings(category);

-- Tags + notes per artifact. ``artifact_id = 0`` is a free-floating note tied
-- to a profile (analyst summary).
CREATE TABLE IF NOT EXISTS tags (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_id      INTEGER REFERENCES profiles(id) ON DELETE CASCADE,
    artifact_kind   TEXT NOT NULL,
    artifact_id     INTEGER NOT NULL,
    tag             TEXT,
    note            TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS ix_tags_artifact ON tags(artifact_kind, artifact_id);
CREATE INDEX IF NOT EXISTS ix_tags_profile  ON tags(profile_id);

-- =========================================================================
-- Round 2 of forensic extensions: cache, web-storage, open tabs, permissions.
-- =========================================================================

CREATE TABLE IF NOT EXISTS cache_entries (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_id  INTEGER NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    url         TEXT,
    mime_type   TEXT,
    size        INTEGER,
    fetched_at  TEXT,
    last_used   TEXT,
    status_code INTEGER,
    source      TEXT                   -- chromium_simplecache | firefox_cache2
);
CREATE INDEX IF NOT EXISTS ix_cache_profile ON cache_entries(profile_id);
CREATE INDEX IF NOT EXISTS ix_cache_url     ON cache_entries(url);

CREATE TABLE IF NOT EXISTS web_storage (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_id  INTEGER NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    origin      TEXT,                  -- the URL origin owning the data
    kind        TEXT NOT NULL,         -- localstorage | sessionstorage | indexeddb
    key         TEXT,
    value       TEXT,
    last_modified TEXT,
    source      TEXT                   -- leveldb path / sqlite path
);
CREATE INDEX IF NOT EXISTS ix_storage_profile ON web_storage(profile_id);
CREATE INDEX IF NOT EXISTS ix_storage_origin  ON web_storage(origin);
CREATE INDEX IF NOT EXISTS ix_storage_kind    ON web_storage(kind);

CREATE TABLE IF NOT EXISTS open_tabs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_id  INTEGER NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    session     TEXT,                  -- 'current' | 'last'
    window_idx  INTEGER,
    tab_idx     INTEGER,
    url         TEXT,
    title       TEXT,
    last_active TEXT,
    pinned      INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ix_tabs_profile ON open_tabs(profile_id);

CREATE TABLE IF NOT EXISTS permissions (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_id    INTEGER NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    origin        TEXT,
    permission    TEXT,                -- notifications | geolocation | camera | mic | ...
    setting       TEXT,                -- allow | block | ask | session
    last_modified TEXT
);
CREATE INDEX IF NOT EXISTS ix_perm_profile    ON permissions(profile_id);
CREATE INDEX IF NOT EXISTS ix_perm_permission ON permissions(permission);

-- =========================================================================
-- Round 3: provenance, identity discovery, OS correlation, enrichment.
-- =========================================================================

-- Every file we touched during extraction. The hash chain plus mtime/atime/
-- ctime gives us a court-defensible "this file looked like this at the time
-- we read it" snapshot.
CREATE TABLE IF NOT EXISTS source_files (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_id  INTEGER REFERENCES profiles(id) ON DELETE CASCADE,
    path        TEXT NOT NULL,
    sha256      TEXT NOT NULL,
    size        INTEGER,
    mtime       TEXT,
    atime       TEXT,
    ctime       TEXT,
    image_path  TEXT,                  -- when sourced from a forensic image
    image_offset INTEGER,              -- byte offset inside the image
    read_at     TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS ix_src_profile ON source_files(profile_id);
CREATE INDEX IF NOT EXISTS ix_src_sha     ON source_files(sha256);

-- Identities recovered from cookies + LocalStorage. ``identifier`` is the
-- service-specific user ID, ``username`` the human-readable handle when we
-- could resolve one.
CREATE TABLE IF NOT EXISTS accounts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_id  INTEGER NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    service     TEXT NOT NULL,        -- google | facebook | twitter | github | discord | ...
    identifier  TEXT,                 -- UID / numeric ID
    username    TEXT,                 -- human handle, if known
    email       TEXT,
    source      TEXT,                 -- cookie | localstorage | indexeddb | oauth_token
    detail      TEXT,
    last_seen   TEXT
);
CREATE INDEX IF NOT EXISTS ix_accounts_profile ON accounts(profile_id);
CREATE INDEX IF NOT EXISTS ix_accounts_service ON accounts(service);

-- Conversation messages recovered from IM web clients (WhatsApp Web, Discord,
-- Telegram Web). Best-effort — IndexedDB structured clones aren't fully
-- deterministic without a V8 deserialiser.
CREATE TABLE IF NOT EXISTS messages (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_id  INTEGER NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    app         TEXT NOT NULL,        -- whatsapp | discord | telegram | slack | teams
    chat_id     TEXT,
    chat_name   TEXT,
    sender_id   TEXT,
    sender_name TEXT,
    body        TEXT,
    ts          TEXT,
    source      TEXT
);
CREATE INDEX IF NOT EXISTS ix_msg_profile ON messages(profile_id);
CREATE INDEX IF NOT EXISTS ix_msg_app     ON messages(app);
CREATE INDEX IF NOT EXISTS ix_msg_ts      ON messages(ts);

-- OAuth / JWT tokens harvested from cookies/storage. Decoded scope where the
-- token is a parseable JWT.
CREATE TABLE IF NOT EXISTS tokens (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_id  INTEGER NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    kind        TEXT,                 -- jwt | bearer | oauth_refresh | api_key
    service     TEXT,
    issuer      TEXT,
    subject     TEXT,
    scope       TEXT,
    expires_at  TEXT,
    source      TEXT,
    value       TEXT
);
CREATE INDEX IF NOT EXISTS ix_tokens_profile ON tokens(profile_id);

-- User-Agent strings reconstructed from cache headers / storage.
CREATE TABLE IF NOT EXISTS user_agents (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_id  INTEGER NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    user_agent  TEXT NOT NULL,
    first_seen  TEXT,
    last_seen   TEXT,
    seen_count  INTEGER NOT NULL DEFAULT 1,
    source      TEXT
);
CREATE INDEX IF NOT EXISTS ix_ua_profile ON user_agents(profile_id);

-- OS artifacts that correlate with browser activity. The browser column is
-- empty for artifacts that aren't browser-specific (DNS, registry typed URLs).
CREATE TABLE IF NOT EXISTS os_artifacts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    kind        TEXT NOT NULL,        -- registry | prefetch | lnk | jumplist | dns_cache | hosts
    source_path TEXT,
    browser     TEXT,                 -- chrome | firefox | edge | <empty>
    name        TEXT,
    value       TEXT,
    ts          TEXT,
    extra       TEXT
);
CREATE INDEX IF NOT EXISTS ix_os_kind  ON os_artifacts(kind);
CREATE INDEX IF NOT EXISTS ix_os_ts    ON os_artifacts(ts);

-- Cached WHOIS / GeoIP lookups. We never hit the network at extraction time;
-- this is enrichment that runs on-demand from the Tools menu.
CREATE TABLE IF NOT EXISTS domain_intel (
    domain          TEXT PRIMARY KEY,
    registrar       TEXT,
    registered_at   TEXT,
    expires_at      TEXT,
    asn             TEXT,
    country         TEXT,
    risk            TEXT,             -- info | medium | high
    notes           TEXT,
    refreshed_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Persisted analyst-saved searches. The body is a JSON-encoded filter spec.
CREATE TABLE IF NOT EXISTS saved_searches (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    spec        TEXT NOT NULL,        -- JSON: {table, mode, pattern, regex, columns?}
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Full-text search across the searchable text columns. SQLite's FTS5 maintains
-- this externally; the trigger fan-out below keeps it in sync after every
-- artifact insert.
CREATE VIRTUAL TABLE IF NOT EXISTS fts_all USING fts5(
    artifact_kind UNINDEXED,
    artifact_id   UNINDEXED,
    profile_id    UNINDEXED,
    body,
    tokenize = 'unicode61 remove_diacritics 2'
);

CREATE TRIGGER IF NOT EXISTS trg_fts_history
AFTER INSERT ON history BEGIN
    INSERT INTO fts_all(artifact_kind, artifact_id, profile_id, body)
    VALUES ('history', NEW.id, NEW.profile_id,
            COALESCE(NEW.title, '') || ' ' || COALESCE(NEW.url, ''));
END;
CREATE TRIGGER IF NOT EXISTS trg_fts_cookies
AFTER INSERT ON cookies BEGIN
    INSERT INTO fts_all(artifact_kind, artifact_id, profile_id, body)
    VALUES ('cookies', NEW.id, NEW.profile_id,
            COALESCE(NEW.host, '') || ' ' || COALESCE(NEW.name, '') || ' ' || COALESCE(NEW.value, ''));
END;
CREATE TRIGGER IF NOT EXISTS trg_fts_downloads
AFTER INSERT ON downloads BEGIN
    INSERT INTO fts_all(artifact_kind, artifact_id, profile_id, body)
    VALUES ('downloads', NEW.id, NEW.profile_id,
            COALESCE(NEW.target_path, '') || ' ' || COALESCE(NEW.url, ''));
END;
CREATE TRIGGER IF NOT EXISTS trg_fts_logins
AFTER INSERT ON logins BEGIN
    INSERT INTO fts_all(artifact_kind, artifact_id, profile_id, body)
    VALUES ('logins', NEW.id, NEW.profile_id,
            COALESCE(NEW.origin_url, '') || ' ' || COALESCE(NEW.username, ''));
END;
CREATE TRIGGER IF NOT EXISTS trg_fts_bookmarks
AFTER INSERT ON bookmarks BEGIN
    INSERT INTO fts_all(artifact_kind, artifact_id, profile_id, body)
    VALUES ('bookmarks', NEW.id, NEW.profile_id,
            COALESCE(NEW.name, '') || ' ' || COALESCE(NEW.url, ''));
END;
CREATE TRIGGER IF NOT EXISTS trg_fts_storage
AFTER INSERT ON web_storage BEGIN
    INSERT INTO fts_all(artifact_kind, artifact_id, profile_id, body)
    VALUES ('web_storage', NEW.id, NEW.profile_id,
            COALESCE(NEW.origin, '') || ' ' || COALESCE(NEW.key, '') || ' ' || COALESCE(NEW.value, ''));
END;
CREATE TRIGGER IF NOT EXISTS trg_fts_messages
AFTER INSERT ON messages BEGIN
    INSERT INTO fts_all(artifact_kind, artifact_id, profile_id, body)
    VALUES ('messages', NEW.id, NEW.profile_id,
            COALESCE(NEW.sender_name, '') || ' ' || COALESCE(NEW.body, ''));
END;
"""


_BUNDLE_TO_TABLE = {
    "history": (
        HistoryEntry,
        ("url", "title", "visit_count", "typed_count", "last_visit", "visit_type",
         "deleted", "from_visit_url", "category"),
    ),
    "cookies": (
        Cookie,
        ("host", "name", "value", "path", "expires", "created", "last_access",
         "secure", "http_only", "same_site", "encrypted", "deleted"),
    ),
    "downloads": (
        Download,
        ("url", "target_path", "referrer", "mime_type", "total_bytes",
         "received_bytes", "state", "start_time", "end_time", "deleted", "category"),
    ),
    "logins": (
        Login,
        ("origin_url", "action_url", "username", "password", "date_created",
         "date_last_used", "times_used", "encrypted"),
    ),
    "bookmarks": (
        Bookmark,
        ("folder", "name", "url", "date_added", "date_modified", "category"),
    ),
    "autofill": (
        AutofillEntry,
        ("field_name", "value", "count", "first_used", "last_used"),
    ),
    "extensions": (
        Extension,
        ("extension_id", "name", "version", "description", "enabled", "install_path"),
    ),
    "cache_entries": (
        CacheEntry,
        ("url", "mime_type", "size", "fetched_at", "last_used", "status_code", "source"),
    ),
    "web_storage": (
        WebStorageEntry,
        ("origin", "kind", "key", "value", "last_modified", "source"),
    ),
    "open_tabs": (
        OpenTab,
        ("session", "window_idx", "tab_idx", "url", "title", "last_active", "pinned"),
    ),
    "permissions": (
        Permission,
        ("origin", "permission", "setting", "last_modified"),
    ),
}


def _to_storable(value: Any) -> Any:
    """Convert dataclass field values to types SQLite accepts."""
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, bool):
        return int(value)
    return value


class SessionStore:
    """One SQLite DB representing the entire analysis session."""

    SUFFIX = ".wfs"

    def __init__(self, path: str | Path | None = None) -> None:
        if path is None:
            tmp = tempfile.NamedTemporaryFile(
                prefix=f"webforensics_{uuid.uuid4().hex[:8]}_",
                suffix=".db",
                delete=False,
            )
            tmp.close()
            path = tmp.name
        self.path = Path(path)
        self._conn = sqlite3.connect(self.path, isolation_level=None, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    # --- Lifecycle --------------------------------------------------------

    def _init_schema(self) -> None:
        self._conn.executescript(_SCHEMA)
        self._migrate_legacy()
        self._set_meta("schema_version", "2")
        if not self._get_meta("created_at"):
            self._set_meta("created_at", datetime.now(timezone.utc).isoformat())

    def _migrate_legacy(self) -> None:
        """Add columns that didn't exist in v1 ``.wfs`` files."""
        # CREATE TABLE IF NOT EXISTS skips column changes on an existing table,
        # so we have to patch the old shape ourselves with ALTER TABLE.
        bates_decl = "TEXT"
        source_decl = "INTEGER"
        for table, column, decl in (
            ("history",   "deleted",        "INTEGER NOT NULL DEFAULT 0"),
            ("history",   "from_visit_url", "TEXT"),
            ("history",   "category",       "TEXT"),
            ("cookies",   "deleted",        "INTEGER NOT NULL DEFAULT 0"),
            ("downloads", "deleted",        "INTEGER NOT NULL DEFAULT 0"),
            ("downloads", "category",       "TEXT"),
            ("bookmarks", "category",       "TEXT"),
            # Bates / provenance — added to every artifact table.
            ("history",       "bates_id",       bates_decl),
            ("history",       "source_file_id", source_decl),
            ("cookies",       "bates_id",       bates_decl),
            ("cookies",       "source_file_id", source_decl),
            ("downloads",     "bates_id",       bates_decl),
            ("downloads",     "source_file_id", source_decl),
            ("logins",        "bates_id",       bates_decl),
            ("logins",        "source_file_id", source_decl),
            ("bookmarks",     "bates_id",       bates_decl),
            ("bookmarks",     "source_file_id", source_decl),
            ("autofill",      "bates_id",       bates_decl),
            ("autofill",      "source_file_id", source_decl),
            ("extensions",    "bates_id",       bates_decl),
            ("extensions",    "source_file_id", source_decl),
            ("cache_entries", "bates_id",       bates_decl),
            ("web_storage",   "bates_id",       bates_decl),
            ("open_tabs",     "bates_id",       bates_decl),
            ("permissions",   "bates_id",       bates_decl),
            ("messages",      "bates_id",       bates_decl),
        ):
            cols = {row["name"] for row in self._conn.execute(f"PRAGMA table_info({table})")}
            if column not in cols:
                try:
                    self._conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")
                except sqlite3.OperationalError:
                    # Table didn't exist yet — schema script handled it.
                    pass

    def close(self) -> None:
        try:
            self._conn.close()
        except sqlite3.Error:
            pass

    # --- Meta -------------------------------------------------------------

    def _set_meta(self, key: str, value: str) -> None:
        self._conn.execute(
            "INSERT INTO meta(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )

    def _get_meta(self, key: str) -> Optional[str]:
        row = self._conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row["value"] if row else None

    # --- Ingest -----------------------------------------------------------

    def ingest_bundle(self, bundle: ProfileBundle, source: str = "live",
                      image_path: Optional[str] = None) -> int:
        """Insert a full ProfileBundle. Returns the new profile_id."""
        cursor = self._conn.execute(
            "INSERT INTO profiles(browser, name, path, source, image_path, summary, errors) "
            "VALUES(?, ?, ?, ?, ?, ?, ?)",
            (
                bundle.browser,
                bundle.profile,
                bundle.path,
                source,
                image_path,
                json.dumps(bundle.summary()),
                json.dumps(bundle.errors),
            ),
        )
        profile_id = cursor.lastrowid

        # Bulk-insert per artifact in a single transaction for speed.
        try:
            self._conn.execute("BEGIN")
            for kind, (_, columns) in _BUNDLE_TO_TABLE.items():
                items = bundle.get(kind)
                if not items:
                    continue
                placeholders = ", ".join("?" * (len(columns) + 1))
                col_list = ", ".join(("profile_id", *columns))
                sql = f"INSERT INTO {kind}({col_list}) VALUES({placeholders})"
                rows = [
                    (profile_id, *[_to_storable(getattr(item, col)) for col in columns])
                    for item in items
                ]
                self._conn.executemany(sql, rows)
            self._conn.execute("COMMIT")
        except sqlite3.Error:
            self._conn.execute("ROLLBACK")
            raise

        # Assign Bates IDs to every row we just wrote so each artifact is
        # individually citable in legal contexts.
        try:
            self._assign_bates_ids(profile_id)
        except Exception:  # noqa: BLE001
            logger.exception("Bates assignment failed for profile %s", profile_id)

        # Post-ingest derivations — these are cheap reads of what we just wrote.
        try:
            self._derive_search_terms(profile_id)
        except Exception:  # noqa: BLE001 — derivation never fails ingest
            logger.exception("search-term derivation failed for profile %s", profile_id)
        try:
            self._derive_categories(profile_id)
        except Exception:  # noqa: BLE001
            logger.exception("category derivation failed for profile %s", profile_id)
        try:
            self._derive_identities(profile_id)
        except Exception:  # noqa: BLE001
            logger.exception("identity derivation failed for profile %s", profile_id)
        try:
            self._derive_messages(profile_id)
        except Exception:  # noqa: BLE001
            logger.exception("IM message derivation failed for profile %s", profile_id)
        try:
            self._derive_user_agents(profile_id)
        except Exception:  # noqa: BLE001
            logger.exception("UA derivation failed for profile %s", profile_id)
        return profile_id

    def _derive_identities(self, profile_id: int) -> None:
        from forensics.identity import harvest_identities
        harvest_identities(self._conn, profile_id)

    def _derive_messages(self, profile_id: int) -> None:
        from forensics.im_apps import harvest_messages
        harvest_messages(self._conn, profile_id)

    def _derive_user_agents(self, profile_id: int) -> None:
        from forensics.user_agents import harvest_user_agents
        harvest_user_agents(self._conn, profile_id)

    def _derive_search_terms(self, profile_id: int) -> None:
        from forensics.search_terms import derive_search_terms_for_profile
        terms = list(derive_search_terms_for_profile(self._conn, profile_id))
        if terms:
            self.ingest_search_terms(profile_id, terms)

    def _assign_bates_ids(self, profile_id: int) -> None:
        """Set ``bates_id = WF-NNNNNNNN`` on every freshly-ingested row.

        Bates numbering is the legal convention of giving every page of
        evidence a stable, unique identifier (``DEFENDANT-000001``...). For our
        purposes we use the global rowid so each artifact is citable as
        ``WF-<8-digit-id>`` regardless of which session it lives in.
        """
        for table in ("history", "cookies", "downloads", "logins", "bookmarks",
                      "autofill", "extensions", "cache_entries", "web_storage",
                      "open_tabs", "permissions", "messages"):
            try:
                self._conn.execute(
                    f"UPDATE {table} SET bates_id = printf('WF-%08d', id) "
                    f"WHERE profile_id=? AND (bates_id IS NULL OR bates_id = '')",
                    (profile_id,),
                )
            except sqlite3.OperationalError:
                # Table may not have a bates_id column on legacy DBs we can't migrate.
                continue

    def _derive_categories(self, profile_id: int) -> None:
        """Run the URL categorizer over history/downloads/bookmarks rows that
        don't carry a category yet (the live extractors leave it blank)."""
        from forensics.categorizer import categorize
        for table, url_col in (("history", "url"), ("downloads", "url"), ("bookmarks", "url")):
            rows = self._conn.execute(
                f"SELECT id, {url_col} FROM {table} "
                f"WHERE profile_id=? AND (category IS NULL OR category = '')",
                (profile_id,),
            ).fetchall()
            updates = []
            for row in rows:
                cat = categorize(row[url_col] or "")
                if cat:
                    updates.append((cat, int(row["id"])))
            if updates:
                self._conn.executemany(
                    f"UPDATE {table} SET category=? WHERE id=?", updates,
                )

    # --- Query helpers ----------------------------------------------------

    def list_profiles(self) -> list[sqlite3.Row]:
        return list(self._conn.execute(
            "SELECT id, browser, name, path, source, image_path, loaded_at, summary, errors "
            "FROM profiles ORDER BY id"
        ))

    def delete_profile(self, profile_id: int) -> None:
        self._conn.execute("DELETE FROM profiles WHERE id=?", (profile_id,))

    def clear(self) -> None:
        # Removing profiles cascades to every artifact table and the events log.
        self._conn.execute("DELETE FROM profiles")
        self._conn.execute("DELETE FROM sqlite_sequence")

    def summary(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for kind in ARTIFACT_KINDS:
            row = self._conn.execute(f"SELECT COUNT(*) AS n FROM {kind}").fetchone()
            out[kind] = int(row["n"] or 0)
        return out

    def row_count(self, table: str, profile_id: Optional[int] = None) -> int:
        if table not in _BUNDLE_TO_TABLE and table not in ("events", "profiles"):
            raise ValueError(f"Unknown table: {table}")
        if profile_id is None:
            row = self._conn.execute(f"SELECT COUNT(*) AS n FROM {table}").fetchone()
        else:
            row = self._conn.execute(
                f"SELECT COUNT(*) AS n FROM {table} WHERE profile_id=?", (profile_id,)
            ).fetchone()
        return int(row["n"] or 0)

    def fetch(
        self,
        table: str,
        profile_id: Optional[int] = None,
        where: str = "",
        params: tuple = (),
        order: str = "",
        limit: Optional[int] = None,
    ) -> list[sqlite3.Row]:
        clauses: list[str] = []
        all_params: list[Any] = []
        if profile_id is not None:
            clauses.append("profile_id = ?")
            all_params.append(profile_id)
        if where:
            clauses.append(where)
            all_params.extend(params)
        sql = f"SELECT * FROM {table}"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        if order:
            sql += f" ORDER BY {order}"
        if limit:
            sql += f" LIMIT {int(limit)}"
        return list(self._conn.execute(sql, tuple(all_params)))

    def search(self, query: str, limit: int = 500) -> dict[str, list[sqlite3.Row]]:
        """Global LIKE search across the artifact tables.

        Returns a ``{kind: rows}`` mapping with ``limit`` rows per kind so the
        UI can show grouped previews without dragging in millions of rows.
        """
        like = f"%{query}%"
        results: dict[str, list[sqlite3.Row]] = {}
        # Per-kind LIKE columns — picked so that the hits are meaningful.
        plan = {
            "history":   ("url", "title"),
            "cookies":   ("host", "name", "value"),
            "downloads": ("url", "target_path", "mime_type"),
            "logins":    ("origin_url", "username"),
            "bookmarks": ("folder", "name", "url"),
            "autofill":  ("field_name", "value"),
            "extensions":("name", "extension_id", "description"),
        }
        for kind, cols in plan.items():
            where = " OR ".join(f"{c} LIKE ?" for c in cols)
            params = tuple(like for _ in cols)
            sql = f"SELECT * FROM {kind} WHERE {where} LIMIT {int(limit)}"
            results[kind] = list(self._conn.execute(sql, params))
        return results

    def connection(self) -> sqlite3.Connection:
        """Direct access for the QtSql adapter — use sparingly."""
        return self._conn

    @property
    def db_path(self) -> Path:
        return self.path

    # --- Search terms -----------------------------------------------------

    def ingest_search_terms(self, profile_id: int, terms: Iterable[dict]) -> int:
        """Bulk-insert parsed search queries — returns the row count."""
        rows = [
            (
                profile_id,
                t.get("engine", ""),
                t.get("query", ""),
                t.get("url", ""),
                t.get("title", ""),
                t.get("ts", ""),
            )
            for t in terms
        ]
        if not rows:
            return 0
        self._conn.executemany(
            "INSERT INTO search_terms(profile_id, engine, query, url, title, ts) "
            "VALUES(?, ?, ?, ?, ?, ?)",
            rows,
        )
        return len(rows)

    # --- IOCs -------------------------------------------------------------

    def upsert_iocs(self, iocs: Iterable[dict]) -> int:
        """Insert IOCs, skipping duplicates on (value, kind)."""
        rows = list(iocs)
        inserted = 0
        for ioc in rows:
            try:
                cursor = self._conn.execute(
                    "INSERT OR IGNORE INTO iocs(value, kind, severity, source, description) "
                    "VALUES(?, ?, ?, ?, ?)",
                    (
                        ioc.get("value", "").strip(),
                        ioc.get("kind", "domain"),
                        ioc.get("severity", "medium"),
                        ioc.get("source", ""),
                        ioc.get("description", ""),
                    ),
                )
                if cursor.rowcount:
                    inserted += 1
            except sqlite3.Error as exc:
                logger.warning("IOC insert failed for %r: %s", ioc.get("value"), exc)
        return inserted

    def all_iocs(self) -> list[sqlite3.Row]:
        return list(self._conn.execute("SELECT * FROM iocs ORDER BY kind, value"))

    def clear_iocs(self) -> None:
        self._conn.execute("DELETE FROM ioc_hits")
        self._conn.execute("DELETE FROM iocs")

    def record_ioc_hit(
        self,
        ioc_id: int,
        artifact_kind: str,
        artifact_id: int,
        profile_id: int,
        matched_field: str,
        matched_value: str,
    ) -> None:
        self._conn.execute(
            "INSERT INTO ioc_hits(ioc_id, artifact_kind, artifact_id, profile_id, "
            "matched_field, matched_value) VALUES(?, ?, ?, ?, ?, ?)",
            (ioc_id, artifact_kind, artifact_id, profile_id, matched_field, matched_value),
        )

    # --- Findings ---------------------------------------------------------

    def record_finding(
        self,
        category: str,
        title: str,
        severity: str = "medium",
        detail: str = "",
        profile_id: Optional[int] = None,
        ts: Optional[str] = None,
    ) -> int:
        cursor = self._conn.execute(
            "INSERT INTO findings(profile_id, category, severity, title, detail, ts) "
            "VALUES(?, ?, ?, ?, ?, ?)",
            (profile_id, category, severity, title, detail, ts),
        )
        return int(cursor.lastrowid)

    def clear_findings(self) -> None:
        self._conn.execute("DELETE FROM findings")

    # --- Source-file provenance -------------------------------------------

    def record_source_file(
        self,
        path: str,
        sha256: str,
        size: int = 0,
        mtime: Optional[str] = None,
        atime: Optional[str] = None,
        ctime: Optional[str] = None,
        image_path: Optional[str] = None,
        image_offset: Optional[int] = None,
        profile_id: Optional[int] = None,
    ) -> int:
        cursor = self._conn.execute(
            "INSERT INTO source_files(profile_id, path, sha256, size, mtime, atime, "
            "ctime, image_path, image_offset) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (profile_id, path, sha256, size, mtime, atime, ctime, image_path, image_offset),
        )
        return int(cursor.lastrowid)

    # --- FTS5 search helper ----------------------------------------------

    def fts_search(self, query: str, limit: int = 500) -> list[sqlite3.Row]:
        """Run an FTS5 MATCH and return joined rows grouped by kind/id."""
        try:
            return list(self._conn.execute(
                "SELECT artifact_kind, artifact_id, profile_id, body, "
                "       snippet(fts_all, 3, '<<', '>>', '…', 16) AS snippet "
                "FROM fts_all WHERE fts_all MATCH ? LIMIT ?",
                (query, int(limit)),
            ))
        except sqlite3.OperationalError as exc:
            logger.debug("FTS query failed: %s", exc)
            return []

    # --- Tags + notes -----------------------------------------------------

    def add_tag(
        self,
        artifact_kind: str,
        artifact_id: int,
        tag: str = "",
        note: str = "",
        profile_id: Optional[int] = None,
    ) -> int:
        cursor = self._conn.execute(
            "INSERT INTO tags(profile_id, artifact_kind, artifact_id, tag, note) "
            "VALUES(?, ?, ?, ?, ?)",
            (profile_id, artifact_kind, artifact_id, tag, note),
        )
        return int(cursor.lastrowid)

    def tags_for(self, artifact_kind: str, artifact_id: int) -> list[sqlite3.Row]:
        return list(self._conn.execute(
            "SELECT * FROM tags WHERE artifact_kind=? AND artifact_id=? ORDER BY id",
            (artifact_kind, artifact_id),
        ))

    def delete_tag(self, tag_id: int) -> None:
        self._conn.execute("DELETE FROM tags WHERE id=?", (tag_id,))
