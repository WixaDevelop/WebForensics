"""Site-permission extraction.

Chromium puts every site setting in ``Profile/Preferences`` JSON, under
``profile.content_settings.exceptions.<permission>``. The key is the origin
pattern, the value is ``{"setting": <int>, "last_modified": <microseconds since
1601>}``.

Firefox keeps them in ``permissions.sqlite`` (table ``moz_perms``).

We normalise both to ``{origin, permission, setting, last_modified}``.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Iterator, Optional

from utils.time_utils import chromium_to_datetime, unix_to_datetime

logger = logging.getLogger(__name__)


# Chromium "setting" int → string. See content_settings_pattern.h.
_CHROME_SETTINGS = {0: "default", 1: "allow", 2: "block", 3: "ask", 4: "session_only"}


# Firefox capability → string (moz_perms.permission).
_FF_CAPABILITIES = {1: "allow", 2: "block", 8: "session_only"}


# Permissions we care about. Chromium prefixes some with "media_stream_" etc.;
# normalise to short names.
_PERM_RENAMES = {
    "media_stream_camera": "camera",
    "media_stream_mic":    "microphone",
    "midi_sysex":          "midi",
    "media-key-system-access": "drm",
}


def parse_chromium_permissions(preferences_path: Path) -> Iterator[dict]:
    if not preferences_path.is_file():
        return
    try:
        prefs = json.loads(preferences_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        logger.debug("Preferences read failed: %s", exc)
        return
    exceptions = (
        prefs.get("profile", {})
            .get("content_settings", {})
            .get("exceptions", {})
    )
    if not isinstance(exceptions, dict):
        return
    for permission, sites in exceptions.items():
        if not isinstance(sites, dict):
            continue
        canonical = _PERM_RENAMES.get(permission, permission)
        for origin_pattern, payload in sites.items():
            if not isinstance(payload, dict):
                continue
            # Modern Chromium nests the value as ``{"setting": <int>, "expiration": …}``
            # while older versions had the int directly. Unwrap one level if needed.
            raw_setting = payload.get("setting")
            if isinstance(raw_setting, dict):
                raw_setting = raw_setting.get("setting")
            try:
                setting_int = int(raw_setting) if raw_setting is not None else None
            except (TypeError, ValueError):
                setting_int = None
            setting = _CHROME_SETTINGS.get(setting_int, str(raw_setting) if raw_setting is not None else "")
            last_modified = payload.get("last_modified")
            ts = _from_chromium_ts(last_modified)
            yield {
                "origin": origin_pattern,
                "permission": canonical,
                "setting": setting,
                "last_modified": ts,
            }


def parse_firefox_permissions(db_path: Path) -> Iterator[dict]:
    if not db_path.is_file():
        return
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
    except sqlite3.Error as exc:
        logger.debug("permissions.sqlite open failed: %s", exc)
        return
    try:
        for row in conn.execute(
            "SELECT origin, type, permission, modificationTime FROM moz_perms"
        ):
            setting = _FF_CAPABILITIES.get(row["permission"], str(row["permission"]))
            # modificationTime is milliseconds since the Unix epoch.
            ts = None
            ms = row["modificationTime"] or 0
            if ms:
                ts = unix_to_datetime(ms / 1000.0)
            yield {
                "origin": row["origin"] or "",
                "permission": _PERM_RENAMES.get(row["type"], row["type"] or ""),
                "setting": setting,
                "last_modified": ts,
            }
    except sqlite3.Error as exc:
        logger.debug("moz_perms read failed: %s", exc)
    finally:
        conn.close()


def _from_chromium_ts(value) -> Optional[datetime]:
    if value is None:
        return None
    try:
        microseconds = int(value)
    except (TypeError, ValueError):
        return None
    if microseconds <= 0:
        return None
    return chromium_to_datetime(microseconds)
