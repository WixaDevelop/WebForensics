"""Extract User-Agent strings the browser actually presented to the network.

Sources we look at:

* ``cache_entries`` URLs — many tracker pixels embed UA-derived params; not
  reliable enough on its own.
* ``web_storage`` values — site-side scripts often save UA as ``userAgent``
  or ``ua`` for debugging. We pick these up.
* Cookie ``user-agent`` / ``ua`` keys.
* The browser's own ``Local State`` (Chromium) or ``addonStartup.json.lz4``
  (Firefox) sometimes carry a UA the last session reported. Out of scope here.

We persist each unique UA + first/last seen + count.
"""

from __future__ import annotations

import re
import sqlite3

_UA_PATTERN = re.compile(
    r"Mozilla/[0-9.]+ \([^)]+\)[^\"',]{0,256}",
)


def harvest_user_agents(conn: sqlite3.Connection, profile_id: int) -> int:
    """Scan storage + cookies for UA strings and write to ``user_agents``."""
    seen: dict[str, dict] = {}
    # Cookies named user-agent / ua.
    rows = conn.execute(
        "SELECT host, name, value, last_access FROM cookies "
        "WHERE profile_id=? AND (name='ua' OR name='user-agent' OR LOWER(name)='useragent')",
        (profile_id,),
    ).fetchall()
    for row in rows:
        _record(seen, row["value"] or "", row["last_access"] or "", f"cookie:{row['name']}@{row['host']}")
    # Storage values that contain something looking like a UA.
    rows = conn.execute(
        "SELECT origin, key, value, last_modified FROM web_storage WHERE profile_id=?",
        (profile_id,),
    ).fetchall()
    for row in rows:
        value = row["value"] or ""
        for match in _UA_PATTERN.finditer(value):
            _record(seen, match.group(0), row["last_modified"] or "", f"storage:{row['key']}@{row['origin']}")
    if not seen:
        return 0
    for ua, info in seen.items():
        conn.execute(
            "INSERT INTO user_agents(profile_id, user_agent, first_seen, last_seen, "
            "seen_count, source) VALUES(?, ?, ?, ?, ?, ?)",
            (
                profile_id, ua, info["first"], info["last"], info["count"],
                info["source"],
            ),
        )
    return len(seen)


def _record(seen: dict, ua: str, ts: str, source: str) -> None:
    if not ua or "Mozilla/" not in ua:
        return
    ua = ua.strip()[:512]
    if ua not in seen:
        seen[ua] = {"first": ts, "last": ts, "count": 1, "source": source}
        return
    entry = seen[ua]
    entry["count"] += 1
    if ts and (not entry["first"] or ts < entry["first"]):
        entry["first"] = ts
    if ts and ts > entry["last"]:
        entry["last"] = ts
