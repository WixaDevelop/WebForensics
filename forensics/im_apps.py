"""Instant-messaging webapp extractors.

WhatsApp Web, Discord and Telegram Web all use IndexedDB for message
storage, which the generic ``web_storage`` extractor already dumps. This
module post-processes those rows into a structured ``messages`` table.

The challenge: IndexedDB values are V8 structured-clone blobs. Without a full
deserialiser we can't always rebuild objects perfectly, but we can fish out
the obvious fields: sender, body, timestamp. For each app we keep a small
set of *known key prefixes* and regex-extract what looks like a message.

Best-effort, but for forensic purposes this often surfaces enough to prove
a conversation existed even when the live IM tab is closed.
"""

from __future__ import annotations

import json
import logging
import re
import sqlite3
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


# Origin → app name. We look at ``web_storage.origin`` to dispatch.
_IM_ORIGINS = {
    "https://web.whatsapp.com":   "whatsapp",
    "https://discord.com":        "discord",
    "https://web.telegram.org":   "telegram",
    "https://app.slack.com":      "slack",
    "https://teams.microsoft.com":"teams",
}


_TIMESTAMP_FIELDS = ("t", "ts", "timestamp", "time", "created_at", "edited_timestamp", "sentAt")
_BODY_FIELDS = ("body", "text", "content", "msg", "message", "caption")
_FROM_FIELDS = ("from", "fromMe", "sender", "author", "userId", "from_id")
_NAME_FIELDS = ("name", "username", "pushname", "global_name", "verifiedName")
_CHAT_FIELDS = ("chat", "channel_id", "remote", "chatId", "to")


def harvest_messages(conn: sqlite3.Connection, profile_id: int) -> int:
    """Scan ``web_storage`` rows for *profile_id* and write to ``messages``.

    Returns the count of inserted message rows.
    """
    inserted = 0
    rows = conn.execute(
        "SELECT id, origin, key, value, last_modified FROM web_storage "
        "WHERE profile_id=? AND kind IN ('indexeddb', 'localstorage')",
        (profile_id,),
    ).fetchall()
    for row in rows:
        app = _app_for_origin(row["origin"] or "")
        if not app:
            continue
        value = row["value"] or ""
        if len(value) < 20:
            continue
        for payload in _extract_message_payloads(value):
            inserted += _insert_message(conn, profile_id, app, payload, row)
    return inserted


def _app_for_origin(origin: str) -> str:
    for prefix, app in _IM_ORIGINS.items():
        if origin.startswith(prefix):
            return app
    return ""


def _extract_message_payloads(blob: str):
    """Yield dict-shaped payloads that look like messages.

    We parse every JSON-like substring (objects with key/value) found in
    the storage value. WhatsApp Web stores ``{"id":…,"body":…,"from":…}``
    blobs; Discord stores arrays of ``{"id":…,"author":…,"content":…}``.
    """
    # Strip leading garbage so JSON parse has a chance. We don't try every
    # offset — that's quadratic. We just look for ``{`` / ``[`` and try the
    # tail; if it doesn't parse we try the next ``{``.
    for opener_idx in (i for i, ch in enumerate(blob[:4096]) if ch in "{["):
        try:
            decoder = json.JSONDecoder()
            obj, _end = decoder.raw_decode(blob[opener_idx:])
        except (ValueError, IndexError):
            continue
        yield from _walk_objects(obj)
        return


def _walk_objects(obj):
    if isinstance(obj, dict):
        if _looks_like_message(obj):
            yield obj
        for v in obj.values():
            yield from _walk_objects(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _walk_objects(v)


def _looks_like_message(obj: dict) -> bool:
    if not isinstance(obj, dict):
        return False
    has_body = any(f in obj for f in _BODY_FIELDS)
    has_time = any(f in obj for f in _TIMESTAMP_FIELDS)
    return has_body and has_time


def _insert_message(conn, profile_id: int, app: str, payload: dict, src_row) -> int:
    body = _pick(payload, _BODY_FIELDS)
    ts = _pick_timestamp(payload)
    sender_id = str(_pick(payload, _FROM_FIELDS) or "")[:240]
    sender_name = str(_pick(payload, _NAME_FIELDS) or "")[:240]
    chat_id = str(_pick(payload, _CHAT_FIELDS) or "")[:240]
    body = str(body or "").strip()
    if not body:
        return 0
    body = body[:4000]
    conn.execute(
        "INSERT INTO messages(profile_id, app, chat_id, chat_name, sender_id, "
        "sender_name, body, ts, source) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            profile_id, app, chat_id, "", sender_id, sender_name, body, ts,
            f"web_storage:{src_row['id']}@{src_row['origin']}",
        ),
    )
    return 1


def _pick(obj: dict, fields):
    for f in fields:
        if f in obj and obj[f] is not None:
            return obj[f]
    return None


def _pick_timestamp(obj: dict) -> str:
    raw = _pick(obj, _TIMESTAMP_FIELDS)
    if raw is None:
        return ""
    if isinstance(raw, str) and "T" in raw:
        return raw
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return ""
    # WhatsApp uses seconds; Discord uses milliseconds; both store epochs > 1e9.
    if value > 1e12:
        value = value / 1000.0
    try:
        return datetime.fromtimestamp(value, tz=timezone.utc).isoformat()
    except (OverflowError, ValueError):
        return ""
