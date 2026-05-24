"""Turn opaque cookies and storage values into named accounts + tokens.

After ingest we sweep through ``cookies``, ``web_storage`` and ``messages``
for patterns that map to a real-world identity. Examples:

* Google cookies — ``HSID``/``SID``/``SIDCC`` + ``__Secure-1PSID`` + storage
  key ``Google ID Token`` reveal a Google account UID.
* Facebook cookie ``c_user`` is literally the user ID.
* Twitter/X cookie ``twid`` contains ``u%3D<id>``.
* GitHub cookies ``user_session`` + ``logged_in`` + storage entries reveal username.
* Discord LocalStorage key ``user_id`` is the snowflake.
* JWTs (anywhere) are decoded — issuer + subject + scopes go to the tokens table.

The output is two tables: ``accounts`` (identity) and ``tokens`` (creds with
expiry). Everything is best-effort — false positives are filtered by requiring
the value to look like the expected format (numeric UID, JWT header).
"""

from __future__ import annotations

import base64
import json
import logging
import re
import sqlite3
from datetime import datetime, timezone
from typing import Iterable, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Cookie-based identity rules
# ---------------------------------------------------------------------------


# (cookie name, host substring) → service. Matching: cookie.name equals the
# rule's name AND cookie.host contains the rule's host substring.
_COOKIE_ID_RULES = (
    ("c_user",        "facebook.com",      "facebook",   "user_id"),
    ("xs",            "facebook.com",      "facebook",   "session"),
    ("twid",          "twitter.com",       "twitter",    "user_id"),
    ("twid",          "x.com",             "twitter",    "user_id"),
    ("ds_user_id",    "instagram.com",     "instagram",  "user_id"),
    ("sessionid",     "instagram.com",     "instagram",  "session"),
    ("user_session",  "github.com",        "github",     "session"),
    ("dotcom_user",   "github.com",        "github",     "username"),
    ("li_at",         "linkedin.com",      "linkedin",   "session"),
    ("liap",          "linkedin.com",      "linkedin",   "user_flag"),
    ("PREF",          ".google.com",       "google",     "pref"),
    ("__Secure-1PSID","google.com",        "google",     "session"),
    ("SAPISID",       "google.com",        "google",     "session"),
    ("HSID",          "google.com",        "google",     "session"),
    ("SID",           "google.com",        "google",     "session"),
    ("token",         "discord.com",       "discord",    "session"),
    ("__Secure-next-auth.session-token", "", "next_auth", "session"),
    ("auth_token",    "twitter.com",       "twitter",    "session"),
    ("amazon-search-language", "amazon.",  "amazon",     "session"),
    ("reddit_session", "reddit.com",       "reddit",     "session"),
)


# Twitter/X stores user id inside ``twid`` as ``u%3D<digits>``.
_TWID_RE = re.compile(r"u%3D(?P<id>\d+)", re.IGNORECASE)
# Numeric Facebook c_user id has 8-17 digits.
_NUMERIC_ID_RE = re.compile(r"^\d{4,20}$")


def harvest_identities(conn: sqlite3.Connection, profile_id: int) -> dict:
    """Run every rule and INSERT into ``accounts`` and ``tokens``.

    Returns a counts dict for callers that want to surface it.
    """
    accounts_added = 0
    tokens_added = 0

    accounts_added += _scan_cookies(conn, profile_id)
    accounts_added += _scan_storage_for_identity(conn, profile_id)
    tokens_added += _scan_storage_for_tokens(conn, profile_id)
    tokens_added += _scan_cookies_for_tokens(conn, profile_id)
    return {"accounts": accounts_added, "tokens": tokens_added}


def _scan_cookies(conn: sqlite3.Connection, profile_id: int) -> int:
    added = 0
    rows = conn.execute(
        "SELECT id, host, name, value, last_access FROM cookies WHERE profile_id=?",
        (profile_id,),
    ).fetchall()
    seen: set[tuple[str, str]] = set()
    for row in rows:
        host = (row["host"] or "").lower()
        name = row["name"] or ""
        value = row["value"] or ""
        last_seen = row["last_access"] or ""
        for rule_name, host_substr, service, role in _COOKIE_ID_RULES:
            if name != rule_name:
                continue
            if host_substr and host_substr not in host:
                continue
            identifier, username = _extract_identifier(service, name, value, role)
            if not identifier and not username:
                continue
            key = (service, identifier or username)
            if key in seen:
                continue
            seen.add(key)
            conn.execute(
                "INSERT INTO accounts(profile_id, service, identifier, username, "
                "source, detail, last_seen) VALUES(?, ?, ?, ?, ?, ?, ?)",
                (
                    profile_id,
                    service,
                    identifier or "",
                    username or "",
                    "cookie",
                    f"{name} on {host}",
                    last_seen,
                ),
            )
            added += 1
    return added


def _extract_identifier(service: str, name: str, value: str, role: str) -> tuple[str, str]:
    """Pull a usable identifier from a cookie value.

    Returns ``(identifier, username)``. ``identifier`` is the stable user ID,
    ``username`` is a human-readable handle when the cookie carries one.
    """
    if not value:
        return "", ""
    # Cookies that *are* the user id directly.
    if name == "c_user" and _NUMERIC_ID_RE.match(value):
        return value, ""
    if name == "ds_user_id" and _NUMERIC_ID_RE.match(value):
        return value, ""
    if name == "dotcom_user":
        # GitHub stores the username directly in this cookie.
        return "", value
    if name == "twid":
        match = _TWID_RE.search(value)
        if match:
            return match.group("id"), ""
        return "", ""
    if name == "next-auth.session-token" or name.startswith("__Secure-next-auth"):
        # Parse the JWT/JWE payload if we can; otherwise note we saw a session.
        sub, _ = _decode_jwt_subject(value)
        return sub or "", ""
    # Default: surface the raw token only when it doesn't look like a long
    # opaque blob (don't pollute accounts with bytes nobody can interpret).
    if 4 <= len(value) <= 64 and _NUMERIC_ID_RE.match(value):
        return value, ""
    return "", ""


# ---------------------------------------------------------------------------
# LocalStorage / IndexedDB identity rules
# ---------------------------------------------------------------------------


_STORAGE_ID_RULES = (
    # (key substring, origin substring, service, role)
    ("user_id",                  "discord.com",       "discord",  "user_id"),
    ("user_id_cache",            "discord.com",       "discord",  "user_id"),
    ("user-cache-v2",            "discord.com",       "discord",  "user_id"),
    ("currentUserId",            "twitter.com",       "twitter",  "user_id"),
    ("twid",                     "twitter.com",       "twitter",  "user_id"),
    ("user_authToken",           "linkedin.com",      "linkedin", "session"),
    ("MyAccount.userId",         "amazon.",           "amazon",   "user_id"),
    ("googleAccountInfo",        "google.com",        "google",   "user_id"),
    ("apns/user_id",             "apple.com",         "apple",    "user_id"),
    ("authToken",                "telegram",          "telegram", "session"),
    ("loggedUser",               "",                  "generic",  "user_id"),
)


def _scan_storage_for_identity(conn: sqlite3.Connection, profile_id: int) -> int:
    added = 0
    rows = conn.execute(
        "SELECT id, origin, kind, key, value, last_modified FROM web_storage "
        "WHERE profile_id=?", (profile_id,),
    ).fetchall()
    seen: set[tuple[str, str]] = set()
    for row in rows:
        origin = (row["origin"] or "").lower()
        key = row["key"] or ""
        value = row["value"] or ""
        for sub, origin_substr, service, role in _STORAGE_ID_RULES:
            if sub not in key.lower():
                continue
            if origin_substr and origin_substr not in origin:
                continue
            identifier, username = _identifier_from_storage(value, role)
            if not identifier and not username:
                continue
            entry_key = (service, identifier or username)
            if entry_key in seen:
                continue
            seen.add(entry_key)
            conn.execute(
                "INSERT INTO accounts(profile_id, service, identifier, username, "
                "source, detail, last_seen) VALUES(?, ?, ?, ?, ?, ?, ?)",
                (
                    profile_id, service, identifier or "", username or "",
                    row["kind"] or "localstorage",
                    f"{key} at {origin}",
                    row["last_modified"] or "",
                ),
            )
            added += 1
    return added


def _identifier_from_storage(value: str, role: str) -> tuple[str, str]:
    if not value:
        return "", ""
    raw = value.strip().strip('"\'')
    if _NUMERIC_ID_RE.match(raw):
        return raw, ""
    # JSON snowflake / discord wraps the id inside a JSON envelope.
    try:
        obj = json.loads(raw)
    except (ValueError, TypeError):
        obj = None
    if isinstance(obj, dict):
        for cand in ("id", "user_id", "uid", "userId", "subject"):
            if cand in obj:
                v = str(obj[cand])
                if _NUMERIC_ID_RE.match(v) or len(v) <= 64:
                    return v, ""
        for cand in ("username", "name", "login", "handle"):
            if cand in obj and isinstance(obj[cand], str):
                return "", obj[cand]
    if isinstance(obj, list) and obj and isinstance(obj[0], dict):
        return _identifier_from_storage(json.dumps(obj[0]), role)
    return "", ""


# ---------------------------------------------------------------------------
# JWT / OAuth token detection
# ---------------------------------------------------------------------------


# Standard 3-part JWT: ``<base64>.<base64>.<base64>``.
_JWT_RE = re.compile(r"(eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})")


def _scan_cookies_for_tokens(conn: sqlite3.Connection, profile_id: int) -> int:
    added = 0
    for row in conn.execute(
        "SELECT id, host, name, value FROM cookies WHERE profile_id=?", (profile_id,),
    ):
        added += _classify_token(conn, profile_id, row["value"] or "", source=f"cookie:{row['name']}@{row['host']}")
    return added


def _scan_storage_for_tokens(conn: sqlite3.Connection, profile_id: int) -> int:
    added = 0
    for row in conn.execute(
        "SELECT id, origin, key, value FROM web_storage WHERE profile_id=?", (profile_id,),
    ):
        added += _classify_token(conn, profile_id, row["value"] or "", source=f"storage:{row['key']}@{row['origin']}")
    return added


def _classify_token(conn: sqlite3.Connection, profile_id: int, payload: str, source: str) -> int:
    """Insert one row in ``tokens`` for every JWT detected in *payload*."""
    if not payload:
        return 0
    found = 0
    for match in _JWT_RE.finditer(payload):
        jwt = match.group(1)
        sub, claims = _decode_jwt_subject(jwt)
        if claims is None:
            continue
        service = _service_from_jwt(claims)
        exp = claims.get("exp")
        expires_at = ""
        if isinstance(exp, (int, float)) and exp > 0:
            try:
                expires_at = datetime.fromtimestamp(exp, tz=timezone.utc).isoformat()
            except (OverflowError, ValueError):
                expires_at = ""
        scope = claims.get("scope") or claims.get("scp") or ""
        if isinstance(scope, list):
            scope = " ".join(str(s) for s in scope)
        conn.execute(
            "INSERT INTO tokens(profile_id, kind, service, issuer, subject, scope, "
            "expires_at, source, value) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                profile_id,
                "jwt",
                service,
                str(claims.get("iss", ""))[:240],
                str(sub or claims.get("sub", ""))[:240],
                str(scope)[:240],
                expires_at,
                source[:240],
                jwt[:1200],  # bound the stored value
            ),
        )
        found += 1
    return found


def _decode_jwt_subject(jwt: str) -> tuple[Optional[str], Optional[dict]]:
    """Return (sub, full_payload) by base64url-decoding the second segment."""
    parts = jwt.split(".")
    if len(parts) < 2:
        return None, None
    body = parts[1]
    pad = "=" * (-len(body) % 4)
    try:
        decoded = base64.urlsafe_b64decode(body + pad)
        claims = json.loads(decoded)
    except (ValueError, TypeError, json.JSONDecodeError):
        return None, None
    if not isinstance(claims, dict):
        return None, None
    return str(claims.get("sub") or "") or None, claims


def _service_from_jwt(claims: dict) -> str:
    iss = str(claims.get("iss") or "").lower()
    if "google" in iss or "accounts.google" in iss:
        return "google"
    if "microsoftonline" in iss or "login.microsoft" in iss:
        return "microsoft"
    if "auth0" in iss:
        return "auth0"
    if "okta" in iss:
        return "okta"
    if "amazonaws" in iss or "cognito" in iss:
        return "aws_cognito"
    if "discord" in iss:
        return "discord"
    if "github" in iss:
        return "github"
    return iss.split("//")[-1].split("/")[0] or "unknown"
