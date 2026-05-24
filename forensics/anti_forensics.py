"""Heuristic anti-forensics indicators.

Looks at the ingested ``SessionStore`` and writes ``findings`` rows for
patterns that often indicate a user tried to cover their tracks:

* **Timeline gap** — a stretch of ``>24h`` with zero events sandwiched
  between two stretches of normal activity. Flag both ends.
* **Cleared / wiped history** — total history rows for a profile is
  implausibly low *relative to* the number of bookmarks or cookies, or the
  profile's ``loaded_at`` is recent but ``last_visit`` of history is older
  than its earliest cookie.
* **Cookie expiry without visit** — cookies still alive but no matching
  history entry for the host (the page was visited but history wiped).
* **Carved-only host** — a host appears only in carved (deleted) history
  records and nowhere in the live tables.
* **Time-warp** — an event with a timestamp in the future (clock-fiddling).

This is heuristic and noisy by design — analysts judge findings, not the
tool. Each finding has a severity.
"""

from __future__ import annotations

import logging
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Iterable, Optional
from urllib.parse import urlparse

from data.store import SessionStore

logger = logging.getLogger(__name__)


GAP_HOURS = 24
WIPE_RATIO = 4   # >N× more bookmarks than history rows is suspicious


def run_all(store: SessionStore) -> int:
    """Re-run every analyser; returns the total number of new findings."""
    conn = store.connection()
    store.clear_findings()
    total = 0
    for profile in store.list_profiles():
        pid = int(profile["id"])
        total += _check_timeline_gaps(conn, store, pid)
        total += _check_wiped_history(conn, store, pid)
        total += _check_orphan_cookies(conn, store, pid)
        total += _check_carved_only_hosts(conn, store, pid)
    total += _check_time_warp(conn, store)
    return total


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------


def _check_timeline_gaps(conn: sqlite3.Connection, store: SessionStore, pid: int) -> int:
    rows = conn.execute(
        "SELECT ts FROM events WHERE profile_id=? AND ts IS NOT NULL AND ts != '' "
        "ORDER BY ts",
        (pid,),
    ).fetchall()
    if len(rows) < 10:
        return 0
    count = 0
    prev: Optional[datetime] = None
    for row in rows:
        ts = _parse(row["ts"])
        if ts is None:
            continue
        if prev is not None:
            gap = ts - prev
            if gap >= timedelta(hours=GAP_HOURS):
                detail = (
                    f"No events between {prev.isoformat()} and {ts.isoformat()} "
                    f"({gap.total_seconds() / 3600:.1f}h gap)."
                )
                store.record_finding(
                    "timeline_gap",
                    title=f"Timeline gap: {gap.days}d {gap.seconds // 3600}h",
                    severity="medium" if gap < timedelta(days=7) else "high",
                    detail=detail,
                    profile_id=pid,
                    ts=ts.isoformat(),
                )
                count += 1
        prev = ts
    return count


def _check_wiped_history(conn: sqlite3.Connection, store: SessionStore, pid: int) -> int:
    counts = {
        kind: conn.execute(
            f"SELECT COUNT(*) AS n FROM {kind} WHERE profile_id=?", (pid,)
        ).fetchone()["n"] for kind in ("history", "bookmarks", "cookies", "logins")
    }
    history = counts["history"]
    cookies = counts["cookies"]
    bookmarks = counts["bookmarks"]
    findings = 0
    # Bookmarks survive history clears; lots of bookmarks but no history is suspicious.
    if bookmarks >= 20 and history == 0:
        store.record_finding(
            "cleared_history",
            title="History is empty but bookmarks survive",
            severity="high",
            detail=f"{bookmarks} bookmarks present; 0 history rows. Likely a history wipe.",
            profile_id=pid,
        )
        findings += 1
    elif history > 0 and bookmarks >= WIPE_RATIO * history and bookmarks >= 10:
        store.record_finding(
            "cleared_history",
            title="History sparse relative to bookmarks",
            severity="medium",
            detail=f"{history} history rows vs. {bookmarks} bookmarks — ratio {bookmarks / history:.1f}×.",
            profile_id=pid,
        )
        findings += 1
    if cookies >= 50 and history == 0:
        store.record_finding(
            "cleared_history",
            title="History empty but cookies survive",
            severity="high",
            detail=f"{cookies} cookies retained with no corresponding visits.",
            profile_id=pid,
        )
        findings += 1
    return findings


def _check_orphan_cookies(conn: sqlite3.Connection, store: SessionStore, pid: int) -> int:
    """Cookies whose host never appears in history — common after a wipe."""
    history_hosts = set()
    for row in conn.execute(
        "SELECT url FROM history WHERE profile_id=? AND url IS NOT NULL", (pid,)
    ):
        host = urlparse(str(row["url"])).hostname or ""
        if host:
            history_hosts.add(host.lower())
    orphan_hosts: set[str] = set()
    for row in conn.execute(
        "SELECT DISTINCT host FROM cookies WHERE profile_id=? AND host IS NOT NULL "
        "AND host != ''",
        (pid,),
    ):
        cookie_host = str(row["host"]).lstrip(".").lower()
        if not cookie_host:
            continue
        # Tolerate subdomain mismatch: example.com cookie ↔ www.example.com history.
        if any(h == cookie_host or h.endswith("." + cookie_host) or cookie_host.endswith("." + h)
               for h in history_hosts):
            continue
        orphan_hosts.add(cookie_host)
    if len(orphan_hosts) >= 5:
        sample = ", ".join(sorted(orphan_hosts)[:10])
        store.record_finding(
            "orphan_cookies",
            title=f"{len(orphan_hosts)} cookie hosts have no matching history",
            severity="low" if len(orphan_hosts) < 20 else "medium",
            detail=f"Sample: {sample}{'…' if len(orphan_hosts) > 10 else ''}",
            profile_id=pid,
        )
        return 1
    return 0


def _check_carved_only_hosts(
    conn: sqlite3.Connection,
    store: SessionStore,
    pid: int,
) -> int:
    """Hosts that appear *only* in carved rows — recovered after deletion."""
    live = {
        urlparse(str(r["url"])).hostname or ""
        for r in conn.execute(
            "SELECT url FROM history WHERE profile_id=? AND deleted = 0 "
            "AND url IS NOT NULL", (pid,),
        )
    }
    carved = {
        urlparse(str(r["url"])).hostname or ""
        for r in conn.execute(
            "SELECT url FROM history WHERE profile_id=? AND deleted = 1 "
            "AND url IS NOT NULL", (pid,),
        )
    }
    only_carved = {h for h in carved if h and h not in live}
    if only_carved:
        sample = ", ".join(sorted(only_carved)[:10])
        store.record_finding(
            "carved_only_host",
            title=f"{len(only_carved)} hosts only present in deleted records",
            severity="high",
            detail=f"Recovered from WAL / freelist: {sample}"
                   f"{'…' if len(only_carved) > 10 else ''}",
            profile_id=pid,
        )
        return 1
    return 0


def _check_time_warp(conn: sqlite3.Connection, store: SessionStore) -> int:
    """Events with a timestamp far in the future."""
    rows = conn.execute(
        "SELECT profile_id, kind, summary, ts FROM events WHERE ts > ?",
        ((datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),),
    ).fetchall()
    if not rows:
        return 0
    sample_lines = []
    for row in rows[:5]:
        sample_lines.append(f"  • [{row['kind']}] {row['ts']} — {row['summary']}")
    store.record_finding(
        "time_warp",
        title=f"{len(rows)} events dated in the future",
        severity="medium",
        detail="Could indicate clock-fiddling or imported data:\n" + "\n".join(sample_lines),
        profile_id=None,
        ts=rows[0]["ts"],
    )
    return 1


def _parse(value: str) -> Optional[datetime]:
    if not value:
        return None
    try:
        # Accept both ``Z``-suffixed and naive ISO strings.
        if value.endswith("Z"):
            return datetime.fromisoformat(value[:-1]).replace(tzinfo=timezone.utc)
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return None
