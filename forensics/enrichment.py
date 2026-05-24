"""Offline domain enrichment.

Filling out WHOIS and GeoIP information is genuinely useful — recently
registered domains in history are textbook phishing indicators, suspicious
TLDs are flagged in policy guides. But online lookups are slow, leak the
investigation, and break in air-gapped environments.

So we keep this fully offline. Two information sources:

* **TLD risk table** — a curated list of TLDs known to be cheap / abused for
  scams / parked domains. From multiple public abuse trackers.
* **Country-by-TLD** — ccTLD → ISO country code. Handy for "this user touched
  domains in 30 countries last week" analyses.

If the user wants real WHOIS data they can run a separate lookup and import
via CSV with kind=domain rows — the IOC loader already handles that.

Output: the ``domain_intel`` table, populated on demand for every distinct
host found in ``history``.
"""

from __future__ import annotations

import logging
import sqlite3
from datetime import datetime, timezone
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


# TLDs flagged in recent abuse reports (Spamhaus / Symantec / etc).
_RISKY_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq",        # Freenom — historically free, heavily abused
    ".top", ".xyz", ".loan", ".click", ".link",
    ".work", ".gdn", ".country", ".racing",
    ".surf", ".rest", ".monster",
    ".buzz", ".fit", ".support",
}

_HIGH_RISK_TLDS = {".onion", ".i2p"}  # Tor / I2P — special handling


# ISO country codes by ccTLD. Trimmed list — the most common ccTLDs in browser
# data. Unmatched TLDs leave country empty.
_TLD_COUNTRY = {
    ".es": "ES", ".uk": "GB", ".de": "DE", ".fr": "FR", ".it": "IT",
    ".pt": "PT", ".nl": "NL", ".se": "SE", ".no": "NO", ".dk": "DK",
    ".fi": "FI", ".pl": "PL", ".gr": "GR", ".cz": "CZ", ".at": "AT",
    ".ch": "CH", ".be": "BE", ".ie": "IE", ".ro": "RO", ".bg": "BG",
    ".hu": "HU",
    ".us": "US", ".ca": "CA", ".mx": "MX", ".br": "BR", ".ar": "AR",
    ".cl": "CL", ".co": "CO", ".pe": "PE", ".uy": "UY", ".ve": "VE",
    ".ru": "RU", ".ua": "UA", ".by": "BY", ".kz": "KZ", ".cn": "CN",
    ".jp": "JP", ".kr": "KR", ".tw": "TW", ".hk": "HK", ".in": "IN",
    ".id": "ID", ".my": "MY", ".sg": "SG", ".th": "TH", ".vn": "VN",
    ".ph": "PH",
    ".au": "AU", ".nz": "NZ", ".za": "ZA", ".ng": "NG", ".eg": "EG",
    ".ma": "MA", ".sa": "SA", ".ae": "AE", ".il": "IL", ".ir": "IR",
    ".tr": "TR",
}


def enrich_domains(conn: sqlite3.Connection, profile_id: int | None = None) -> int:
    """Populate ``domain_intel`` for every host in history.

    Returns the number of *new* rows added (existing entries are left alone).
    """
    where = ""
    params: tuple = ()
    if profile_id is not None:
        where = " WHERE profile_id=?"
        params = (int(profile_id),)
    rows = conn.execute(
        f"SELECT DISTINCT url FROM history{where} AND url IS NOT NULL "
        if where else
        "SELECT DISTINCT url FROM history WHERE url IS NOT NULL ",
        params,
    ).fetchall()
    hosts: set[str] = set()
    for row in rows:
        try:
            host = urlparse(str(row["url"])).hostname or ""
        except ValueError:
            continue
        if host:
            hosts.add(host.lower().lstrip("."))
    if not hosts:
        return 0
    added = 0
    for host in hosts:
        if conn.execute("SELECT 1 FROM domain_intel WHERE domain=?", (host,)).fetchone():
            continue
        intel = enrich_one(host)
        conn.execute(
            "INSERT OR IGNORE INTO domain_intel(domain, country, risk, notes, refreshed_at) "
            "VALUES(?, ?, ?, ?, ?)",
            (
                host,
                intel["country"],
                intel["risk"],
                intel["notes"],
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        added += 1
    return added


def enrich_one(host: str) -> dict:
    """Compute (country, risk, notes) for a single host using local data only."""
    host = host.lower().lstrip(".")
    if not host:
        return {"country": "", "risk": "info", "notes": ""}
    country = ""
    risk = "info"
    notes: list[str] = []
    # Match the longest TLD suffix first (handles co.uk type).
    for suffix in sorted(_TLD_COUNTRY, key=len, reverse=True):
        if host.endswith(suffix):
            country = _TLD_COUNTRY[suffix]
            break
    last_dot = host.rfind(".")
    tld = host[last_dot:] if last_dot >= 0 else ""
    if tld in _HIGH_RISK_TLDS:
        risk = "high"
        notes.append("anonymity-network domain")
    elif tld in _RISKY_TLDS:
        risk = "medium"
        notes.append("TLD frequently abused for phishing")
    if host.count("-") >= 3 or any(host.startswith(p) for p in ("xn--",)):
        notes.append("punycode / dashy hostname — possible homograph")
        if risk == "info":
            risk = "medium"
    return {
        "country": country,
        "risk": risk,
        "notes": "; ".join(notes),
    }
