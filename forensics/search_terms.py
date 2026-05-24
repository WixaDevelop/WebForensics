"""Parse search queries out of browser-history URLs.

Most search engines pass the user's query through a well-known querystring
parameter (Google ``q=``, DuckDuckGo ``q=``, YouTube ``search_query=``, Bing
``q=``, Yahoo ``p=``, etc.). We match the host against a small registry and
URL-decode whatever the engine uses, producing one record per visited search
page.

This is *not* hooked into navigation in real time — it's a post-pass over the
``history`` table after a profile's been ingested, so it works for both live
extractions and forensic images.
"""

from __future__ import annotations

import logging
import sqlite3
from dataclasses import dataclass
from typing import Iterable, Iterator
from urllib.parse import parse_qs, unquote_plus, urlparse

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class _EnginePattern:
    name: str
    host_suffix: tuple[str, ...]   # match if URL host ends with one of these
    path_prefix: tuple[str, ...]   # additionally require the path to start with one of these (empty = any)
    query_keys: tuple[str, ...]    # querystring keys, tried in order


# Order matters: more-specific hosts first (mail.google.com would otherwise
# match google.com). Empty path_prefix means "any path".
_ENGINES: tuple[_EnginePattern, ...] = (
    _EnginePattern("YouTube", ("youtube.com", "m.youtube.com"), ("/results",), ("search_query",)),
    _EnginePattern("Google Images", ("google.com", "www.google.com"), ("/imgres", "/images/search"), ("q", "query")),
    _EnginePattern("Google", ("google.com", "www.google.com", "google.co", "google.es"),
                   ("/search", "/url", "/webhp", "/#q"), ("q", "query")),
    _EnginePattern("Bing", ("bing.com", "www.bing.com"), ("/search", "/images"), ("q",)),
    _EnginePattern("DuckDuckGo", ("duckduckgo.com",), ("/",), ("q",)),
    _EnginePattern("Yahoo", ("search.yahoo.com",), ("/search",), ("p", "q")),
    _EnginePattern("Yandex", ("yandex.com", "yandex.ru"), ("/search",), ("text",)),
    _EnginePattern("Baidu", ("baidu.com",), ("/s",), ("wd", "word")),
    _EnginePattern("Ecosia", ("ecosia.org",), ("/search",), ("q",)),
    _EnginePattern("Startpage", ("startpage.com",), ("/do/search", "/search"), ("query", "q")),
    _EnginePattern("Brave Search", ("search.brave.com",), ("/search",), ("q",)),
    _EnginePattern("Twitter / X", ("twitter.com", "x.com"), ("/search",), ("q",)),
    _EnginePattern("Reddit", ("reddit.com", "www.reddit.com", "old.reddit.com"),
                   ("/search", "/r/"), ("q",)),
    _EnginePattern("GitHub", ("github.com",), ("/search",), ("q",)),
    _EnginePattern("StackOverflow", ("stackoverflow.com",), ("/search",), ("q",)),
    _EnginePattern("Wikipedia", ("wikipedia.org",), ("/wiki/Special:Search", "/w/index.php"), ("search", "q")),
    _EnginePattern("Amazon", ("amazon.com", "amazon.co.uk", "amazon.es"), ("/s",), ("k", "field-keywords")),
    _EnginePattern("eBay", ("ebay.com", "ebay.es"), ("/sch/",), ("_nkw",)),
)


def extract_search_term(url: str) -> dict | None:
    """Return ``{engine, query, url}`` if *url* looks like a search page.

    Returns ``None`` for non-search URLs so callers can quickly filter.
    """
    if not url or not isinstance(url, str):
        return None
    try:
        parsed = urlparse(url)
    except ValueError:
        return None
    host = (parsed.hostname or "").lower()
    if not host:
        return None
    path = parsed.path or ""
    qs = parse_qs(parsed.query, keep_blank_values=False)

    for engine in _ENGINES:
        if not any(host == h or host.endswith("." + h) for h in engine.host_suffix):
            continue
        if engine.path_prefix and not any(path.startswith(p) for p in engine.path_prefix):
            continue
        for key in engine.query_keys:
            if key in qs and qs[key]:
                term = unquote_plus(qs[key][0]).strip()
                if term:
                    return {"engine": engine.name, "query": term, "url": url}
        # Some engines include the term in the fragment (e.g. legacy Google #q=…).
        if parsed.fragment:
            frag_qs = parse_qs(parsed.fragment)
            for key in engine.query_keys:
                if key in frag_qs and frag_qs[key]:
                    term = unquote_plus(frag_qs[key][0]).strip()
                    if term:
                        return {"engine": engine.name, "query": term, "url": url}
    return None


def derive_search_terms_for_profile(
    conn: sqlite3.Connection,
    profile_id: int,
) -> Iterator[dict]:
    """Yield one search-term record per history row whose URL is a search page."""
    rows = conn.execute(
        "SELECT url, title, last_visit FROM history WHERE profile_id=? AND url IS NOT NULL",
        (profile_id,),
    )
    for row in rows:
        parsed = extract_search_term(row["url"])
        if not parsed:
            continue
        yield {
            "engine": parsed["engine"],
            "query": parsed["query"],
            "url": parsed["url"],
            "title": row["title"] or "",
            "ts": row["last_visit"] or "",
        }
