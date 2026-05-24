"""Lightweight URL categorizer.

Static table of well-known domain/host patterns. Designed to be fast (substring
lookup, no regex) and forensically *neutral*: we don't shame any category, we
just label so analysts can filter "what banking did this person use" or
"what dark-web hosts appeared".

Categories: ``banking``, ``social``, ``mail``, ``im`` (instant messaging),
``streaming``, ``gambling``, ``adult``, ``cloud``, ``crypto``, ``shopping``,
``search``, ``news``, ``dev`` (developer / source-control), ``government``,
``education``, ``darkweb``, ``vpn_proxy``, ``advertising`` (trackers).
"""

from __future__ import annotations

from urllib.parse import urlparse


_CATEGORIES: dict[str, tuple[str, ...]] = {
    "banking": (
        "bankofamerica.com", "chase.com", "wellsfargo.com", "citibank.com",
        "barclays", "hsbc", "santander", "bbva", "caixabank", "ing.com",
        "revolut.com", "monzo.com", "wise.com", "n26.com",
        "paypal.com", "venmo.com", "cashapp.com", "zelle",
        "deutschebank", "bnpparibas", "ubs.com", "creditsuisse",
        "americanexpress.com", "discover.com",
    ),
    "social": (
        "facebook.com", "instagram.com", "twitter.com", "x.com",
        "linkedin.com", "tiktok.com", "snapchat.com", "pinterest.com",
        "reddit.com", "tumblr.com", "vk.com", "weibo.com", "ok.ru",
        "bsky.app", "mastodon", "threads.net",
    ),
    "mail": (
        "mail.google.com", "gmail.com", "outlook.com", "outlook.live.com",
        "outlook.office.com", "office365.com", "office.com",
        "yahoo.com/mail", "mail.yahoo.com",
        "protonmail.com", "proton.me", "tutanota.com", "fastmail.com",
        "yandex.com/mail", "mail.ru", "icloud.com/mail",
    ),
    "im": (
        "web.whatsapp.com", "messenger.com",
        "discord.com", "telegram.org", "web.telegram.org",
        "slack.com", "teams.microsoft.com", "skype.com",
        "signal.org", "wire.com", "matrix.to", "element.io",
        "wechat.com", "viber.com", "line.me",
    ),
    "streaming": (
        "youtube.com", "netflix.com", "primevideo.com", "hbo.com", "hbomax.com",
        "disneyplus.com", "hulu.com", "spotify.com", "twitch.tv",
        "deezer.com", "soundcloud.com", "paramount", "appletv",
        "movistarplus", "rakuten.tv",
    ),
    "gambling": (
        "bet365.com", "pokerstars", "betfair", "williamhill", "888casino",
        "draftkings", "fanduel", "888.com", "casino", "betway",
        "winamax", "bwin", "bet-at-home",
    ),
    "adult": (
        "pornhub", "xvideos", "xhamster", "xnxx", "redtube",
        "youporn", "onlyfans", "chaturbate", "stripchat", "livejasmin",
        "manyvids",
    ),
    "cloud": (
        "drive.google.com", "docs.google.com", "dropbox.com", "box.com",
        "onedrive.live.com", "icloud.com",
        "mega.nz", "mediafire.com", "wetransfer.com", "pcloud.com",
        "sync.com",
    ),
    "crypto": (
        "binance.com", "coinbase.com", "kraken.com", "kucoin.com",
        "bitfinex.com", "bybit.com", "okx.com", "huobi.com",
        "blockchain.com", "etherscan.io", "blockchain.info", "metamask.io",
        "trustwallet", "ledger.com", "trezor.io", "uniswap.org",
        ".eth.limo",
    ),
    "shopping": (
        "amazon.", "ebay.", "aliexpress.com", "alibaba.com",
        "shopify.com", "etsy.com", "wish.com", "shein.com",
        "mercadolibre", "wallapop.com", "vinted.",
        "elcorteingles.es",
    ),
    "search": (
        "google.com/search", "bing.com/search", "duckduckgo.com",
        "yandex.com/search", "yahoo.com/search", "search.brave.com",
        "ecosia.org/search", "startpage.com", "qwant.com",
    ),
    "news": (
        "bbc.co.uk", "cnn.com", "reuters.com", "apnews.com", "nytimes.com",
        "theguardian.com", "wsj.com", "ft.com", "elpais.com", "elmundo.es",
        "lavanguardia.com", "abc.es", "marca.com", "as.com",
        "lemonde.fr", "spiegel.de", "bild.de", "rt.com",
    ),
    "dev": (
        "github.com", "gitlab.com", "bitbucket.org",
        "stackoverflow.com", "stackexchange.com", "news.ycombinator.com",
        "npmjs.com", "pypi.org", "crates.io", "rubygems.org", "packagist.org",
        "docker.io", "hub.docker.com",
        "developer.mozilla.org", "developer.apple.com",
        "godbolt.org", "replit.com", "codepen.io", "jsfiddle.net",
        "leetcode.com", "hackerrank.com",
    ),
    "government": (
        ".gov", ".gov.uk", ".gob.es", ".gob.ar", ".gob.mx", ".gob.pe",
        ".gob.cl", ".gov.au", ".gouv.fr", ".gc.ca",
        "ssa.gov", "irs.gov", "europa.eu", "agenciatributaria.es",
        "seg-social.es", "dgt.es",
    ),
    "education": (
        ".edu", "moodle", "blackboard", "canvas.", "coursera.org",
        "edx.org", "udemy.com", "khanacademy.org", "duolingo.com",
        ".ac.uk", ".edu.es", ".edu.ar", "scholar.google",
    ),
    "darkweb": (
        ".onion", ".i2p", "tor.taxi", "dark.fail", "ahmia.fi",
        "torproject.org",
    ),
    "vpn_proxy": (
        "nordvpn.com", "expressvpn.com", "protonvpn.com", "mullvad.net",
        "windscribe.com", "surfshark.com", "tunnelbear.com",
        "pia.com", "privateinternetaccess.com", "warp.cloudflare.com",
        "openvpn.net",
    ),
    "advertising": (
        "doubleclick.net", "googlesyndication.com", "googletagmanager.com",
        "google-analytics.com", "facebook.net", "adservice.google.com",
        "criteo.com", "adnxs.com", "moatads.com", "scorecardresearch.com",
        "outbrain.com", "taboola.com", "amplitude.com", "segment.com",
        "mixpanel.com", "hotjar.com", "fullstory.com",
    ),
}


def categorize(url: str) -> str:
    """Return the category for *url*, or '' if no rule matched.

    The matching strategy is *substring on the host*, with a couple of
    URL-suffix exceptions (``/search`` paths, ``.gov`` TLDs). First match
    wins — order in ``_CATEGORIES`` defines precedence (banking beats
    advertising, ``darkweb`` beats general categories, etc.).
    """
    if not url or not isinstance(url, str):
        return ""
    try:
        parsed = urlparse(url)
    except ValueError:
        return ""
    host = (parsed.hostname or "").lower()
    if not host:
        return ""
    # Used by the ``search`` and ``mail`` heuristics that need the path too.
    needle = f"{host}{parsed.path}"
    for category, patterns in _CATEGORIES.items():
        for pattern in patterns:
            if pattern in needle:
                return category
    return ""
