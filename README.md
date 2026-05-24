# WebForensics

Forensic analysis tool for **Google Chrome**, **Microsoft Edge**, **Brave**,
**Opera / Opera GX**, **Vivaldi**, **Mozilla Firefox** and **Tor Browser**
profiles — from a live system *or* from a forensic image (E01 / raw `.dd`).
Built with PyQt5, distributed as a Windows `.exe`.

> ⚠️  Use only on systems you own or have explicit authorisation to analyse.

## What it does

| Artifact          | Chromium-based         | Firefox / Tor                        |
|-------------------|------------------------|--------------------------------------|
| History           | ✔ (+ referrer graph)   | ✔ (+ referrer graph)                 |
| Cookies           | ✔ (DPAPI + AES-GCM)    | ✔                                    |
| Downloads         | ✔                      | ✔                                    |
| Saved logins      | ✔ (DPAPI + AES-GCM)    | ✔ (NSS — uses Firefox's `nss3.dll`)  |
| Bookmarks         | ✔                      | ✔                                    |
| Autofill          | ✔                      | ✔                                    |
| Extensions        | ✔                      | ✔                                    |
| Cache (URLs only) | ✔ (Simple Cache)       | ✔ (cache2)                           |
| LocalStorage / IndexedDB | ✔ (LevelDB scan)| ✔ (per-origin SQLite)                |
| Open tabs / sessions | ✔ (SNSS commands)   | ✔ (sessionstore.jsonlz4)             |
| Site permissions  | ✔ (Preferences JSON)   | ✔ (permissions.sqlite)               |
| Deleted rows      | ✔ (WAL + freelist carving) | ✔ (WAL + freelist carving)       |

Supported browsers: Chrome, Edge, Brave, Opera, Opera GX, Vivaldi, Firefox, Tor Browser.

Plus:

- **Auto-detect** profiles in default install locations, or **point at any
  folder** (mounted images, exported profiles).
- **Forensic image support**: open E01 / `.dd` / `.img` / `.raw` directly —
  enumerates `Users\<acct>\AppData` paths inside NTFS volumes and stages every
  profile to a temp directory for extraction.
- **Sessions** saved as `.wfs` (a portable SQLite file) — close and reopen
  later without re-extracting.
- **Read-only by design**: source DBs are copied to temp before opening; on
  Windows we go through `CreateFileW` with FILE_SHARE_* so live cookie
  databases can still be read where the browser allows it.
- **Chain of custody**: every E01 / raw image is SHA-256'd at open and logged
  to an append-only audit JSONL under `%LOCALAPPDATA%\WebForensics`.
- **Scalable UI**: all artifact tables are backed by SQLite via
  `QSqlTableModel`; only the visible rows are materialised, so profiles with
  millions of history rows stay responsive.
- **Timeline view** that merges every artifact's timestamp into one
  cross-browser feed.
- **Activity charts** (hour-of-day, last-30-day visits, top hosts, downloads
  per month) painted with `QPainter` — no extra dependencies.
- **Global cross-artifact search** (Ctrl-F) — LIKE across all tables, hits
  grouped by kind; double-click to jump to a pre-filtered tab.
- **Search-term extraction** — pulls the actual queries the user typed into
  Google, Bing, YouTube, DuckDuckGo, Yandex, Brave Search, Twitter/X, GitHub
  etc. out of history URLs, with a dedicated "Searches" tab that ranks them.
- **IOC matching** — load a CSV / JSON / line-delimited list of domains,
  URLs, hashes, IPs, emails or usernames; rows that match are highlighted in
  red across every artifact table with a hit count per IOC.
- **SQLite carving** — recovers deleted history rows from unallocated and
  WAL space (parses the SQLite record format directly). Carved rows are
  flagged with an amber background and `visit_type = "carved"`.
- **Anti-forensics findings** — a dedicated "Findings" tab runs heuristic
  checks: timeline gaps, empty history with surviving bookmarks/cookies,
  orphan cookies whose host never appears in history, hosts that only
  exist in carved records, and time-warped events.
- **Tags + notes** — right-click any row to tag it as evidence or attach an
  analyst note; tagged rows get a blue highlight and persist in the `.wfs`.
- **Export** to CSV (one file per artifact), JSON (single document), a
  self-contained HTML report, or a **court-ready PDF** with a cover page,
  chain-of-custody (source-image SHA-256 list pulled from the audit log)
  and paginated per-artifact tables.
- **URL categorization** — every history / download / bookmark URL is tagged
  (banking, social, mail, im, streaming, gambling, adult, cloud, crypto,
  shopping, search, news, dev, government, education, **darkweb**, vpn_proxy,
  advertising). Filter the history tab by category to scope analysis.
- **Session diff** (Tools → Compare sessions…) — pick two `.wfs` files and see
  which URLs / cookies / logins / tabs / permissions changed between captures.
- **Command-line mode** — `python -m cli auto --out report.pdf` or
  `python -m cli extract --image suspect.E01 --out evidence.wfs` for headless
  forensic pipelines.
- **Bates numbering** — every artifact row gets a stable `WF-NNNNNNNN` ID,
  legally citable. Source-file metadata table records every file touched with
  SHA-256, size, mtime/atime/ctime and image offset.
- **Report signing** — every PDF gets an HMAC-SHA256 sidecar. Tamper-evident
  with one click via the verifier.
- **CASE / UCO export** — interchange format accepted by Autopsy, FTK,
  X-Ways. Maps every artifact to the matching UCO facet (URLFacet,
  HTTPCookieFacet, FileFacet, AccountFacet, etc).
- **Account discovery** — sweeps cookies / LocalStorage / IndexedDB for
  known identity patterns (Facebook `c_user`, Twitter `twid`, Google session,
  GitHub user, Discord snowflake, etc.) and surfaces the resolved accounts.
- **OAuth / JWT harvesting** — scans every cookie and storage value for
  valid JWTs, decodes them and writes `(issuer, subject, scope, exp)` to a
  `tokens` table.
- **IM webapp extractors** — best-effort recovery of WhatsApp Web / Discord /
  Telegram Web messages from IndexedDB blobs.
- **OS-artifact correlation** — Windows Registry (TypedURLs, TypedPaths),
  Prefetch (browser executable launches), LNK recent docs and the static
  hosts file, plus a live `ipconfig /displaydns` snapshot when available.
- **Offline domain enrichment** — flags risky TLDs (`.tk`, `.onion`,
  punycode), assigns country from ccTLD.
- **Network graph** — referrer chains drawn with a force-directed layout
  (no extra deps). Click a host to see inbound / outbound link counts.
- **Full-text search (FTS5)** — virtual table indexed across history,
  cookies, downloads, logins, bookmarks, storage and messages. Use
  `term1 AND term2` / `phrase` / `prefix*` / `NEAR(a b, 5)` operators.
- **Regex filters + saved searches** — toggle `.*` in any artifact table to
  switch the filter to a Python regex. Save named filters into the `.wfs`.
- **Light / dark theme** toggle and **EN / ES** language switch.

## Install (from source)

Python 3.10+ required.

```powershell
git clone https://github.com/WixaDevelop/WebForensics.git
cd WebForensics
pip install -r requirements.txt
python main.py
```

The `pytsk3` and `libewf-python` packages bring in compiled binaries needed
for E01 / disk-image support. On Windows the wheels on PyPI work out of the
box; on Linux you may need `libtsk-dev` and `libewf-dev` from your package
manager.

## Build a Windows `.exe`

```powershell
powershell -ExecutionPolicy Bypass -File .\build\build.ps1
```

This produces `dist\WebForensics\WebForensics.exe` (≈160 MB folder). If
[Inno Setup](https://jrsoftware.org/isdl.php) is installed and `iscc.exe` is
on PATH, the script also builds a single-file installer at
`dist\WebForensics-<version>-setup.exe`.

## Project layout

```
WebForensics/
├── main.py                       entry point
├── controller.py                 ForensicsController — UI ↔ extractors ↔ image
├── browsers/                     one extractor per browser family
│   ├── base.py                   abstract BrowserBase + BrowserProfile
│   ├── chromium.py               shared Chrome/Edge/Brave/Opera/Vivaldi logic
│   ├── chrome.py / edge.py / brave.py / vivaldi.py
│   ├── opera.py / opera_gx.py    flattened single-profile Chromium variants
│   ├── firefox.py
│   └── tor.py                    Firefox derivative inside Tor Browser bundle
├── data/
│   ├── store.py                  SessionStore — SQLite analytical backing store
│   ├── session.py                .wfs save/open
│   ├── sqlite_handler.py         locked-file aware reader
│   ├── decryptor.py              Chromium DPAPI + AES-256-GCM
│   ├── nss_decryptor.py          Firefox NSS SDR via ctypes
│   └── models.py                 typed records produced by extractors
├── exporters/                    CSV / JSON / HTML / PDF / CASE-UCO
├── forensics/
│   ├── image.py                  open E01 (pyewf) or raw (pytsk3)
│   ├── extractor.py              walk NTFS, stage profiles to temp
│   ├── search_terms.py           parse search queries out of URLs
│   ├── ioc.py                    IOC loading + matching
│   ├── sqlite_carver.py          recover deleted SQLite records
│   ├── anti_forensics.py         heuristic indicator analysers
│   ├── cache.py                  Chromium Simple Cache + Firefox cache2
│   ├── web_storage.py            LevelDB + per-origin SQLite scanner
│   ├── sessions.py               SNSS + sessionstore.jsonlz4 parsers
│   ├── permissions.py            site-permission extraction
│   ├── diff.py                   .wfs ↔ .wfs comparator
│   ├── identity.py               account discovery + JWT harvesting
│   ├── im_apps.py                WhatsApp/Discord/Telegram message rec.
│   ├── user_agents.py            UA fingerprint extraction
│   ├── os_artifacts.py           Windows Registry / Prefetch / LNK / DNS
│   ├── enrichment.py             offline TLD risk + country lookup
│   └── categorizer.py            URL classifier (banking/social/...)
├── ui/
│   ├── main_window.py            shell — toolbar, tabs, threads, sessions
│   ├── i18n.py                   in-process tr() with EN/ES table
│   ├── theme.py                  light / dark palettes
│   ├── widgets/                  DataTable (virtual), DetailPanel,
│   │                             TimelineView, ChartsView, GlobalSearch,
│   │                             SearchTermsView, FindingsView
│   └── dialogs/                  Profile, Export, IOC, Audit, About
├── utils/
│   ├── paths.py                  per-OS profile locations
│   ├── time_utils.py             WebKit (1601) / PRTime (1970) conversion
│   ├── hashing.py                SHA-256 streamer
│   ├── audit.py                  append-only JSONL audit log
│   └── signing.py                HMAC-SHA256 report signatures
└── build/
    ├── webforensics.spec         PyInstaller spec
    ├── build.ps1                 build script (PyInstaller + Inno Setup)
    └── installer.iss             Inno Setup installer definition
```

## Notes on decryption

- **Chromium cookies / logins** decrypt only when the analysis runs under the
  same Windows account that originally encrypted them — DPAPI is bound to the
  user's SID + master key. From a forensic image, decryption requires the
  master key, which is out of scope here.
- **Firefox logins** are unwrapped by Firefox's own `nss3.dll`. The locator
  looks in `C:\Program Files\Mozilla Firefox`. If the user set a master
  password the call returns `encrypted=True`; ask the analyst for it before
  re-running.

## IOC feed format

The IOC dialog accepts three formats:

* **CSV** with a header row — at minimum a `value` column; `kind`, `severity`,
  `source`, `description` optional.
* **JSON** — a list of objects, or `{ "iocs": [...] }`. Each entry can be a
  bare string or an object with the same fields as the CSV.
* **Plain text** — one IOC per line. Lines starting with `#` are skipped.
  Kind is inferred from the value (hash > IP > URL > domain).

Severities accepted: `info`, `low`, `medium`, `high`, `critical`. After
loading, click **Match now** to scan all currently-ingested artifacts.

## Carving limitations

WAL + unallocated-cell carving is heuristic. We only emit a row when the
record decodes cleanly and its URL looks plausible (`http://`, `https://`,
`ftp://` or `file://` prefix). Carved rows are tagged `visit_type = "carved"`
and `deleted = 1`; the live extractor's rows remain untouched, so you can
always tell them apart in the timeline and the data tables.

## 📜 License

Custom Non-Commercial License — free for non-commercial use; commercial use
requires permission from <wiixa.devp@gmail.com>.
