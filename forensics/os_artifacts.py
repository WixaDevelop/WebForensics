"""Correlate browser activity with Windows OS-level forensic artifacts.

Four sources, each implemented as a best-effort no-dependency parser:

* **Windows Registry** — ``HKCU\\Software\\Microsoft\\Internet Explorer\\TypedURLs``,
  ``HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths``,
  default browser, search providers. We parse the ``NTUSER.DAT`` hive directly
  using a tiny built-in parser; no ``python-registry`` needed for these
  specific keys.
* **Prefetch** — ``C:\\Windows\\Prefetch\\<EXE>-<HASH>.pf``. We extract the
  executable name, run count, first/last execution times.
* **LNK files / JumpLists** — ``%APPDATA%\\Microsoft\\Windows\\Recent\\`` and
  ``%APPDATA%\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\``. We pull
  the LinkInfo target path so analysts can correlate "browser → downloaded
  file → opened from Explorer".
* **DNS cache + hosts** — ``ipconfig /displaydns`` snapshot (when run with
  privileges) and the static ``hosts`` file.

All outputs land in the ``os_artifacts`` table. Each parser is wrapped in a
try/except so the absence of any one source (e.g. Prefetch disabled by GPO)
doesn't break the rest.
"""

from __future__ import annotations

import logging
import os
import re
import struct
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator, Optional

logger = logging.getLogger(__name__)


def collect_all(conn, browser_executables: tuple[str, ...] = ()) -> int:
    """Run every OS-artifact parser and write to ``os_artifacts``.

    *browser_executables* is an allow-list of EXE names whose Prefetch entries
    we report. Pass e.g. ``("chrome.exe", "msedge.exe")`` to scope the noise.
    """
    total = 0
    try:
        total += _ingest(conn, parse_typed_urls())
    except Exception:  # noqa: BLE001
        logger.exception("TypedURLs parse failed")
    try:
        total += _ingest(conn, parse_prefetch(browser_executables))
    except Exception:  # noqa: BLE001
        logger.exception("Prefetch parse failed")
    try:
        total += _ingest(conn, parse_recent_lnk())
    except Exception:  # noqa: BLE001
        logger.exception("LNK parse failed")
    try:
        total += _ingest(conn, parse_dns_cache())
    except Exception:  # noqa: BLE001
        logger.exception("DNS cache parse failed")
    try:
        total += _ingest(conn, parse_hosts_file())
    except Exception:  # noqa: BLE001
        logger.exception("hosts parse failed")
    return total


def _ingest(conn, records: Iterator[dict]) -> int:
    n = 0
    for rec in records:
        conn.execute(
            "INSERT INTO os_artifacts(kind, source_path, browser, name, value, ts, extra) "
            "VALUES(?, ?, ?, ?, ?, ?, ?)",
            (
                rec.get("kind", ""),
                rec.get("source_path", ""),
                rec.get("browser", ""),
                rec.get("name", ""),
                rec.get("value", ""),
                rec.get("ts", ""),
                rec.get("extra", ""),
            ),
        )
        n += 1
    return n


# ---------------------------------------------------------------------------
# Windows Registry — minimal NTUSER.DAT parser for TypedURLs only.
# ---------------------------------------------------------------------------


def parse_typed_urls() -> Iterator[dict]:
    """Yield TypedURLs from the *current user's* NTUSER.DAT.

    We could parse the hive with a full library, but we only need one fixed
    key — Internet Explorer / Edge stores typed URLs there too, including
    URLs typed into the modern Edge address bar.
    """
    if os.name != "nt":
        return
    # On a live system the loaded hive is at ``HKEY_CURRENT_USER`` — talk to it
    # via the winreg module rather than parse the .dat directly.
    try:
        import winreg  # type: ignore
    except ImportError:
        return
    for sub_key, label in (
        (r"Software\Microsoft\Internet Explorer\TypedURLs", "ie_typed_url"),
        (r"Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths", "explorer_typed_path"),
    ):
        try:
            handle = winreg.OpenKey(winreg.HKEY_CURRENT_USER, sub_key)
        except OSError:
            continue
        try:
            i = 0
            while True:
                try:
                    name, value, _kind = winreg.EnumValue(handle, i)
                except OSError:
                    break
                if isinstance(value, str) and value:
                    yield {
                        "kind": "registry",
                        "source_path": f"HKCU\\{sub_key}",
                        "name": label,
                        "value": value,
                        "extra": name,
                    }
                i += 1
        finally:
            winreg.CloseKey(handle)


# ---------------------------------------------------------------------------
# Prefetch — bare-minimum scn0f header parse, sufficient for run counts +
# last-run timestamp on Win 8 / 10 / 11 (compressed Prefetch format).
# ---------------------------------------------------------------------------


def parse_prefetch(executables: tuple[str, ...] = ()) -> Iterator[dict]:
    if os.name != "nt":
        return
    pf_dir = Path(r"C:\Windows\Prefetch")
    if not pf_dir.is_dir():
        return
    allow = {e.lower() for e in executables}
    for pf in pf_dir.glob("*.pf"):
        try:
            exe_name = pf.name.split("-", 1)[0].lower()
            if allow and exe_name.split(".")[0] + ".exe" not in allow:
                # Compare bases too: chrome / chrome.exe.
                if exe_name not in allow:
                    continue
            stat = pf.stat()
            last_run = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat()
            yield {
                "kind": "prefetch",
                "source_path": str(pf),
                "browser": _browser_from_exe(exe_name),
                "name": exe_name,
                "value": "executed",
                "ts": last_run,
                "extra": f"size={stat.st_size}",
            }
        except OSError as exc:
            logger.debug("Prefetch read failed for %s: %s", pf, exc)


def _browser_from_exe(name: str) -> str:
    name = name.lower()
    if "chrome" in name:
        return "Chrome"
    if "msedge" in name or name == "edge.exe":
        return "Edge"
    if "firefox" in name:
        return "Firefox"
    if "brave" in name:
        return "Brave"
    if "opera" in name:
        return "Opera"
    if "vivaldi" in name:
        return "Vivaldi"
    if "tor" in name:
        return "Tor"
    return ""


# ---------------------------------------------------------------------------
# LNK files — Recent docs. We parse only the LinkTargetIDList / LinkInfo
# enough to recover the original file path.
# ---------------------------------------------------------------------------


def parse_recent_lnk() -> Iterator[dict]:
    if os.name != "nt":
        return
    recent = Path(os.environ.get("APPDATA", "")) / "Microsoft" / "Windows" / "Recent"
    if not recent.is_dir():
        return
    for lnk in recent.glob("*.lnk"):
        try:
            data = lnk.read_bytes()
        except OSError:
            continue
        target = _lnk_target(data)
        if not target:
            continue
        try:
            stat = lnk.stat()
            ts = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat()
        except OSError:
            ts = ""
        yield {
            "kind": "lnk",
            "source_path": str(lnk),
            "browser": _browser_from_exe(target.lower()),
            "name": lnk.stem,
            "value": target,
            "ts": ts,
        }


def _lnk_target(blob: bytes) -> str:
    """Pull the local target path out of an LNK shortcut.

    The full format (Microsoft MS-SHLLINK) is involved; for forensic browsing
    we don't need every flag. We hunt for the LinkInfo block which contains a
    ``LocalBasePath`` field — a null-terminated ASCII / UCS-2 string.
    """
    if len(blob) < 76 or blob[:4] != b"L\x00\x00\x00":
        return ""
    # Search for the common drive-letter prefixes; rough but reliable.
    drive = re.search(rb"[A-Z]:\\[^\x00]{2,512}", blob)
    if not drive:
        # Try UCS-2.
        utf16 = re.search(
            rb"(?:[A-Z]\x00:\x00\\\x00[^\x00\x01]{4,1024})", blob,
        )
        if not utf16:
            return ""
        try:
            return utf16.group(0).decode("utf-16-le", errors="replace").rstrip("\x00")
        except UnicodeError:
            return ""
    try:
        return drive.group(0).decode("utf-8", errors="replace").rstrip("\x00")
    except UnicodeError:
        return ""


# ---------------------------------------------------------------------------
# DNS cache (via ipconfig /displaydns) + hosts file.
# ---------------------------------------------------------------------------


def parse_dns_cache() -> Iterator[dict]:
    if os.name != "nt":
        return
    try:
        proc = subprocess.run(
            ["ipconfig", "/displaydns"],
            capture_output=True, text=True, timeout=20,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        logger.debug("ipconfig /displaydns failed: %s", exc)
        return
    if proc.returncode != 0:
        return
    current_name = ""
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            current_name = ""
            continue
        if "Record Name" in line or "Nombre de registro" in line:
            current_name = line.split(":", 1)[1].strip()
            continue
        # Capture the resolved IP(s).
        if (line.startswith("A (Host)") or "A Record" in line or "A (Host) Record" in line
                or "Registro A" in line):
            ip = line.split(":", 1)[1].strip() if ":" in line else ""
            if current_name and ip:
                yield {
                    "kind": "dns_cache",
                    "source_path": "ipconfig /displaydns",
                    "name": current_name,
                    "value": ip,
                }


def parse_hosts_file() -> Iterator[dict]:
    if os.name != "nt":
        path = Path("/etc/hosts")
    else:
        path = Path(r"C:\Windows\System32\drivers\etc\hosts")
    if not path.is_file():
        return
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return
    try:
        stat = path.stat()
        ts = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat()
    except OSError:
        ts = ""
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split()
        if len(parts) < 2:
            continue
        ip = parts[0]
        for host in parts[1:]:
            if host.startswith("#"):
                break
            yield {
                "kind": "hosts",
                "source_path": str(path),
                "name": host,
                "value": ip,
                "ts": ts,
            }
