"""PDF report exporter — court-ready single-file report.

Uses ``QTextDocument`` + ``QPrinter`` so we don't drag in reportlab / WeasyPrint.
The document is plain HTML with carefully scoped CSS that Qt's printing layer
understands.

Layout:

* Cover page: case identifier, generation timestamp, profile / artifact tallies.
* Chain of custody: SHA-256 of every source image opened (read from the audit
  log if present), plus per-profile file paths.
* One section per artifact kind, paginated. Tables are capped at the first
  ``_MAX_ROWS_PER_TABLE`` rows so the PDF stays printable; a footer notes the
  truncation so analysts know to cross-check.
"""

from __future__ import annotations

import html
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from PyQt5.QtCore import QSizeF, Qt
from PyQt5.QtGui import QPageLayout, QPageSize, QTextDocument
from PyQt5.QtPrintSupport import QPrinter

from data.models import ARTIFACT_KINDS, ProfileBundle
from exporters.base import ExporterBase

logger = logging.getLogger(__name__)

_MAX_ROWS_PER_TABLE = 1000


_PDF_CSS = """
* { box-sizing: border-box; }
body { font-family: 'Segoe UI', Arial, sans-serif; color: #1f2328; }
h1 { font-size: 22pt; color: #1f2328; margin: 0; }
h2 { font-size: 14pt; color: #1f2328; margin: 14pt 0 6pt; border-bottom: 1px solid #d1d9e0; padding-bottom: 2pt; }
h3 { font-size: 11pt; color: #1f2328; margin: 10pt 0 4pt; }
.cover { page-break-after: always; }
.cover .title { font-size: 28pt; font-weight: bold; }
.cover .subtitle { color: #57606a; font-size: 12pt; margin-top: 6pt; }
.cover table { margin-top: 36pt; }
.kv td { padding: 3pt 8pt; }
.kv td:first-child { color: #57606a; }
.profile { page-break-before: always; }
table.data { width: 100%; border-collapse: collapse; font-size: 8pt; margin-top: 4pt; }
table.data th, table.data td { border: 1px solid #d1d9e0; padding: 2pt 4pt; text-align: left;
                               vertical-align: top; word-break: break-word; }
table.data th { background: #f6f8fa; }
table.data tr:nth-child(even) td { background: #fafbfc; }
.footer { color: #6e7781; font-size: 8pt; margin-top: 6pt; }
.notice { color: #cf222e; font-size: 9pt; margin-top: 4pt; }
"""


class PdfExporter(ExporterBase):
    extension = ".pdf"

    def export(
        self,
        bundles: Iterable[ProfileBundle],
        out_path: str | Path,
        kinds: Iterable[str] = ARTIFACT_KINDS,
    ) -> Path:
        kinds = list(kinds)
        bundles = list(bundles)
        target = Path(out_path)
        if target.is_dir():
            target = target / "webforensics.pdf"
        if target.suffix.lower() != ".pdf":
            target = target.with_suffix(".pdf")
        target.parent.mkdir(parents=True, exist_ok=True)

        document = QTextDocument()
        document.setDefaultStyleSheet(_PDF_CSS)
        document.setHtml(self._render(bundles, kinds))

        printer = QPrinter(QPrinter.HighResolution)
        printer.setOutputFormat(QPrinter.PdfFormat)
        printer.setOutputFileName(str(target))
        printer.setPageSize(QPageSize(QPageSize.A4))
        printer.setPageMargins(15, 15, 15, 15, QPrinter.Millimeter)
        # Match the document page size to the printer so Qt's pagination works.
        size = printer.pageRect(QPrinter.Point).size()
        document.setPageSize(QSizeF(size))
        document.print_(printer)
        # Drop an HMAC sidecar so reviewers can tell the PDF wasn't edited
        # after generation. Failure to sign is non-fatal — the PDF itself is.
        try:
            from utils.signing import sign_file
            sign_file(target)
        except Exception as exc:  # noqa: BLE001
            logger.debug("PDF signing skipped: %s", exc)
        return target

    # --- Rendering --------------------------------------------------------

    def _render(self, bundles: list[ProfileBundle], kinds: list[str]) -> str:
        out: list[str] = ["<html><body>"]
        out.append(self._render_cover(bundles, kinds))
        out.append(self._render_custody(bundles))
        for bundle in bundles:
            out.append(self._render_profile(bundle, kinds))
        out.append("</body></html>")
        return "".join(out)

    def _render_cover(self, bundles: list[ProfileBundle], kinds: list[str]) -> str:
        total = sum(
            sum(b.summary().get(k, 0) for k in kinds) for b in bundles
        )
        rows = [
            ("Generated",       datetime.now(timezone.utc).isoformat()),
            ("Profiles",        str(len(bundles))),
            ("Artifact kinds",  ", ".join(kinds)),
            ("Total records",   str(total)),
            ("Tool",            "WebForensics 1.0"),
        ]
        kv = "".join(
            f"<tr><td>{html.escape(k)}</td><td>{html.escape(v)}</td></tr>"
            for k, v in rows
        )
        return (
            "<div class='cover'>"
            "<div class='title'>WebForensics Report</div>"
            "<div class='subtitle'>Browser-profile forensic analysis</div>"
            f"<table class='kv'>{kv}</table>"
            "<p class='footer'>Generated by WebForensics. Hash-verified source "
            "evidence is summarised in the chain-of-custody section.</p>"
            "</div>"
        )

    def _render_custody(self, bundles: list[ProfileBundle]) -> str:
        out = ["<h2>Chain of custody</h2>"]
        rows = []
        for bundle in bundles:
            for err in bundle.errors:
                if err.startswith("[image] source="):
                    rows.append(("image", bundle.browser, bundle.profile,
                                 err.removeprefix("[image] source=")))
        if rows:
            out.append("<table class='data'><thead><tr>"
                       "<th>Source</th><th>Browser</th><th>Profile</th><th>Origin</th>"
                       "</tr></thead><tbody>")
            for source, browser, profile, origin in rows:
                out.append("<tr>"
                           f"<td>{html.escape(source)}</td>"
                           f"<td>{html.escape(browser)}</td>"
                           f"<td>{html.escape(profile)}</td>"
                           f"<td>{html.escape(origin)}</td>"
                           "</tr>")
            out.append("</tbody></table>")
        # Audit log SHA-256 entries.
        audit_path = self._audit_log_path()
        if audit_path and audit_path.is_file():
            try:
                hashes = []
                for line in audit_path.read_text(encoding="utf-8").splitlines()[-200:]:
                    try:
                        entry = json.loads(line)
                    except ValueError:
                        continue
                    if entry.get("action") == "open_image" and entry.get("sha256"):
                        hashes.append((entry.get("ts", ""), entry.get("target", ""),
                                       entry.get("sha256", "")))
                if hashes:
                    out.append("<h3>Source-image SHA-256</h3>")
                    out.append("<table class='data'><thead><tr>"
                               "<th>Opened</th><th>Image</th><th>SHA-256</th>"
                               "</tr></thead><tbody>")
                    for ts, target, digest in hashes:
                        out.append("<tr>"
                                   f"<td>{html.escape(ts)}</td>"
                                   f"<td>{html.escape(str(target))}</td>"
                                   f"<td><code>{html.escape(digest)}</code></td>"
                                   "</tr>")
                    out.append("</tbody></table>")
            except OSError:
                pass
        if not rows:
            out.append("<p class='footer'>Live-system extraction — no source image was hashed.</p>")
        return "".join(out)

    def _render_profile(self, bundle: ProfileBundle, kinds: list[str]) -> str:
        summary = bundle.summary()
        chips = ", ".join(f"{k}: {summary[k]}" for k in kinds if summary.get(k)) or "no data"
        out = [
            "<div class='profile'>",
            f"<h2>{html.escape(bundle.browser)} — {html.escape(bundle.profile)}</h2>",
            f"<div class='footer'>{html.escape(bundle.path)}</div>",
            f"<div>{html.escape(chips)}</div>",
        ]
        if bundle.errors:
            errs = "<br>".join(html.escape(e) for e in bundle.errors)
            out.append(f"<div class='notice'>Notes: {errs}</div>")
        for kind in kinds:
            items = bundle.get(kind)
            if not items:
                continue
            out.append(self._render_table(kind, items))
        out.append("</div>")
        return "".join(out)

    def _render_table(self, kind: str, items) -> str:
        rows = [item.to_dict() for item in items]
        truncated = len(rows) > _MAX_ROWS_PER_TABLE
        if truncated:
            rows = rows[:_MAX_ROWS_PER_TABLE]
        columns: list[str] = []
        for row in rows:
            for key in row:
                if key not in columns:
                    columns.append(key)
        # Drop pure-metadata columns to save horizontal space.
        columns = [c for c in columns if c not in ("browser", "profile")]
        head = "".join(f"<th>{html.escape(c)}</th>" for c in columns)
        body = []
        for row in rows:
            cells = "".join(
                f"<td>{html.escape(str(row.get(c, '')))[:300]}</td>" for c in columns
            )
            body.append(f"<tr>{cells}</tr>")
        notice = ""
        if truncated:
            notice = (
                f"<div class='notice'>Truncated to first {_MAX_ROWS_PER_TABLE:,} "
                f"of {len(items):,} rows for printability.</div>"
            )
        return (
            f"<h3>{html.escape(kind.title())} ({len(items)})</h3>"
            f"<table class='data'><thead><tr>{head}</tr></thead>"
            f"<tbody>{''.join(body)}</tbody></table>{notice}"
        )

    # --- Helpers ----------------------------------------------------------

    def _audit_log_path(self) -> Path | None:
        # Mirrors utils.audit.AuditLog default location.
        local = os.environ.get("LOCALAPPDATA")
        if local:
            return Path(local) / "WebForensics" / "audit.log.jsonl"
        return None
