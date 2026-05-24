"""HTML exporter — self-contained report with an executive summary.

Generates a single HTML file with embedded CSS and a minimal JS filter box per
table. No external dependencies required, viewable in any modern browser.
"""

from __future__ import annotations

import html
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from data.models import ARTIFACT_KINDS, ProfileBundle
from exporters.base import ExporterBase


_CSS = """
* { box-sizing: border-box; }
body { font-family: -apple-system, Segoe UI, Roboto, sans-serif;
       margin: 0; background: #f6f8fa; color: #1f2328; }
header { background: #1f2328; color: #fff; padding: 1.5rem 2rem; }
header h1 { margin: 0 0 .25rem; font-size: 1.5rem; }
header .meta { color: #9ca3af; font-size: .85rem; }
main { padding: 2rem; max-width: 1400px; margin: 0 auto; }
.profile { background: #fff; border: 1px solid #d1d9e0; border-radius: 8px;
           padding: 1.5rem; margin-bottom: 1.5rem; }
.profile h2 { margin: 0 0 .5rem; font-size: 1.2rem; }
.summary { display: flex; flex-wrap: wrap; gap: .5rem; margin: .5rem 0 1rem; }
.summary span { background: #eef2f6; border-radius: 999px; padding: .2rem .7rem;
                font-size: .85rem; color: #1f2328; }
details { margin-top: 1rem; border-top: 1px solid #eaeef2; padding-top: 1rem; }
details > summary { cursor: pointer; font-weight: 600; font-size: 1rem; }
.filter { margin: .5rem 0; }
.filter input { padding: .35rem .6rem; border: 1px solid #d1d9e0;
                border-radius: 4px; font-size: .9rem; width: 280px; }
table { width: 100%; border-collapse: collapse; font-size: .85rem; margin-top: .5rem; }
th, td { padding: .4rem .6rem; border-bottom: 1px solid #eaeef2;
         text-align: left; vertical-align: top; word-break: break-word; }
th { background: #f6f8fa; position: sticky; top: 0; }
tbody tr:nth-child(even) { background: #fafbfc; }
tbody tr:hover { background: #fff8c5; }
.errors { color: #cf222e; background: #ffebe9; padding: .5rem .75rem;
          border-radius: 4px; margin-top: .5rem; }
"""

_FILTER_JS = """
function wfFilter(inputId, tableId){
  const q = document.getElementById(inputId).value.toLowerCase();
  const rows = document.getElementById(tableId).tBodies[0].rows;
  for (let i = 0; i < rows.length; i++){
    rows[i].style.display = rows[i].textContent.toLowerCase().includes(q) ? '' : 'none';
  }
}
"""


class HtmlExporter(ExporterBase):
    extension = ".html"

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
            target = target / "webforensics.html"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(self._render(bundles, kinds), encoding="utf-8")
        return target

    # --- Rendering --------------------------------------------------------

    def _render(self, bundles: list[ProfileBundle], kinds: list[str]) -> str:
        parts: list[str] = []
        parts.append("<!doctype html><html lang='en'><head><meta charset='utf-8'>")
        parts.append("<title>WebForensics Report</title>")
        parts.append(f"<style>{_CSS}</style>")
        parts.append(f"<script>{_FILTER_JS}</script>")
        parts.append("</head><body>")
        parts.append(
            "<header><h1>WebForensics Report</h1>"
            f"<div class='meta'>Generated {datetime.now(timezone.utc).isoformat()}"
            f" — {len(bundles)} profile(s)</div></header><main>"
        )
        for idx, bundle in enumerate(bundles):
            parts.append(self._render_profile(idx, bundle, kinds))
        parts.append("</main></body></html>")
        return "".join(parts)

    def _render_profile(self, idx: int, bundle: ProfileBundle, kinds: list[str]) -> str:
        summary = bundle.summary()
        chips = "".join(
            f"<span>{html.escape(k)}: {summary[k]}</span>"
            for k in kinds if summary.get(k)
        )
        out = [
            "<section class='profile'>",
            f"<h2>{html.escape(bundle.browser)} — {html.escape(bundle.profile)}</h2>",
            f"<div class='meta'>{html.escape(bundle.path)}</div>",
            f"<div class='summary'>{chips or '<span>no data</span>'}</div>",
        ]
        if bundle.errors:
            errs = "<br>".join(html.escape(e) for e in bundle.errors)
            out.append(f"<div class='errors'>Errors: {errs}</div>")
        for kind in kinds:
            items = bundle.get(kind)
            if not items:
                continue
            out.append(self._render_table(idx, kind, items))
        out.append("</section>")
        return "".join(out)

    def _render_table(self, idx: int, kind: str, items) -> str:
        rows = [item.to_dict() for item in items]
        # Stable column order: union across rows, in first-seen order.
        columns: list[str] = []
        for row in rows:
            for key in row:
                if key not in columns:
                    columns.append(key)
        table_id = f"t-{idx}-{kind}"
        input_id = f"f-{idx}-{kind}"
        head = "".join(f"<th>{html.escape(c)}</th>" for c in columns)
        body_rows = []
        for row in rows:
            cells = "".join(f"<td>{html.escape(str(row.get(c, '')))}</td>" for c in columns)
            body_rows.append(f"<tr>{cells}</tr>")
        return (
            f"<details open><summary>{html.escape(kind.title())} ({len(rows)})</summary>"
            f"<div class='filter'><input id='{input_id}' placeholder='Filter…' "
            f"oninput=\"wfFilter('{input_id}','{table_id}')\"></div>"
            f"<table id='{table_id}'><thead><tr>{head}</tr></thead>"
            f"<tbody>{''.join(body_rows)}</tbody></table></details>"
        )
