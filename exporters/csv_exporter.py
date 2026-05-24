"""CSV exporter — one ``<kind>.csv`` per artifact in the output folder.

The chosen format is multiple files (rather than one merged CSV) because each
artifact kind has its own columns. ``out_path`` is treated as a *directory*.
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Iterable

from data.models import ARTIFACT_KINDS, ProfileBundle
from exporters.base import ExporterBase


class CsvExporter(ExporterBase):
    extension = ""  # output is a directory

    def export(
        self,
        bundles: Iterable[ProfileBundle],
        out_path: str | Path,
        kinds: Iterable[str] = ARTIFACT_KINDS,
    ) -> Path:
        out_dir = Path(out_path)
        out_dir.mkdir(parents=True, exist_ok=True)
        kinds = list(kinds)
        bundles = list(bundles)

        for kind in kinds:
            rows: list[dict] = []
            for bundle in bundles:
                for item in bundle.get(kind):
                    rows.append(item.to_dict())
            file_path = out_dir / f"{kind}.csv"
            if not rows:
                # Still create the file so users see what was requested.
                file_path.write_text("", encoding="utf-8")
                continue
            # Union of keys across all rows preserves order while staying complete.
            fieldnames: list[str] = []
            for row in rows:
                for key in row:
                    if key not in fieldnames:
                        fieldnames.append(key)
            with file_path.open("w", encoding="utf-8", newline="") as fh:
                writer = csv.DictWriter(fh, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(rows)
        return out_dir
