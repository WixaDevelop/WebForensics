"""JSON exporter — single document with one section per profile.

The document layout is::

    {
      "generated_at": "...",
      "profiles": [
        {
          "browser": "...",
          "profile": "...",
          "path": "...",
          "summary": { "history": N, ... },
          "errors": [...],
          "history": [...], "cookies": [...], ...
        }
      ]
    }
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from data.models import ARTIFACT_KINDS, ProfileBundle
from exporters.base import ExporterBase


class JsonExporter(ExporterBase):
    extension = ".json"

    def export(
        self,
        bundles: Iterable[ProfileBundle],
        out_path: str | Path,
        kinds: Iterable[str] = ARTIFACT_KINDS,
    ) -> Path:
        kinds = list(kinds)
        bundles = list(bundles)
        doc = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "profiles": [self._profile_dict(b, kinds) for b in bundles],
        }
        target = Path(out_path)
        if target.is_dir():
            target = target / "webforensics.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(doc, indent=2, ensure_ascii=False), encoding="utf-8")
        return target

    def _profile_dict(self, bundle: ProfileBundle, kinds: list[str]) -> dict:
        data: dict = {
            "browser": bundle.browser,
            "profile": bundle.profile,
            "path": bundle.path,
            "summary": bundle.summary(),
            "errors": bundle.errors,
        }
        for kind in kinds:
            data[kind] = [item.to_dict() for item in bundle.get(kind)]
        return data
