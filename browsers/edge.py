"""Microsoft Edge (Chromium) — same extractor as Chrome with different paths."""

from __future__ import annotations

from pathlib import Path
from typing import List

from browsers.chromium import ChromiumBrowser
from utils.paths import edge_user_data_dirs


class EdgeBrowser(ChromiumBrowser):
    name = "Edge"

    def user_data_dirs(self) -> List[Path]:
        return edge_user_data_dirs()
