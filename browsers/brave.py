"""Brave Browser — Chromium fork with its own user-data root."""

from __future__ import annotations

from pathlib import Path
from typing import List

from browsers.chromium import ChromiumBrowser
from utils.paths import brave_user_data_dirs


class BraveBrowser(ChromiumBrowser):
    name = "Brave"

    def user_data_dirs(self) -> List[Path]:
        return brave_user_data_dirs()
