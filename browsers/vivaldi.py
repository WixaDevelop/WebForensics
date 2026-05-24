"""Vivaldi Browser — standard Chromium User Data layout."""

from __future__ import annotations

from pathlib import Path
from typing import List

from browsers.chromium import ChromiumBrowser
from utils.paths import vivaldi_user_data_dirs


class VivaldiBrowser(ChromiumBrowser):
    name = "Vivaldi"

    def user_data_dirs(self) -> List[Path]:
        return vivaldi_user_data_dirs()
