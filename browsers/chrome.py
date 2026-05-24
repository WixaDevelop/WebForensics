"""Google Chrome — thin subclass that only contributes default paths."""

from __future__ import annotations

from pathlib import Path
from typing import List

from browsers.chromium import ChromiumBrowser
from utils.paths import chrome_user_data_dirs


class ChromeBrowser(ChromiumBrowser):
    name = "Chrome"

    def user_data_dirs(self) -> List[Path]:
        return chrome_user_data_dirs()
