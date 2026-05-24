"""Opera GX — same single-profile layout as Opera, different path."""

from __future__ import annotations

from pathlib import Path
from typing import List

from browsers.base import BrowserProfile
from browsers.chromium import ChromiumBrowser
from utils.paths import is_chromium_profile_dir, opera_gx_user_data_dirs


class OperaGXBrowser(ChromiumBrowser):
    name = "Opera GX"

    def user_data_dirs(self) -> List[Path]:
        return opera_gx_user_data_dirs()

    def discover_profiles(self) -> list[BrowserProfile]:
        out: list[BrowserProfile] = []
        for user_data in self.user_data_dirs():
            if is_chromium_profile_dir(user_data):
                out.append(BrowserProfile(self.name, user_data.name, user_data))
        return out
