"""Opera (stable) — Chromium with an unusual single-profile layout.

Unlike Chrome/Edge, Opera puts all artifacts directly inside the user-data
directory (``Opera Stable``) instead of a ``Default`` subfolder. We override
``discover_profiles`` to treat each user-data dir itself as the profile.
"""

from __future__ import annotations

from pathlib import Path
from typing import List

from browsers.base import BrowserProfile
from browsers.chromium import ChromiumBrowser
from utils.paths import is_chromium_profile_dir, opera_user_data_dirs


class OperaBrowser(ChromiumBrowser):
    name = "Opera"

    def user_data_dirs(self) -> List[Path]:
        return opera_user_data_dirs()

    def discover_profiles(self) -> list[BrowserProfile]:
        out: list[BrowserProfile] = []
        for user_data in self.user_data_dirs():
            if is_chromium_profile_dir(user_data):
                out.append(BrowserProfile(self.name, user_data.name, user_data))
        return out
