"""Confirmation dialog shown after a recursive folder scan.

Listing every discovered profile with a checkbox lets the analyst pick
exactly which ones to extract. The dialog also classifies each profile
as a primary user profile or an embedded WebView2 / CEF profile (the
sort that lives inside third-party apps like Zoom, Teams, NVIDIA App).
Embedded profiles can still hold forensic evidence — tokens, cookies
from the embedded auth flow — so we offer them, just not by default.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
)

from browsers.base import BrowserProfile
from ui.i18n import tr


# Heuristics that mark a profile path as "embedded inside another app".
# These are not browser installs — they are CEF / WebView2 instances
# Office, Zoom, NVIDIA, OneDrive etc. carry to host their auth UIs.
_EMBEDDED_MARKERS = (
    "EBWebView", "CefCache", "WebView2", "WV2Profile",
    "EdgeBrowserControl", "EdgeWebView",
)


def _is_embedded(profile: BrowserProfile) -> bool:
    path = str(profile.path).replace("\\", "/")
    return any(marker in path for marker in _EMBEDDED_MARKERS)


class FolderScanResultDialog(QDialog):
    """Lets the analyst review and filter profiles found in a folder scan."""

    def __init__(self, profiles: list[BrowserProfile], folder: str, parent=None) -> None:
        super().__init__(parent)
        self._profiles = profiles
        self._folder = folder
        self._selected: list[BrowserProfile] = []
        self.setWindowTitle(tr("Folder scan results"))
        self.resize(820, 520)
        self._build_ui()

    @property
    def selected_profiles(self) -> list[BrowserProfile]:
        return list(self._selected)

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)

        primary = [p for p in self._profiles if not _is_embedded(p)]
        embedded = [p for p in self._profiles if _is_embedded(p)]

        header = QLabel(tr(
            "Found {total} profile(s) under {folder}\n"
            "  • {primary} primary browser profile(s)\n"
            "  • {embedded} embedded WebView2 / CEF profile(s) (apps with built-in browsers)\n\n"
            "Tick the profiles you want to extract. Embedded profiles can hold "
            "tokens, cookies and history from the host app's auth flows."
        ).format(
            total=len(self._profiles),
            folder=self._folder,
            primary=len(primary),
            embedded=len(embedded),
        ))
        header.setWordWrap(True)
        layout.addWidget(header)

        # Quick-select buttons.
        button_row = QHBoxLayout()
        for label, action in (
            (tr("Select all"), self._select_all),
            (tr("Primary only"), self._select_primary_only),
            (tr("Select none"), self._select_none),
        ):
            btn = QPushButton(label)
            btn.clicked.connect(action)
            button_row.addWidget(btn)
        button_row.addStretch(1)
        layout.addLayout(button_row)

        # Tree: group by browser, then by category.
        self._tree = QTreeWidget()
        self._tree.setHeaderLabels([tr("Profile"), tr("Path")])
        self._tree.setColumnWidth(0, 280)
        self._tree.setRootIsDecorated(True)
        self._tree.setAlternatingRowColors(True)
        layout.addWidget(self._tree, 1)

        self._items: list[tuple[QTreeWidgetItem, BrowserProfile]] = []
        # Group by category first, then by browser.
        for category, bucket, default_checked in (
            (tr("Primary browsers"), primary, True),
            (tr("Embedded WebView / CEF profiles"), embedded, False),
        ):
            if not bucket:
                continue
            cat_node = QTreeWidgetItem(self._tree, [category, ""])
            font = cat_node.font(0)
            font.setBold(True)
            cat_node.setFont(0, font)
            cat_node.setExpanded(True)
            # Group by browser within the category.
            by_browser: dict[str, list[BrowserProfile]] = {}
            for p in bucket:
                by_browser.setdefault(p.browser, []).append(p)
            for browser in sorted(by_browser):
                browser_node = QTreeWidgetItem(cat_node, [browser, ""])
                browser_node.setExpanded(True)
                for prof in by_browser[browser]:
                    item = QTreeWidgetItem(browser_node, [prof.name, str(prof.path)])
                    item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
                    item.setCheckState(0, Qt.Checked if default_checked else Qt.Unchecked)
                    self._items.append((item, prof))

        # Bottom: OK/Cancel.
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self._on_accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _set_all_check(self, predicate) -> None:
        for item, profile in self._items:
            item.setCheckState(0, Qt.Checked if predicate(profile) else Qt.Unchecked)

    def _select_all(self) -> None:
        self._set_all_check(lambda _p: True)

    def _select_primary_only(self) -> None:
        self._set_all_check(lambda p: not _is_embedded(p))

    def _select_none(self) -> None:
        self._set_all_check(lambda _p: False)

    def _on_accept(self) -> None:
        self._selected = [p for item, p in self._items if item.checkState(0) == Qt.Checked]
        self.accept()
