"""Profile selection dialog.

Two ways to pick a profile:

1.  Pick from the list of auto-detected profiles in default OS locations.
2.  Click "Open folder…" to point at any directory (useful for forensic
    images mounted on another path).
"""

from __future__ import annotations

from pathlib import Path

from PyQt5.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
)

from browsers.base import BrowserProfile
from controller import ForensicsController


class ProfileDialog(QDialog):
    """Lets the user choose one or more profiles to analyse."""

    def __init__(self, controller: ForensicsController, parent=None) -> None:
        super().__init__(parent)
        self._controller = controller
        self._selected: list[BrowserProfile] = []
        self.setWindowTitle("Open profile")
        self.resize(560, 420)
        self._build_ui()
        self._populate()

    @property
    def selected_profiles(self) -> list[BrowserProfile]:
        return list(self._selected)

    # --- UI ---------------------------------------------------------------

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Detected profiles on this system:"))

        self._list = QListWidget()
        self._list.setSelectionMode(QListWidget.ExtendedSelection)
        layout.addWidget(self._list, 1)

        manual_row = QHBoxLayout()
        manual_row.addWidget(QLabel("Or analyse an external profile folder:"))
        self._browse_btn = QPushButton("Open folder…")
        self._browse_btn.clicked.connect(self._browse_folder)
        manual_row.addWidget(self._browse_btn)
        manual_row.addStretch(1)
        layout.addLayout(manual_row)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self._on_accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self._buttons = buttons

    def _populate(self) -> None:
        profiles = self._controller.discover_profiles()
        if not profiles:
            placeholder = QListWidgetItem("No profiles auto-detected — use 'Open folder…'")
            placeholder.setFlags(placeholder.flags() & ~0x1)  # disable selection
            self._list.addItem(placeholder)
            self._buttons.button(QDialogButtonBox.Ok).setEnabled(False)
            return
        for profile in profiles:
            item = QListWidgetItem(f"{profile.browser}  —  {profile.name}   ({profile.path})")
            item.setData(0x0100, profile)  # Qt.UserRole == 0x0100
            self._list.addItem(item)
        self._list.setCurrentRow(0)

    # --- Slots ------------------------------------------------------------

    def _browse_folder(self) -> None:
        folder = QFileDialog.getExistingDirectory(self, "Select browser profile folder")
        if not folder:
            return
        profile = self._controller.identify_profile(Path(folder))
        if profile is None:
            QMessageBox.warning(
                self,
                "Not a recognised profile",
                "The selected folder does not look like a Chrome, Edge or Firefox profile.",
            )
            return
        self._selected = [profile]
        self.accept()

    def _on_accept(self) -> None:
        items = self._list.selectedItems()
        self._selected = [item.data(0x0100) for item in items if item.data(0x0100) is not None]
        if not self._selected:
            QMessageBox.information(self, "No selection", "Please pick at least one profile.")
            return
        self.accept()
