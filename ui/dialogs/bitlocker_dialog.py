"""Prompt the analyst for BitLocker unlock credentials.

Shown automatically when :func:`forensics.probe_image` reports at least
one BitLocker-encrypted partition in the image being opened. The user
can supply any combination of:

* a user/login password,
* the 48-digit recovery key (with or without dashes),
* a startup key file (``.bek``),
* a pre-extracted full volume encryption key (hex).

We hand the populated :class:`BitLockerCredentials` to the extractor;
``libbde`` tries each form in turn until one unlocks the volume.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from PyQt5.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
)

from forensics import BitLockerCredentials, BitLockerPartition
from ui.i18n import tr


class BitLockerCredentialsDialog(QDialog):
    """Modal dialog for supplying BitLocker unlock credentials."""

    def __init__(
        self,
        partitions: list[BitLockerPartition],
        parent=None,
    ) -> None:
        super().__init__(parent)
        self._partitions = partitions
        self._credentials: Optional[BitLockerCredentials] = None
        self.setWindowTitle(tr("BitLocker partition detected"))
        self.resize(560, 360)
        self._build_ui()

    @property
    def credentials(self) -> Optional[BitLockerCredentials]:
        return self._credentials

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)

        layout.addWidget(QLabel(
            tr("One or more partitions in this image are encrypted with BitLocker. "
               "Supply at least one credential below to unlock them.")
        ))

        # Partition list (informational).
        for part in self._partitions:
            size_gb = part.byte_length / (1024 ** 3)
            layout.addWidget(QLabel(
                f"  • {part.description or 'partition'}  —  "
                f"{size_gb:.1f} GiB  (addr={part.addr}, offset=0x{part.byte_offset:x})"
            ))

        form = QFormLayout()
        layout.addLayout(form)

        self._password_input = QLineEdit()
        self._password_input.setEchoMode(QLineEdit.Password)
        self._password_input.setPlaceholderText(tr("User/login password"))
        form.addRow(tr("Password:"), self._password_input)

        self._recovery_input = QLineEdit()
        self._recovery_input.setPlaceholderText(
            tr("48-digit recovery key (with or without dashes)")
        )
        form.addRow(tr("Recovery key:"), self._recovery_input)

        bek_row = QHBoxLayout()
        self._bek_input = QLineEdit()
        self._bek_input.setReadOnly(True)
        self._bek_input.setPlaceholderText(tr("Path to a .bek startup key file"))
        bek_row.addWidget(self._bek_input, 1)
        browse = QPushButton(tr("Browse…"))
        browse.clicked.connect(self._browse_bek)
        bek_row.addWidget(browse)
        form.addRow(tr("Startup key:"), bek_row)

        self._fvek_input = QLineEdit()
        self._fvek_input.setPlaceholderText(
            tr("Full volume encryption key (hex, optional)")
        )
        form.addRow(tr("FVEK (hex):"), self._fvek_input)

        # OK/Cancel/Skip — Skip lets the analyst proceed without unlocking
        # (e.g., they only care about the recovery partition).
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        skip = QPushButton(tr("Skip BitLocker"))
        skip.setToolTip(tr("Continue without unlocking — only readable partitions will be scanned."))
        skip.clicked.connect(self._skip)
        buttons.addButton(skip, QDialogButtonBox.ActionRole)
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _browse_bek(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, tr("Select BitLocker startup key (.bek)"),
            "", "Startup key (*.bek);;All files (*.*)",
        )
        if path:
            self._bek_input.setText(path)

    def _accept(self) -> None:
        creds = BitLockerCredentials(
            password=self._password_input.text().strip() or None,
            recovery_password=self._recovery_input.text().strip() or None,
            startup_key_path=(Path(self._bek_input.text()) if self._bek_input.text() else None),
            full_volume_key_hex=self._fvek_input.text().strip() or None,
        )
        if creds.is_empty():
            # Treat empty as "skip" so the dialog isn't a dead-end.
            self._credentials = None
        else:
            self._credentials = creds
        self.accept()

    def _skip(self) -> None:
        self._credentials = None
        self.accept()
