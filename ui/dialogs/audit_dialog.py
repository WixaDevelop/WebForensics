"""Browseable view of the audit log."""

from __future__ import annotations

import json
from typing import Optional

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QLabel,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
)

from utils.audit import AuditLog


class AuditDialog(QDialog):
    """Show the last N audit entries; read-only."""

    def __init__(self, audit: AuditLog, parent: Optional[QDialog] = None) -> None:
        super().__init__(parent)
        self._audit = audit
        self.setWindowTitle("Audit log")
        self.resize(820, 480)
        self._build_ui()
        self._populate()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel(f"<b>Log file:</b> {self._audit.path}"))

        self._tree = QTreeWidget()
        self._tree.setHeaderLabels(["Timestamp (UTC)", "Actor", "Action", "Target", "Extra"])
        self._tree.setColumnWidth(0, 200)
        self._tree.setColumnWidth(1, 110)
        self._tree.setColumnWidth(2, 110)
        self._tree.setColumnWidth(3, 240)
        layout.addWidget(self._tree, 1)

        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(self.reject)
        buttons.accepted.connect(self.accept)
        buttons.button(QDialogButtonBox.Close).clicked.connect(self.accept)
        layout.addWidget(buttons)

    def _populate(self) -> None:
        entries = self._audit.tail(500)
        # Most recent first — easier to spot what just happened.
        for entry in reversed(entries):
            item = QTreeWidgetItem(self._tree, [
                str(entry.get("ts", "")),
                str(entry.get("actor", "")),
                str(entry.get("action", "")),
                str(entry.get("target", "")),
                json.dumps(entry.get("extra", {}), ensure_ascii=False),
            ])
            item.setToolTip(4, item.text(4))
        if self._tree.topLevelItemCount() == 0:
            placeholder = QTreeWidgetItem(self._tree, ["(empty)", "", "", "", ""])
            placeholder.setDisabled(True)
