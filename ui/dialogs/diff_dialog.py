"""Session-diff dialog.

Lets the user pick two ``.wfs`` files and shows a tree of "what changed".
Useful for monitoring a profile across time or comparing a live extraction
against an earlier forensic image.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from forensics.diff import SessionDiff, compare_wfs


class DiffDialog(QDialog):
    """Pick two ``.wfs`` files, hit Compare, browse the tree of changes."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Compare sessions")
        self.resize(900, 600)
        self._build_ui()

    def _build_ui(self) -> None:
        outer = QVBoxLayout(self)
        outer.addWidget(QLabel(
            "<b>Compare two WebForensics sessions</b><br>"
            "<small>Match rules: history/bookmarks by URL · cookies by host+name · "
            "logins by origin+username · tabs by window+index+url · permissions by origin+kind.</small>"
        ))

        left_row = QHBoxLayout()
        left_row.addWidget(QLabel("Baseline (.wfs):"))
        self._left_edit = QLineEdit()
        left_row.addWidget(self._left_edit, 1)
        left_browse = QPushButton("Browse…")
        left_browse.clicked.connect(lambda: self._pick(self._left_edit))
        left_row.addWidget(left_browse)
        outer.addLayout(left_row)

        right_row = QHBoxLayout()
        right_row.addWidget(QLabel("Newer (.wfs):"))
        self._right_edit = QLineEdit()
        right_row.addWidget(self._right_edit, 1)
        right_browse = QPushButton("Browse…")
        right_browse.clicked.connect(lambda: self._pick(self._right_edit))
        right_row.addWidget(right_browse)
        outer.addLayout(right_row)

        button_row = QHBoxLayout()
        compare = QPushButton("Compare")
        compare.clicked.connect(self._run)
        button_row.addWidget(compare)
        self._summary = QLabel("")
        self._summary.setStyleSheet("color: #444;")
        button_row.addWidget(self._summary, 1)
        outer.addLayout(button_row)

        self._tree = QTreeWidget()
        self._tree.setHeaderLabels(["Change", "Value", "Detail"])
        self._tree.setColumnWidth(0, 220)
        self._tree.setColumnWidth(1, 320)
        outer.addWidget(self._tree, 1)

        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(self.reject)
        outer.addWidget(buttons)

    def _pick(self, edit: QLineEdit) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Choose .wfs file", "", "WebForensics session (*.wfs);;SQLite (*.db *.sqlite)"
        )
        if path:
            edit.setText(path)

    def _run(self) -> None:
        left = self._left_edit.text().strip()
        right = self._right_edit.text().strip()
        if not left or not right:
            QMessageBox.warning(self, "Missing paths", "Pick both files first.")
            return
        try:
            diff = compare_wfs(Path(left), Path(right))
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Diff failed", str(exc))
            return
        self._render(diff)

    def _render(self, diff: SessionDiff) -> None:
        self._tree.clear()
        self._summary.setText(diff.summary)
        for table, td in diff.tables.items():
            if not td.added and not td.removed:
                continue
            top = QTreeWidgetItem(self._tree, [
                table,
                f"+{len(td.added)} added, -{len(td.removed)} removed",
                "",
            ])
            font = top.font(0)
            font.setBold(True)
            top.setFont(0, font)
            for entry in td.added[:200]:
                title = self._title_for(table, entry)
                QTreeWidgetItem(top, ["+ added", title, _short(entry)])
            for entry in td.removed[:200]:
                title = self._title_for(table, entry)
                QTreeWidgetItem(top, ["- removed", title, _short(entry)])
            if len(td.added) > 200 or len(td.removed) > 200:
                QTreeWidgetItem(top, ["…",
                                      f"showing first 200 of each (total +{len(td.added)} -{len(td.removed)})",
                                      ""])
            top.setExpanded(True)
        if self._tree.topLevelItemCount() == 0:
            QTreeWidgetItem(self._tree, ["no changes", "", ""])

    def _title_for(self, table: str, row: dict) -> str:
        if "url" in row and row["url"]:
            return str(row["url"])
        if "origin" in row and row["origin"]:
            return str(row["origin"])
        if "host" in row and row["host"]:
            return f"{row.get('name', '')}@{row['host']}"
        return next((str(v) for v in row.values() if v), "")


def _short(payload: dict) -> str:
    """Compact one-line render of a row dict for the right column."""
    pieces = []
    for k, v in payload.items():
        if v is None or v == "":
            continue
        text = str(v)
        if len(text) > 60:
            text = text[:57] + "…"
        pieces.append(f"{k}={text}")
        if len(pieces) >= 4:
            break
    return " · ".join(pieces)
