"""Global search dialog: looks for a string across every artifact at once.

Hits are grouped by kind and clicking one drops you onto the matching tab
with the table pre-filtered to the query. Useful for "did this user ever
touch domain X" or "is this username anywhere on disk".
"""

from __future__ import annotations

from typing import Optional

from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSplitter,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from data.store import SessionStore


class GlobalSearchDialog(QDialog):
    """Modeless dialog with a live cross-artifact LIKE search."""

    navigate_requested = pyqtSignal(str, str)  # (kind, query)

    def __init__(self, store: SessionStore, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._store = store
        self.setWindowTitle("Global search")
        self.resize(720, 480)
        self.setWindowFlag(Qt.Window)
        self._build_ui()
        # ``Modeless`` so the user can keep navigating while it's open.
        self.setModal(False)

    # --- UI ---------------------------------------------------------------

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)

        row = QHBoxLayout()
        row.addWidget(QLabel("Search:"))
        self._input = QLineEdit()
        self._input.setPlaceholderText("Type to search across all artifacts…")
        self._input.returnPressed.connect(self._run_search)
        row.addWidget(self._input, 1)
        run = QPushButton("Search")
        run.clicked.connect(self._run_search)
        row.addWidget(run)
        layout.addLayout(row)

        splitter = QSplitter(Qt.Horizontal)
        self._tree = QTreeWidget()
        self._tree.setHeaderLabels(["Match", "Detail"])
        self._tree.setColumnWidth(0, 300)
        self._tree.itemDoubleClicked.connect(self._on_double_click)
        splitter.addWidget(self._tree)
        layout.addWidget(splitter, 1)

        self._summary = QLabel("Type a query and press Enter.")
        self._summary.setStyleSheet("color: #666;")
        layout.addWidget(self._summary)

        hint = QLabel(
            "<i>Double-click a kind row to open that tab with the filter applied.</i>"
        )
        hint.setStyleSheet("color: #888; font-size: 11px;")
        layout.addWidget(hint)

    # --- Slots ------------------------------------------------------------

    def _run_search(self) -> None:
        query = self._input.text().strip()
        self._tree.clear()
        if not query:
            self._summary.setText("Type a query and press Enter.")
            return
        results = self._store.search(query, limit=50)
        total_hits = 0
        for kind, rows in results.items():
            if not rows:
                continue
            total_hits += len(rows)
            group = QTreeWidgetItem(self._tree, [
                f"{kind} ({len(rows)})",
                "double-click to open the tab pre-filtered",
            ])
            group.setData(0, Qt.UserRole, (kind, query))
            font = group.font(0)
            font.setBold(True)
            group.setFont(0, font)
            # Show a preview of the first few matches under each group.
            for row in rows[:10]:
                summary, detail = self._row_preview(kind, row)
                child = QTreeWidgetItem(group, [summary, detail])
                child.setData(0, Qt.UserRole, (kind, query))
            if len(rows) > 10:
                more = QTreeWidgetItem(group, [f"… {len(rows) - 10} more", ""])
                more.setData(0, Qt.UserRole, (kind, query))
            group.setExpanded(True)
        if total_hits == 0:
            self._summary.setText(f"No matches for “{query}”.")
        else:
            self._summary.setText(f"{total_hits} match{'es' if total_hits != 1 else ''} across artifacts.")

    def _row_preview(self, kind: str, row) -> tuple[str, str]:
        """Return ``(summary, detail)`` strings for a hit preview."""
        getr = lambda k: str(row[k]) if k in row.keys() and row[k] is not None else ""
        if kind == "history":
            return getr("title") or getr("url"), getr("url")
        if kind == "cookies":
            return f"{getr('name')} @ {getr('host')}", getr("value")[:120]
        if kind == "downloads":
            return getr("target_path") or getr("url"), getr("url")
        if kind == "logins":
            return f"{getr('username')} @ {getr('origin_url')}", getr("action_url")
        if kind == "bookmarks":
            return getr("name") or getr("url"), getr("url")
        if kind == "autofill":
            return f"{getr('field_name')} = {getr('value')[:80]}", f"count={getr('count')}"
        if kind == "extensions":
            return getr("name") or getr("extension_id"), getr("description")
        return getr("name") or getr("id") or "(no name)", ""

    def _on_double_click(self, item: QTreeWidgetItem, _column: int) -> None:
        payload = item.data(0, Qt.UserRole)
        if not payload:
            return
        kind, query = payload
        self.navigate_requested.emit(kind, query)
