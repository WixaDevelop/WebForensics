"""IOC management dialog.

Three jobs:

1.  Show the IOC list currently loaded into the session.
2.  Let the analyst load a CSV / JSON / text file of new IOCs.
3.  Trigger a re-match across the current artifacts.

Matching runs synchronously on the session connection — it's cheap because
every match is a substring LIKE against the indexed artifact tables.
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
    QMessageBox,
    QPushButton,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from data.store import SessionStore
from forensics.ioc import load_iocs_from_path, match_all


class IOCDialog(QDialog):
    """Lists IOCs and runs match / load / clear actions on the store."""

    def __init__(self, store: SessionStore, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._store = store
        self.setWindowTitle("IOC matching")
        self.resize(720, 520)
        self._build_ui()
        self._reload()

    # --- UI ---------------------------------------------------------------

    def _build_ui(self) -> None:
        outer = QVBoxLayout(self)

        outer.addWidget(QLabel(
            "<b>Indicators of Compromise</b><br>"
            "<small>Load a CSV/JSON/text feed and match it across history, "
            "cookies, downloads, logins and bookmarks.</small>"
        ))

        button_row = QHBoxLayout()
        load = QPushButton("Load file…")
        load.clicked.connect(self._load_file)
        button_row.addWidget(load)
        match = QPushButton("Match now")
        match.clicked.connect(self._match_now)
        button_row.addWidget(match)
        clear = QPushButton("Clear all")
        clear.clicked.connect(self._clear)
        button_row.addWidget(clear)
        button_row.addStretch(1)
        self._summary = QLabel("0 IOCs loaded.")
        self._summary.setStyleSheet("color: #444;")
        button_row.addWidget(self._summary)
        outer.addLayout(button_row)

        self._tree = QTreeWidget()
        self._tree.setHeaderLabels(["Value", "Kind", "Severity", "Source", "Hits"])
        self._tree.setRootIsDecorated(False)
        self._tree.setAlternatingRowColors(True)
        outer.addWidget(self._tree, 1)

        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(self.reject)
        outer.addWidget(buttons)

    # --- Actions ----------------------------------------------------------

    def _load_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Load IOC file",
            "",
            "IOC feeds (*.csv *.json *.txt *.ioc);;All files (*.*)",
        )
        if not path:
            return
        try:
            iocs = load_iocs_from_path(path)
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Load failed", str(exc))
            return
        if not iocs:
            QMessageBox.information(self, "No IOCs", f"No usable entries in {Path(path).name}.")
            return
        inserted = self._store.upsert_iocs(iocs)
        QMessageBox.information(
            self,
            "Loaded",
            f"{inserted} new IOC{'s' if inserted != 1 else ''} loaded (of {len(iocs)} in file). "
            "Click 'Match now' to scan the current artifacts.",
        )
        self._reload()

    def _match_now(self) -> None:
        try:
            hits = match_all(self._store.connection())
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Match failed", str(exc))
            return
        QMessageBox.information(
            self,
            "Matching done",
            f"{hits} hit{'s' if hits != 1 else ''} across artifacts. "
            "Flagged rows show up with a coloured 'IOC' decoration in their tables.",
        )
        self._reload()

    def _clear(self) -> None:
        confirm = QMessageBox.question(
            self,
            "Confirm",
            "Remove every IOC and its hits from this session?",
        )
        if confirm != QMessageBox.Yes:
            return
        self._store.clear_iocs()
        self._reload()

    # --- Population -------------------------------------------------------

    def _reload(self) -> None:
        self._tree.clear()
        conn = self._store.connection()
        iocs = list(conn.execute(
            "SELECT i.id, i.value, i.kind, i.severity, i.source, "
            "       (SELECT COUNT(*) FROM ioc_hits h WHERE h.ioc_id = i.id) AS hits "
            "FROM iocs i ORDER BY hits DESC, i.kind, i.value"
        ))
        for row in iocs:
            item = QTreeWidgetItem(self._tree, [
                str(row["value"]),
                str(row["kind"]),
                str(row["severity"]),
                str(row["source"] or ""),
                str(row["hits"] or 0),
            ])
            item.setData(0, Qt.UserRole, int(row["id"]))
            if int(row["hits"] or 0) > 0:
                font = item.font(0)
                font.setBold(True)
                item.setFont(0, font)
        total_hits = sum(int(row["hits"] or 0) for row in iocs)
        self._summary.setText(
            f"{len(iocs)} IOC{'s' if len(iocs) != 1 else ''} loaded · "
            f"{total_hits} hit{'s' if total_hits != 1 else ''}"
        )
