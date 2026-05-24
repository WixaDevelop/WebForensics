"""Findings tab — anti-forensics analyser output.

Pure read-only view of the ``findings`` table with a Run button to (re)run the
analysers. The model is a ``QSqlQueryModel`` that joins to profiles for the
human-readable browser/profile names; the colour decorator highlights severity.
"""

from __future__ import annotations

from typing import Optional

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QBrush, QColor
from PyQt5.QtSql import QSqlDatabase, QSqlQuery, QSqlQueryModel
from PyQt5.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from data.store import SessionStore
from forensics.anti_forensics import run_all


_SEVERITY_COLORS = {
    "info":     QColor("#e0f2fe"),
    "low":      QColor("#dcfce7"),
    "medium":   QColor("#fef3c7"),
    "high":     QColor("#fee2e2"),
    "critical": QColor("#fecaca"),
}


class _FindingsModel(QSqlQueryModel):
    """Adds severity-based row background."""

    def data(self, index, role=Qt.DisplayRole):  # type: ignore[override]
        if role == Qt.BackgroundRole:
            severity_index = self._severity_col()
            if severity_index >= 0:
                sev = str(super().data(self.index(index.row(), severity_index),
                                       Qt.DisplayRole) or "").lower()
                if sev in _SEVERITY_COLORS:
                    return QBrush(_SEVERITY_COLORS[sev])
        return super().data(index, role)

    def _severity_col(self) -> int:
        for i in range(self.columnCount()):
            if self.headerData(i, Qt.Horizontal) == "Severity":
                return i
        return -1


class FindingsView(QWidget):
    """Findings tab with a run button."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._store: Optional[SessionStore] = None
        self._db: Optional[QSqlDatabase] = None
        self._model: Optional[_FindingsModel] = None
        self._build_ui()

    def _build_ui(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(8, 8, 8, 8)

        row = QHBoxLayout()
        self._header = QLabel("<b>Anti-forensics findings</b>")
        row.addWidget(self._header)
        row.addStretch(1)
        run = QPushButton("Run analysers")
        run.clicked.connect(self._run)
        row.addWidget(run)
        outer.addLayout(row)

        info = QLabel(
            "<small>Heuristic checks: timeline gaps, history wipes, orphan cookies, "
            "carved-only hosts, future-dated events. Re-run any time after loading "
            "new profiles.</small>"
        )
        info.setStyleSheet("color: #555;")
        info.setWordWrap(True)
        outer.addWidget(info)

        self._view = QTableView()
        self._view.setSortingEnabled(False)
        self._view.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._view.setAlternatingRowColors(True)
        self._view.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self._view.horizontalHeader().setStretchLastSection(True)
        self._view.verticalHeader().setVisible(False)
        self._view.setWordWrap(True)
        outer.addWidget(self._view, 1)

        self._counter = QLabel("0 findings — click Run analysers to scan.")
        self._counter.setStyleSheet("color: #666;")
        outer.addWidget(self._counter)

    # --- Public API -------------------------------------------------------

    def attach(self, store: SessionStore) -> None:
        self._store = store
        if self._db is not None:
            QSqlDatabase.removeDatabase(self._db.connectionName())
        name = f"wfs_findings_{id(self)}"
        db = QSqlDatabase.addDatabase("QSQLITE", name)
        db.setDatabaseName(str(store.path))
        if not db.open():
            raise RuntimeError(f"Cannot open findings DB: {db.lastError().text()}")
        QSqlQuery("PRAGMA query_only = ON", db)
        self._db = db

        self._model = _FindingsModel(self)
        self._view.setModel(self._model)
        self._refresh()

    def refresh(self) -> None:
        self._refresh()

    # --- Internal ---------------------------------------------------------

    def _run(self) -> None:
        if self._store is None:
            return
        try:
            count = run_all(self._store)
        except Exception as exc:  # noqa: BLE001
            from PyQt5.QtWidgets import QMessageBox
            QMessageBox.critical(self, "Analyser failed", str(exc))
            return
        # The query connection is read-only — issue a checkpoint to publish writes.
        self._store.connection().execute("PRAGMA wal_checkpoint(PASSIVE)")
        self._refresh()
        self._counter.setText(
            f"{count} new finding{'s' if count != 1 else ''} from this run."
        )

    def _refresh(self) -> None:
        if self._model is None or self._db is None:
            return
        sql = (
            "SELECT f.ts AS Timestamp, f.severity AS Severity, f.category AS Category, "
            "       f.title AS Finding, f.detail AS Detail, "
            "       COALESCE(p.browser || ' / ' || p.name, '(global)') AS Profile "
            "FROM findings f LEFT JOIN profiles p ON p.id = f.profile_id "
            "ORDER BY CASE f.severity "
            "  WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 "
            "  WHEN 'low' THEN 3 ELSE 4 END, f.ts DESC"
        )
        query = QSqlQuery(self._db)
        query.exec_(sql)
        self._model.setQuery(query)
        while self._model.canFetchMore():
            self._model.fetchMore()
        total = self._model.rowCount()
        if total:
            self._counter.setText(f"{total} finding{'s' if total != 1 else ''}.")
        else:
            self._counter.setText("No findings (yet) — Run analysers to scan.")
        self._view.resizeColumnsToContents()
        # Keep the Detail column wide.
        for col in range(self._model.columnCount() - 1):
            width = self._view.columnWidth(col)
            self._view.setColumnWidth(col, min(width, 280))
