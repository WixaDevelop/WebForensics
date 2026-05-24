"""Chronological cross-artifact timeline.

Renders the ``events`` table — populated automatically by INSERT triggers on
every artifact table — sorted by timestamp. Lets the analyst answer "what
happened on this machine in time order" without flipping between tabs.

Includes:

* Kind filter (multi-checkbox) so the user can isolate, say, "logins only".
* Date-range filter (from / to).
* Per-row colour swatch derived from the kind, so eyes can track patterns.
"""

from __future__ import annotations

from typing import Optional

from PyQt5.QtCore import QDate, Qt
from PyQt5.QtGui import QColor
from PyQt5.QtSql import QSqlDatabase, QSqlQuery, QSqlQueryModel
from PyQt5.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QDateEdit,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from data.store import SessionStore


_KIND_COLOURS = {
    "history": "#2563eb",
    "download": "#a16207",
    "login": "#dc2626",
    "bookmark": "#16a34a",
    "cookie": "#7c3aed",
    "autofill": "#0891b2",
}
_ALL_KINDS = tuple(_KIND_COLOURS.keys())


class _TimelineModel(QSqlQueryModel):
    """Adds a coloured cell decorator on the ``kind`` column."""

    def data(self, index, role=Qt.DisplayRole):  # type: ignore[override]
        if role == Qt.DecorationRole and index.column() == self._kind_col:
            kind = super().data(self.index(index.row(), self._kind_col), Qt.DisplayRole)
            if kind in _KIND_COLOURS:
                return QColor(_KIND_COLOURS[str(kind)])
        return super().data(index, role)

    def setColumns(self, kind_col: int) -> None:
        self._kind_col = kind_col


class TimelineView(QWidget):
    """Cross-artifact event timeline reading from a ``SessionStore``."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._store: Optional[SessionStore] = None
        self._db: Optional[QSqlDatabase] = None
        self._model: Optional[_TimelineModel] = None
        self._kind_boxes: dict[str, QCheckBox] = {}
        self._build_ui()

    # --- UI ---------------------------------------------------------------

    def _build_ui(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(8, 8, 8, 8)

        controls = QHBoxLayout()
        controls.addWidget(QLabel("Kinds:"))
        for kind in _ALL_KINDS:
            box = QCheckBox(kind)
            box.setChecked(True)
            box.stateChanged.connect(self._refresh)
            self._kind_boxes[kind] = box
            controls.addWidget(box)

        controls.addSpacing(12)
        controls.addWidget(QLabel("From:"))
        self._from = QDateEdit(calendarPopup=True)
        self._from.setDate(QDate.currentDate().addYears(-2))
        self._from.dateChanged.connect(self._refresh)
        controls.addWidget(self._from)
        controls.addWidget(QLabel("To:"))
        self._to = QDateEdit(calendarPopup=True)
        self._to.setDate(QDate.currentDate())
        self._to.dateChanged.connect(self._refresh)
        controls.addWidget(self._to)

        controls.addSpacing(12)
        self._search = QLineEdit()
        self._search.setPlaceholderText("Search summary / detail…")
        self._search.textChanged.connect(self._refresh)
        controls.addWidget(self._search, 1)
        reset = QPushButton("Reset")
        reset.clicked.connect(self._reset_filters)
        controls.addWidget(reset)
        outer.addLayout(controls)

        # Subtle divider keeps the controls visually anchored.
        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setFrameShadow(QFrame.Sunken)
        outer.addWidget(line)

        self._view = QTableView()
        self._view.setSortingEnabled(False)  # already sorted by query
        self._view.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._view.setAlternatingRowColors(True)
        self._view.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self._view.horizontalHeader().setStretchLastSection(True)
        self._view.verticalHeader().setVisible(False)
        outer.addWidget(self._view)

        self._counter = QLabel("0 events")
        self._counter.setStyleSheet("color: #666;")
        outer.addWidget(self._counter)

    # --- Public API -------------------------------------------------------

    def attach(self, store: SessionStore) -> None:
        self._store = store
        if self._db is not None:
            QSqlDatabase.removeDatabase(self._db.connectionName())
        name = f"wfs_timeline_{id(self)}"
        db = QSqlDatabase.addDatabase("QSQLITE", name)
        db.setDatabaseName(str(store.path))
        if not db.open():
            raise RuntimeError(f"Cannot open timeline DB: {db.lastError().text()}")
        QSqlQuery("PRAGMA query_only = ON", db)
        self._db = db

        self._model = _TimelineModel(self)
        self._view.setModel(self._model)
        self._refresh()

    def refresh(self) -> None:
        self._refresh()

    # --- Internal ---------------------------------------------------------

    def _reset_filters(self) -> None:
        for box in self._kind_boxes.values():
            box.setChecked(True)
        self._from.setDate(QDate.currentDate().addYears(-2))
        self._to.setDate(QDate.currentDate())
        self._search.clear()

    def _refresh(self) -> None:
        if self._model is None or self._db is None:
            return
        selected_kinds = [k for k, b in self._kind_boxes.items() if b.isChecked()]
        if not selected_kinds:
            self._model.setQuery("SELECT NULL AS ts WHERE 0", self._db)
            self._counter.setText("0 events")
            return

        # Build query with safe-ish parameterised pieces.
        kinds_in = ", ".join(f"'{k}'" for k in selected_kinds)
        from_iso = self._from.date().toString("yyyy-MM-dd") + "T00:00:00"
        to_iso = self._to.date().toString("yyyy-MM-dd") + "T23:59:59"
        clauses = [
            f"kind IN ({kinds_in})",
            f"ts BETWEEN '{from_iso}' AND '{to_iso}'",
        ]
        text = self._search.text().strip()
        if text:
            safe = text.replace("'", "''")
            clauses.append(f"(summary LIKE '%{safe}%' OR detail LIKE '%{safe}%')")
        where = " AND ".join(clauses)
        sql = (
            "SELECT e.ts AS Timestamp, e.kind AS Kind, p.browser AS Browser, "
            "p.name AS Profile, e.summary AS Summary, e.detail AS Detail "
            "FROM events e JOIN profiles p ON p.id = e.profile_id "
            f"WHERE {where} "
            "ORDER BY e.ts DESC "
            "LIMIT 50000"
        )
        query = QSqlQuery(self._db)
        query.exec_(sql)
        self._model.setQuery(query)
        # Find the index of "Kind" so the colour decorator knows which cell to paint.
        kind_index = 1
        for i in range(self._model.columnCount()):
            if self._model.headerData(i, Qt.Horizontal) == "Kind":
                kind_index = i
                break
        self._model.setColumns(kind_index)

        # ``QSqlQueryModel`` lazy-loads by default; pull everything we asked
        # for so the counter reflects reality.
        while self._model.canFetchMore():
            self._model.fetchMore()
        total = self._model.rowCount()
        self._counter.setText(f"{total} event{'s' if total != 1 else ''}")
        self._view.resizeColumnsToContents()
        # Bound column widths so wide URLs don't squash the rest.
        for col in range(self._model.columnCount()):
            width = self._view.columnWidth(col)
            self._view.setColumnWidth(col, min(width, 320))
