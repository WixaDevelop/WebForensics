"""Search-term view: shows what the user searched for, where, and how often.

Two panels side-by-side:

* **Left** — a ranked list of the top queries (across all engines or filtered
  by one) so the analyst can see "what was this person looking up".
* **Right** — the underlying ``search_terms`` rows for the selected query
  (engine, timestamp, source URL).

Data comes from the ``search_terms`` table which is populated automatically
after every history ingest. No new extractor calls needed.
"""

from __future__ import annotations

from typing import Optional

from PyQt5.QtCore import Qt
from PyQt5.QtSql import QSqlDatabase, QSqlQuery, QSqlQueryModel
from PyQt5.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QSplitter,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from data.store import SessionStore


class SearchTermsView(QWidget):
    """Top-queries dashboard backed by ``search_terms``."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._store: Optional[SessionStore] = None
        self._db: Optional[QSqlDatabase] = None
        self._top_model: Optional[QSqlQueryModel] = None
        self._detail_model: Optional[QSqlQueryModel] = None
        self._selected_query: Optional[str] = None
        self._build_ui()

    # --- UI ---------------------------------------------------------------

    def _build_ui(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(8, 8, 8, 8)

        controls = QHBoxLayout()
        controls.addWidget(QLabel("Engine:"))
        self._engine = QComboBox()
        self._engine.addItem("All engines", "")
        self._engine.currentIndexChanged.connect(self._refresh_top)
        controls.addWidget(self._engine)
        controls.addSpacing(12)
        controls.addWidget(QLabel("Filter:"))
        self._filter = QLineEdit()
        self._filter.setPlaceholderText("Substring filter on query…")
        self._filter.textChanged.connect(self._refresh_top)
        controls.addWidget(self._filter, 1)
        reset = QPushButton("Reset")
        reset.clicked.connect(self._reset)
        controls.addWidget(reset)
        outer.addLayout(controls)

        splitter = QSplitter(Qt.Horizontal)
        outer.addWidget(splitter, 1)

        # Top-queries panel.
        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.addWidget(QLabel("<b>Top queries</b>"))
        self._top_view = QTableView()
        self._top_view.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._top_view.setSelectionMode(QAbstractItemView.SingleSelection)
        self._top_view.setAlternatingRowColors(True)
        self._top_view.horizontalHeader().setStretchLastSection(True)
        self._top_view.verticalHeader().setVisible(False)
        left_layout.addWidget(self._top_view)
        self._top_counter = QLabel("0 queries")
        self._top_counter.setStyleSheet("color: #666;")
        left_layout.addWidget(self._top_counter)
        splitter.addWidget(left)

        # Detail panel.
        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        self._detail_header = QLabel("<i>Select a query to see when and where it ran.</i>")
        self._detail_header.setStyleSheet("color: #555;")
        right_layout.addWidget(self._detail_header)
        self._detail_view = QTableView()
        self._detail_view.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._detail_view.setAlternatingRowColors(True)
        self._detail_view.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self._detail_view.horizontalHeader().setStretchLastSection(True)
        self._detail_view.verticalHeader().setVisible(False)
        right_layout.addWidget(self._detail_view)
        splitter.addWidget(right)
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([420, 700])

    # --- Public API -------------------------------------------------------

    def attach(self, store: SessionStore) -> None:
        self._store = store
        if self._db is not None:
            QSqlDatabase.removeDatabase(self._db.connectionName())
        name = f"wfs_searchterms_{id(self)}"
        db = QSqlDatabase.addDatabase("QSQLITE", name)
        db.setDatabaseName(str(store.path))
        if not db.open():
            raise RuntimeError(f"Cannot open search-terms DB: {db.lastError().text()}")
        QSqlQuery("PRAGMA query_only = ON", db)
        self._db = db

        self._top_model = QSqlQueryModel(self)
        self._detail_model = QSqlQueryModel(self)
        self._top_view.setModel(self._top_model)
        self._detail_view.setModel(self._detail_model)
        self._top_view.selectionModel().currentRowChanged.connect(
            lambda cur, _prev: self._on_query_selected(cur))
        self._reload_engines()
        self._refresh_top()

    def refresh(self) -> None:
        self._reload_engines()
        self._refresh_top()

    # --- Internal ---------------------------------------------------------

    def _reset(self) -> None:
        self._engine.setCurrentIndex(0)
        self._filter.clear()

    def _reload_engines(self) -> None:
        if self._db is None:
            return
        current = self._engine.currentData() or ""
        self._engine.blockSignals(True)
        self._engine.clear()
        self._engine.addItem("All engines", "")
        rows = QSqlQuery(self._db)
        rows.exec_("SELECT DISTINCT engine FROM search_terms WHERE engine IS NOT NULL "
                   "AND engine != '' ORDER BY engine")
        while rows.next():
            engine = rows.value(0)
            self._engine.addItem(str(engine), str(engine))
        # Restore the previous selection if it still exists.
        for i in range(self._engine.count()):
            if self._engine.itemData(i) == current:
                self._engine.setCurrentIndex(i)
                break
        self._engine.blockSignals(False)

    def _refresh_top(self) -> None:
        if self._top_model is None or self._db is None:
            return
        engine_filter = (self._engine.currentData() or "").replace("'", "''")
        text = self._filter.text().strip().replace("'", "''")
        clauses = ["query IS NOT NULL", "query != ''"]
        if engine_filter:
            clauses.append(f"engine = '{engine_filter}'")
        if text:
            clauses.append(f"query LIKE '%{text}%'")
        where = " AND ".join(clauses)
        sql = (
            "SELECT query AS Query, COUNT(*) AS Count, "
            "       GROUP_CONCAT(DISTINCT engine) AS Engines, "
            "       MAX(ts) AS \"Last seen\" "
            "FROM search_terms "
            f"WHERE {where} "
            "GROUP BY query "
            "ORDER BY Count DESC, \"Last seen\" DESC "
            "LIMIT 5000"
        )
        query = QSqlQuery(self._db)
        query.exec_(sql)
        self._top_model.setQuery(query)
        while self._top_model.canFetchMore():
            self._top_model.fetchMore()
        total = self._top_model.rowCount()
        self._top_counter.setText(f"{total} unique quer{'ies' if total != 1 else 'y'}")
        self._top_view.resizeColumnsToContents()
        self._detail_header.setText("<i>Select a query to see when and where it ran.</i>")
        self._detail_model.clear()

    def _on_query_selected(self, current) -> None:
        if not current.isValid() or self._top_model is None or self._db is None:
            return
        record = self._top_model.record(current.row())
        term = record.value("Query")
        self._selected_query = str(term)
        safe = self._selected_query.replace("'", "''")
        engine_filter = (self._engine.currentData() or "").replace("'", "''")
        engine_clause = f" AND engine = '{engine_filter}'" if engine_filter else ""
        sql = (
            "SELECT ts AS Timestamp, engine AS Engine, p.browser AS Browser, "
            "       p.name AS Profile, url AS URL, title AS Title "
            "FROM search_terms s "
            "LEFT JOIN profiles p ON p.id = s.profile_id "
            f"WHERE query = '{safe}'{engine_clause} "
            "ORDER BY ts DESC "
            "LIMIT 5000"
        )
        query = QSqlQuery(self._db)
        query.exec_(sql)
        self._detail_model.setQuery(query)
        while self._detail_model.canFetchMore():
            self._detail_model.fetchMore()
        self._detail_view.resizeColumnsToContents()
        for col in range(self._detail_model.columnCount()):
            width = self._detail_view.columnWidth(col)
            self._detail_view.setColumnWidth(col, min(width, 400))
        self._detail_header.setText(
            f"<b>{self._top_model.rowCount()}</b> unique queries — "
            f"showing all visits for <code>{self._selected_query}</code>"
        )
