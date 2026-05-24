"""Scalable artifact-table widget backed by SQLite.

This is the second iteration of ``DataTable``. The first one held every row as
a Python list of strings — fine for a few thousand rows, deadly for the 100k+
entries a real Chrome history can have.

Now:

* Data lives in the session ``SessionStore``; we just point ``QSqlTableModel``
  at it with a filter ``profile_id = ?``.
* Qt itself only materialises the visible viewport plus a small lookahead, so
  scrolling a million-row history stays smooth and memory flat.
* The search box runs a server-side LIKE; Qt re-issues the query.
* Sort by clicking a header re-issues with ``ORDER BY``.
* Selection emits ``row_selected`` carrying the full row dict so the
  ``DetailPanel`` can show every field.
"""

from __future__ import annotations

from typing import Optional

import re

from PyQt5.QtCore import QModelIndex, Qt, pyqtSignal
from PyQt5.QtGui import QBrush, QColor, QKeySequence
from PyQt5.QtSql import QSqlDatabase, QSqlQuery, QSqlTableModel
from PyQt5.QtWidgets import (
    QAbstractItemView,
    QAction,
    QApplication,
    QCheckBox,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMenu,
    QShortcut,
    QTableView,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from data.store import SessionStore


# Colour palettes — applied to the whole row when an artifact has a flag set.
_IOC_BG = QColor("#fee2e2")     # soft red — IOC hit
_DELETED_BG = QColor("#fef3c7") # soft amber — carved / deleted record
_TAG_BG = QColor("#dbeafe")     # soft blue — analyst-tagged row


# Pretty column titles per table. Falls back to raw column name when missing.
_HEADERS = {
    "history": {
        "url": "URL", "title": "Title", "visit_count": "Visits",
        "typed_count": "Typed", "last_visit": "Last visit", "visit_type": "Type",
        "from_visit_url": "Referrer", "category": "Category",
    },
    "cookies": {
        "host": "Host", "name": "Name", "value": "Value", "path": "Path",
        "expires": "Expires", "created": "Created", "last_access": "Accessed",
        "secure": "Secure", "http_only": "HttpOnly", "same_site": "SameSite",
        "encrypted": "Encrypted",
    },
    "downloads": {
        "url": "URL", "target_path": "Target", "referrer": "Referrer",
        "mime_type": "MIME", "total_bytes": "Total", "received_bytes": "Received",
        "state": "State", "start_time": "Started", "end_time": "Ended",
    },
    "logins": {
        "origin_url": "Origin", "action_url": "Action", "username": "Username",
        "password": "Password", "date_created": "Created",
        "date_last_used": "Last used", "times_used": "Uses",
        "encrypted": "Encrypted",
    },
    "bookmarks": {
        "folder": "Folder", "name": "Name", "url": "URL",
        "date_added": "Added", "date_modified": "Modified",
    },
    "autofill": {
        "field_name": "Field", "value": "Value", "count": "Count",
        "first_used": "First used", "last_used": "Last used",
    },
    "extensions": {
        "extension_id": "ID", "name": "Name", "version": "Version",
        "description": "Description", "enabled": "Enabled",
        "install_path": "Path",
    },
    "events": {
        "ts": "Timestamp", "kind": "Kind", "summary": "Summary",
        "detail": "Detail", "profile_id": "Profile",
    },
    "cache_entries": {
        "url": "URL", "mime_type": "MIME", "size": "Size",
        "fetched_at": "Fetched", "last_used": "Last used",
        "status_code": "Status", "source": "Source",
    },
    "web_storage": {
        "origin": "Origin", "kind": "Kind", "key": "Key", "value": "Value",
        "last_modified": "Modified", "source": "Source",
    },
    "open_tabs": {
        "session": "Session", "window_idx": "Window", "tab_idx": "Tab",
        "url": "URL", "title": "Title", "last_active": "Last active",
        "pinned": "Pinned",
    },
    "permissions": {
        "origin": "Origin", "permission": "Permission", "setting": "Setting",
        "last_modified": "Modified",
    },
}

# Columns we hide because they only matter to joins, never to the user.
_HIDDEN = ("id", "profile_id")


# Qt's SQL drivers identify connections by name. Each DataTable gets its own
# so multiple tabs can be sorted/filtered independently against the same file.
_NEXT_CONN_ID = 0


def _next_connection_name() -> str:
    global _NEXT_CONN_ID
    _NEXT_CONN_ID += 1
    return f"wfs_conn_{_NEXT_CONN_ID}"


class _DecoratedTableModel(QSqlTableModel):
    """Adds row-level decorations: IOC hits, carved records, analyst tags."""

    def __init__(self, parent, db, store: SessionStore, table: str) -> None:
        super().__init__(parent, db)
        self._store = store
        self._table = table
        # Caches refreshed on every select() — keyed by (kind, artifact_id).
        self._ioc_ids: set[int] = set()
        self._deleted_ids: set[int] = set()
        self._tag_ids: set[int] = set()

    def select(self) -> bool:  # type: ignore[override]
        ok = super().select()
        # Pull *everything* the model fetched so canFetchMore doesn't leave us
        # decorating only the first 256 rows.
        while super().canFetchMore():
            super().fetchMore()
        self._refresh_decoration_caches()
        return ok

    def data(self, index, role=Qt.DisplayRole):  # type: ignore[override]
        if role in (Qt.BackgroundRole, Qt.ToolTipRole):
            record = self.record(index.row())
            try:
                artifact_id = int(record.value("id"))
            except (TypeError, ValueError):
                artifact_id = -1
            if role == Qt.BackgroundRole:
                if artifact_id in self._ioc_ids:
                    return QBrush(_IOC_BG)
                if artifact_id in self._deleted_ids:
                    return QBrush(_DELETED_BG)
                if artifact_id in self._tag_ids:
                    return QBrush(_TAG_BG)
            elif role == Qt.ToolTipRole:
                tips: list[str] = []
                if artifact_id in self._ioc_ids:
                    tips.append("IOC hit — see the IOC dialog for details")
                if artifact_id in self._deleted_ids:
                    tips.append("Carved from WAL / freelist — possibly deleted record")
                if artifact_id in self._tag_ids:
                    tips.append("Tagged by analyst")
                if tips:
                    return "\n".join(tips)
        return super().data(index, role)

    # --- Cache rebuild ----------------------------------------------------

    def _refresh_decoration_caches(self) -> None:
        conn = self._store.connection()
        try:
            ioc_rows = conn.execute(
                "SELECT DISTINCT artifact_id FROM ioc_hits WHERE artifact_kind=?",
                (self._table,),
            ).fetchall()
            self._ioc_ids = {int(r["artifact_id"]) for r in ioc_rows}
        except Exception:  # noqa: BLE001
            self._ioc_ids = set()
        # Only history / cookies / downloads have a ``deleted`` column.
        if self._table in ("history", "cookies", "downloads"):
            try:
                rows = conn.execute(
                    f"SELECT id FROM {self._table} WHERE deleted = 1"
                ).fetchall()
                self._deleted_ids = {int(r["id"]) for r in rows}
            except Exception:  # noqa: BLE001
                self._deleted_ids = set()
        else:
            self._deleted_ids = set()
        try:
            tag_rows = conn.execute(
                "SELECT DISTINCT artifact_id FROM tags WHERE artifact_kind=?",
                (self._table,),
            ).fetchall()
            self._tag_ids = {int(r["artifact_id"]) for r in tag_rows}
        except Exception:  # noqa: BLE001
            self._tag_ids = set()


class DataTable(QWidget):
    """Virtual table view bound to one artifact table in a ``SessionStore``."""

    row_selected = pyqtSignal(dict)  # full record of the focused row
    tagged = pyqtSignal()            # emitted after a tag is added

    def __init__(self, table: str, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._table = table
        self._profile_id: Optional[int] = None
        self._search_text = ""
        self._store: Optional[SessionStore] = None
        self._db: Optional[QSqlDatabase] = None
        self._model: Optional[_DecoratedTableModel] = None
        self._build_ui()

    # --- Construction -----------------------------------------------------

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        top = QHBoxLayout()
        self._filter = QLineEdit()
        self._filter.setPlaceholderText(f"Filter {self._table}… (server-side LIKE — toggle .* for regex)")
        self._filter.textChanged.connect(self._on_filter_changed)
        self._regex_toggle = QCheckBox(".*")
        self._regex_toggle.setToolTip("Treat the filter as a Python regex (client-side, post-fetch).")
        self._regex_toggle.stateChanged.connect(self._on_filter_changed)
        self._save_btn = QToolButton()
        self._save_btn.setText("☆")
        self._save_btn.setToolTip("Save current filter as a named search")
        self._save_btn.clicked.connect(self._save_current_search)
        self._counter = QLabel("0 rows")
        self._counter.setStyleSheet("color: #666;")
        top.addWidget(self._filter, 1)
        top.addWidget(self._regex_toggle)
        top.addWidget(self._save_btn)
        top.addWidget(self._counter)
        layout.addLayout(top)

        self._view = QTableView()
        self._view.setSortingEnabled(True)
        self._view.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._view.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self._view.setAlternatingRowColors(True)
        self._view.setWordWrap(False)
        self._view.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self._view.horizontalHeader().setStretchLastSection(True)
        self._view.verticalHeader().setVisible(False)
        self._view.setContextMenuPolicy(Qt.CustomContextMenu)
        self._view.customContextMenuRequested.connect(self._open_context_menu)
        layout.addWidget(self._view)

        QShortcut(QKeySequence.Copy, self._view, activated=self._copy_selection)

    # --- Public API -------------------------------------------------------

    def attach(self, store: SessionStore) -> None:
        """Bind this table to a ``SessionStore``.

        Has to be called once before ``set_profile``. Opens a dedicated
        ``QSqlDatabase`` connection so Qt's model is independent of the
        sqlite3 connection the rest of the app uses.
        """
        self._store = store
        # Close any previous connection so reopening with a new session works.
        if self._db is not None:
            QSqlDatabase.removeDatabase(self._db.connectionName())
            self._db = None

        name = _next_connection_name()
        db = QSqlDatabase.addDatabase("QSQLITE", name)
        db.setDatabaseName(str(store.path))
        if not db.open():
            raise RuntimeError(f"Could not open QSQLITE on {store.path}: {db.lastError().text()}")
        # Read-only at the Qt level — Qt still uses parameterised queries even
        # without explicit setReadOnly, but we want belt-and-braces.
        QSqlQuery("PRAGMA query_only = ON", db)
        self._db = db

        model = _DecoratedTableModel(self, db, store, self._table)
        model.setTable(self._table)
        model.setEditStrategy(QSqlTableModel.OnManualSubmit)
        model.select()
        self._configure_headers(model)
        self._view.setModel(model)
        self._hide_internal_columns(model)
        self._model = model
        self._view.selectionModel().currentRowChanged.connect(self._on_row_changed)
        self._refresh()

    def set_profile(self, profile_id: Optional[int]) -> None:
        self._profile_id = profile_id
        self._refresh()

    def refresh(self) -> None:
        self._refresh()

    # --- Slots ------------------------------------------------------------

    def _on_filter_changed(self, text: str) -> None:
        self._search_text = text.strip()
        self._refresh()

    def _refresh(self) -> None:
        if self._model is None:
            return
        clauses: list[str] = []
        if self._profile_id is not None:
            clauses.append(f"profile_id = {int(self._profile_id)}")
        # Regex mode is post-fetch (SQLite's REGEXP isn't reliable across
        # platforms). LIKE mode stays server-side for speed.
        use_regex = self._regex_toggle.isChecked() and bool(self._search_text)
        if self._search_text and not use_regex:
            cols = _HEADERS.get(self._table, {}).keys() or self._all_columns()
            safe = self._search_text.replace("'", "''")
            ors = " OR ".join(f"{c} LIKE '%{safe}%'" for c in cols)
            if ors:
                clauses.append(f"({ors})")
        self._model.setFilter(" AND ".join(clauses))
        self._model.select()
        # Regex post-filter: hide rows whose joined text doesn't match.
        if use_regex:
            try:
                pattern = re.compile(self._search_text, re.IGNORECASE)
            except re.error:
                pattern = None
            cols = _HEADERS.get(self._table, {}).keys() or self._all_columns()
            for row in range(self._model.rowCount()):
                record = self._model.record(row)
                joined = " ".join(str(record.value(c) or "") for c in cols)
                hide = bool(pattern) and not pattern.search(joined)
                self._view.setRowHidden(row, hide)
        # ``QSqlTableModel`` only fetches the first 256 rows by default; pull
        # them all on demand when the user scrolls past the current window.
        while self._model.canFetchMore():
            self._model.fetchMore()
        total = self._model.rowCount()
        self._counter.setText(f"{total} row{'s' if total != 1 else ''}")
        self._view.resizeColumnsToContents()
        for col in range(min(8, self._model.columnCount())):
            width = self._view.columnWidth(col)
            self._view.setColumnWidth(col, min(width, 320))

    def _on_row_changed(self, current: QModelIndex, _previous: QModelIndex) -> None:
        if not current.isValid() or self._model is None:
            return
        record = self._model.record(current.row())
        payload = {record.fieldName(i): record.value(i) for i in range(record.count())}
        self.row_selected.emit(payload)

    def _copy_selection(self) -> None:
        if self._model is None:
            return
        rows = sorted({idx.row() for idx in self._view.selectionModel().selectedRows()})
        if not rows:
            rows = sorted({idx.row() for idx in self._view.selectionModel().selectedIndexes()})
        if not rows:
            return
        cols = [c for c in range(self._model.columnCount())
                if not self._view.isColumnHidden(c)]
        lines = []
        for row in rows:
            cells = [str(self._model.data(self._model.index(row, c)) or "") for c in cols]
            lines.append("\t".join(cells))
        QApplication.clipboard().setText("\n".join(lines))

    # --- Helpers ----------------------------------------------------------

    def _configure_headers(self, model: QSqlTableModel) -> None:
        labels = _HEADERS.get(self._table, {})
        for i in range(model.columnCount()):
            name = model.headerData(i, Qt.Horizontal)
            pretty = labels.get(str(name), str(name).replace("_", " ").title())
            model.setHeaderData(i, Qt.Horizontal, pretty)

    def _hide_internal_columns(self, model: QSqlTableModel) -> None:
        for i in range(model.columnCount()):
            raw = self._raw_column_name(model, i)
            if raw in _HIDDEN:
                self._view.setColumnHidden(i, True)

    def _raw_column_name(self, model: QSqlTableModel, index: int) -> str:
        # ``record()`` gives us the un-prettified column name.
        return model.record().fieldName(index)

    def _all_columns(self) -> list[str]:
        if self._model is None:
            return []
        return [self._raw_column_name(self._model, i) for i in range(self._model.columnCount())]

    # --- Saved searches --------------------------------------------------

    def _save_current_search(self) -> None:
        if not self._search_text or self._store is None:
            return
        from PyQt5.QtWidgets import QInputDialog as _QId
        name, ok = _QId.getText(self, "Save search", "Name:")
        if not ok or not name.strip():
            return
        import json as _json
        spec = _json.dumps({
            "table": self._table,
            "pattern": self._search_text,
            "regex": self._regex_toggle.isChecked(),
        })
        self._store.connection().execute(
            "INSERT INTO saved_searches(name, spec) VALUES(?, ?)",
            (name.strip(), spec),
        )

    # --- Context menu / tagging -------------------------------------------

    def _open_context_menu(self, pos) -> None:
        if self._model is None or self._store is None:
            return
        index = self._view.indexAt(pos)
        if not index.isValid():
            return
        menu = QMenu(self)
        tag_action = QAction("Tag as evidence", self)
        tag_action.triggered.connect(lambda: self._add_tag(index, "evidence"))
        menu.addAction(tag_action)
        note_action = QAction("Add note…", self)
        note_action.triggered.connect(lambda: self._add_note(index))
        menu.addAction(note_action)
        menu.addSeparator()
        copy_action = QAction("Copy row", self)
        copy_action.triggered.connect(self._copy_selection)
        menu.addAction(copy_action)
        menu.exec_(self._view.viewport().mapToGlobal(pos))

    def _add_tag(self, index, tag: str) -> None:
        if self._model is None or self._store is None:
            return
        record = self._model.record(index.row())
        try:
            artifact_id = int(record.value("id"))
            profile_id = int(record.value("profile_id"))
        except (TypeError, ValueError):
            return
        self._store.add_tag(self._table, artifact_id, tag=tag, profile_id=profile_id)
        self._refresh()
        self.tagged.emit()

    def _add_note(self, index) -> None:
        if self._model is None or self._store is None:
            return
        record = self._model.record(index.row())
        try:
            artifact_id = int(record.value("id"))
            profile_id = int(record.value("profile_id"))
        except (TypeError, ValueError):
            return
        text, ok = QInputDialog.getMultiLineText(
            self, "Add note", "Note for this artifact:", ""
        )
        if not ok or not text.strip():
            return
        self._store.add_tag(
            self._table, artifact_id, tag="note", note=text.strip(), profile_id=profile_id,
        )
        self._refresh()
        self.tagged.emit()
