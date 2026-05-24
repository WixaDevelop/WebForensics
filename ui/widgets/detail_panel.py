"""Detail panel for the focused row.

Sits below the main artifact table and shows every field of the selected
record without truncation — long URLs, decoded cookie values, full file
paths. Provides quick actions: copy as JSON, copy a single field, open the
URL externally.

It listens to the ``row_selected`` signal that each ``DataTable`` emits.
"""

from __future__ import annotations

import json
from typing import Any

from PyQt5.QtCore import Qt, QUrl
from PyQt5.QtGui import QDesktopServices
from PyQt5.QtWidgets import (
    QApplication,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)


class DetailPanel(QWidget):
    """Read-only inspector for the currently selected artifact row."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._current: dict[str, Any] = {}
        self._build_ui()

    # --- UI ---------------------------------------------------------------

    def _build_ui(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(8, 8, 8, 8)

        header = QHBoxLayout()
        self._title = QLabel("<i>Select a row to see details.</i>")
        self._title.setStyleSheet("color: #555;")
        header.addWidget(self._title, 1)

        self._open_btn = QPushButton("Open URL")
        self._open_btn.setEnabled(False)
        self._open_btn.clicked.connect(self._open_url)
        header.addWidget(self._open_btn)

        self._copy_json_btn = QPushButton("Copy JSON")
        self._copy_json_btn.setEnabled(False)
        self._copy_json_btn.clicked.connect(self._copy_json)
        header.addWidget(self._copy_json_btn)
        outer.addLayout(header)

        # A scroll area keeps the panel usable even when a single value is
        # huge (think a full cookie blob).
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.NoFrame)
        container = QGroupBox()
        container.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.MinimumExpanding)
        self._form = QFormLayout(container)
        self._form.setLabelAlignment(Qt.AlignRight | Qt.AlignTop)
        self._form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        scroll.setWidget(container)
        outer.addWidget(scroll)

    # --- Public API -------------------------------------------------------

    def show_record(self, record: dict[str, Any]) -> None:
        """Replace the displayed fields with the given record."""
        self._current = dict(record)
        self._clear_form()
        if not record:
            self._title.setText("<i>Select a row to see details.</i>")
            self._open_btn.setEnabled(False)
            self._copy_json_btn.setEnabled(False)
            return

        # Use the most descriptive field as a heading.
        title_value = (
            record.get("title")
            or record.get("name")
            or record.get("url")
            or record.get("origin_url")
            or record.get("host")
            or "(no title)"
        )
        self._title.setText(f"<b>{str(title_value)[:140]}</b>")

        for key, value in record.items():
            if key in ("id", "profile_id"):
                continue
            label = QLabel(self._humanise(key))
            label.setStyleSheet("color: #444;")
            self._form.addRow(label, self._value_widget(value))

        url = self._url_from(record)
        self._open_btn.setEnabled(bool(url))
        self._copy_json_btn.setEnabled(True)

    # --- Internal ---------------------------------------------------------

    def _clear_form(self) -> None:
        # ``QFormLayout`` keeps both label and field widgets; remove both.
        while self._form.rowCount():
            self._form.removeRow(0)

    def _value_widget(self, value: Any) -> QWidget:
        text = "" if value is None else str(value)
        if len(text) > 200 or "\n" in text:
            editor = QTextEdit()
            editor.setReadOnly(True)
            editor.setPlainText(text)
            editor.setMinimumHeight(80)
            editor.setMaximumHeight(180)
            return editor
        label = QLabel(text)
        label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        label.setWordWrap(True)
        return label

    def _humanise(self, key: str) -> str:
        return key.replace("_", " ").title()

    def _url_from(self, record: dict[str, Any]) -> str:
        for k in ("url", "origin_url", "action_url"):
            value = record.get(k)
            if value and isinstance(value, str) and value.startswith(("http://", "https://")):
                return value
        return ""

    # --- Slots ------------------------------------------------------------

    def _open_url(self) -> None:
        url = self._url_from(self._current)
        if url:
            QDesktopServices.openUrl(QUrl(url))

    def _copy_json(self) -> None:
        payload = {k: (str(v) if v is not None else None) for k, v in self._current.items()
                   if k not in ("id", "profile_id")}
        QApplication.clipboard().setText(json.dumps(payload, indent=2, ensure_ascii=False))
