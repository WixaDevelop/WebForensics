"""Export dialog — pick format, artifacts and destination."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

from PyQt5.QtWidgets import (
    QButtonGroup,
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QRadioButton,
    QVBoxLayout,
)

from data.models import ARTIFACT_KINDS


_FORMAT_LABELS = {
    "csv": "CSV (one file per artifact, in a folder)",
    "json": "JSON (single document)",
    "html": "HTML report (single document)",
    "pdf": "PDF report (court-ready)",
    "case": "CASE / UCO (NIST forensic interchange)",
}


class ExportDialog(QDialog):
    """Collects format + selected artifacts + output path."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Export")
        self.resize(520, 420)
        self._format_group = QButtonGroup(self)
        self._kind_boxes: dict[str, QCheckBox] = {}
        self._build_ui()

    @property
    def selected_format(self) -> str:
        for fmt, btn in self._fmt_buttons.items():
            if btn.isChecked():
                return fmt
        return "json"

    @property
    def selected_kinds(self) -> list[str]:
        return [k for k, box in self._kind_boxes.items() if box.isChecked()]

    @property
    def output_path(self) -> Path:
        return Path(self._path_edit.text().strip())

    # --- UI ---------------------------------------------------------------

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)

        fmt_box = QGroupBox("Format")
        fmt_layout = QVBoxLayout(fmt_box)
        self._fmt_buttons: dict[str, QRadioButton] = {}
        for idx, (fmt, label) in enumerate(_FORMAT_LABELS.items()):
            btn = QRadioButton(label)
            if idx == 0:
                btn.setChecked(True)
            self._format_group.addButton(btn, idx)
            self._fmt_buttons[fmt] = btn
            fmt_layout.addWidget(btn)
        for btn in self._fmt_buttons.values():
            btn.toggled.connect(self._update_path_hint)
        layout.addWidget(fmt_box)

        kinds_box = QGroupBox("Artifacts to include")
        kinds_layout = QVBoxLayout(kinds_box)
        row = QHBoxLayout()
        for idx, kind in enumerate(ARTIFACT_KINDS):
            box = QCheckBox(kind.title())
            box.setChecked(True)
            self._kind_boxes[kind] = box
            row.addWidget(box)
            if (idx + 1) % 4 == 0:
                kinds_layout.addLayout(row)
                row = QHBoxLayout()
        if row.count():
            kinds_layout.addLayout(row)
        layout.addWidget(kinds_box)

        path_row = QHBoxLayout()
        path_row.addWidget(QLabel("Output:"))
        self._path_edit = QLineEdit()
        path_row.addWidget(self._path_edit, 1)
        browse = QPushButton("Browse…")
        browse.clicked.connect(self._browse)
        path_row.addWidget(browse)
        layout.addLayout(path_row)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self._on_accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _update_path_hint(self) -> None:
        # Refresh placeholder text so the user sees the expected target shape.
        if self.selected_format == "csv":
            self._path_edit.setPlaceholderText("Folder to write CSV files into…")
        elif self.selected_format == "json":
            self._path_edit.setPlaceholderText("…/webforensics.json")
        elif self.selected_format == "pdf":
            self._path_edit.setPlaceholderText("…/webforensics.pdf")
        else:
            self._path_edit.setPlaceholderText("…/webforensics.html")

    def _browse(self) -> None:
        if self.selected_format == "csv":
            path = QFileDialog.getExistingDirectory(self, "Select output folder")
        else:
            ext_map = {"html": ".html", "json": ".json", "pdf": ".pdf",
                       "case": ".jsonld"}
            ext = ext_map.get(self.selected_format, ".json")
            path, _ = QFileDialog.getSaveFileName(
                self,
                "Save report",
                f"webforensics{ext}",
                f"*{ext}",
            )
        if path:
            self._path_edit.setText(path)

    def _on_accept(self) -> None:
        if not self._path_edit.text().strip():
            from PyQt5.QtWidgets import QMessageBox
            QMessageBox.warning(self, "Missing path", "Please choose an output path.")
            return
        if not self.selected_kinds:
            from PyQt5.QtWidgets import QMessageBox
            QMessageBox.warning(self, "Nothing selected", "Pick at least one artifact.")
            return
        self.accept()
