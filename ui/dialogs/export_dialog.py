"""Export dialog — pick format, artifacts, forensic extras and destination.

The dialog has three checkbox groups so the analyst can include or exclude
data at the granularity that matches each export use-case:

* **Browser artifacts** — the 11 standard kinds (history, cookies, …).
* **Forensic extras** — derived/correlated tables that live in the
  SessionStore but never made it into ``ProfileBundle`` (search terms,
  detected accounts, IM messages, JWT tokens, IOC matches, findings,
  OS artifacts, chain-of-custody, analyst notes, etc).
* **Format** — CSV / XLSX / JSON / HTML / PDF / CASE-UCO.

XLSX is the only format that consumes ``extras`` today; the others get
the original artifacts-only behaviour for backwards compatibility.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QButtonGroup,
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QRadioButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from data.models import ARTIFACT_KINDS
from exporters.xlsx_exporter import EXTRA_TABLES, EXTRA_TABLE_HUMAN_NAMES


_FORMAT_LABELS = {
    "xlsx": "Excel (.xlsx) — una hoja por artefacto, con resumen y glosario",
    "csv": "CSV — un archivo por artefacto, en una carpeta",
    "json": "JSON — documento único",
    "html": "HTML — reporte único",
    "pdf": "PDF — reporte único",
    "case": "CASE / UCO — formato de intercambio forense NIST",
}

# Per-artifact friendly labels — keep simple, the XLSX interpretation
# sheet carries the long-form description.
_ARTIFACT_LABELS = {
    "history": "Historial (URLs visitadas)",
    "cookies": "Cookies (sesiones y rastreo)",
    "downloads": "Descargas (archivos bajados)",
    "logins": "Credenciales guardadas",
    "bookmarks": "Favoritos / marcadores",
    "autofill": "Autocompletado de formularios",
    "extensions": "Extensiones instaladas",
    "cache_entries": "Caché HTTP",
    "web_storage": "LocalStorage / IndexedDB",
    "open_tabs": "Pestañas abiertas",
    "permissions": "Permisos otorgados",
}

# Per-extra friendly label for the checkbox.
_EXTRA_LABELS = {
    "search_terms": "Búsquedas (queries de Google, Bing, etc)",
    "accounts": "Cuentas detectadas (Facebook, Google, GitHub…)",
    "messages": "Mensajes IM (WhatsApp / Discord / Telegram Web)",
    "tokens": "Tokens JWT / OAuth recuperados",
    "user_agents": "User-Agents observados",
    "findings": "Hallazgos forenses (anti-forensics)",
    "iocs": "IOCs cargados",
    "ioc_hits": "Coincidencias de IOC (alta prioridad)",
    "os_artifacts": "Artefactos del SO (Registry / Prefetch / DNS)",
    "source_files": "Cadena de custodia (SHA-256 de cada fuente)",
    "domain_intel": "Enriquecimiento de dominios (WHOIS / GeoIP)",
    "tags": "Notas y etiquetas del analista",
}


class ExportDialog(QDialog):
    """Collects format + profiles + artifacts + extras + output path.

    *available_profiles* lets the analyst pick which profile(s) to
    include in the export. Each entry is ``(profile_id, browser,
    profile_name, count)``. Pass an empty list to hide the profile
    picker (legacy behaviour, exports everything).
    """

    def __init__(
        self,
        parent=None,
        has_store_extras: bool = True,
        available_profiles: list[tuple[int, str, str, int]] | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Exportar")
        self.resize(760, 820)
        self._format_group = QButtonGroup(self)
        self._kind_boxes: dict[str, QCheckBox] = {}
        self._extra_boxes: dict[str, QCheckBox] = {}
        self._profile_boxes: dict[int, QCheckBox] = {}
        self._has_store_extras = has_store_extras
        self._available_profiles = available_profiles or []
        self._build_ui()

    @property
    def selected_format(self) -> str:
        for fmt, btn in self._fmt_buttons.items():
            if btn.isChecked():
                return fmt
        return "xlsx"

    @property
    def selected_kinds(self) -> list[str]:
        return [k for k, box in self._kind_boxes.items() if box.isChecked()]

    @property
    def selected_extras(self) -> list[str]:
        return [k for k, box in self._extra_boxes.items() if box.isChecked()]

    @property
    def selected_profile_ids(self) -> list[int]:
        # When no profile picker is shown, an empty list means "all".
        if not self._profile_boxes:
            return []
        return [pid for pid, box in self._profile_boxes.items() if box.isChecked()]

    @property
    def output_path(self) -> Path:
        return Path(self._path_edit.text().strip())

    # --- UI ---------------------------------------------------------------

    def _build_ui(self) -> None:
        outer = QVBoxLayout(self)

        # Scrollable body so the dialog stays usable on small screens.
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        body = QWidget()
        layout = QVBoxLayout(body)
        scroll.setWidget(body)
        outer.addWidget(scroll, 1)

        # Format.
        fmt_box = QGroupBox("Formato")
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
            btn.toggled.connect(self._update_extras_enabled)
        layout.addWidget(fmt_box)

        # Profiles to include (only shown when the caller passed a list).
        if self._available_profiles:
            prof_box = QGroupBox("Perfiles a incluir")
            prof_layout = QGridLayout(prof_box)
            prof_btn_row = QHBoxLayout()
            select_all_profs = QPushButton("Marcar todo")
            select_none_profs = QPushButton("Desmarcar todo")
            select_all_profs.clicked.connect(lambda: self._set_all(self._profile_boxes, True))
            select_none_profs.clicked.connect(lambda: self._set_all(self._profile_boxes, False))
            prof_btn_row.addWidget(select_all_profs)
            prof_btn_row.addWidget(select_none_profs)
            # One quick-select button per distinct browser, so the user can
            # one-click "only Chrome" / "only Firefox" / etc.
            seen_browsers: dict[str, list[int]] = {}
            for pid, browser, name, _count in self._available_profiles:
                seen_browsers.setdefault(browser, []).append(pid)
            for browser, ids in seen_browsers.items():
                btn = QPushButton(f"Solo {browser}")
                btn.clicked.connect(
                    lambda _checked=False, target_ids=set(ids):
                        self._select_only(self._profile_boxes, target_ids)
                )
                prof_btn_row.addWidget(btn)
            prof_btn_row.addStretch(1)
            prof_layout.addLayout(prof_btn_row, 0, 0, 1, 2)
            for idx, (pid, browser, name, count) in enumerate(self._available_profiles):
                label = f"{browser} — {name}   ({count:,} elementos)"
                box = QCheckBox(label)
                box.setChecked(True)
                self._profile_boxes[pid] = box
                prof_layout.addWidget(box, 1 + idx // 2, idx % 2)
            layout.addWidget(prof_box)

        # Browser artifacts.
        kinds_box = QGroupBox("Artefactos del navegador")
        kinds_layout = QGridLayout(kinds_box)
        kinds_btn_row = QHBoxLayout()
        select_all_kinds = QPushButton("Marcar todo")
        select_none_kinds = QPushButton("Desmarcar todo")
        select_all_kinds.clicked.connect(lambda: self._set_all(self._kind_boxes, True))
        select_none_kinds.clicked.connect(lambda: self._set_all(self._kind_boxes, False))
        kinds_btn_row.addWidget(select_all_kinds)
        kinds_btn_row.addWidget(select_none_kinds)
        kinds_btn_row.addStretch(1)
        kinds_layout.addLayout(kinds_btn_row, 0, 0, 1, 2)
        for idx, kind in enumerate(ARTIFACT_KINDS):
            box = QCheckBox(_ARTIFACT_LABELS.get(kind, kind))
            box.setChecked(True)
            self._kind_boxes[kind] = box
            kinds_layout.addWidget(box, 1 + idx // 2, idx % 2)
        layout.addWidget(kinds_box)

        # Forensic extras.
        self._extras_box = QGroupBox("Datos forenses adicionales (solo XLSX)")
        extras_layout = QGridLayout(self._extras_box)
        ex_btn_row = QHBoxLayout()
        select_all_extras = QPushButton("Marcar todo")
        select_none_extras = QPushButton("Desmarcar todo")
        select_critical_extras = QPushButton("Solo críticos")
        select_all_extras.clicked.connect(lambda: self._set_all(self._extra_boxes, True))
        select_none_extras.clicked.connect(lambda: self._set_all(self._extra_boxes, False))
        select_critical_extras.clicked.connect(self._select_critical_extras)
        ex_btn_row.addWidget(select_all_extras)
        ex_btn_row.addWidget(select_none_extras)
        ex_btn_row.addWidget(select_critical_extras)
        ex_btn_row.addStretch(1)
        extras_layout.addLayout(ex_btn_row, 0, 0, 1, 2)

        # Default-on: search_terms, accounts, ioc_hits, findings, source_files.
        # Other extras default off (they may not even have data in this session).
        on_by_default = {"search_terms", "accounts", "ioc_hits", "findings", "source_files"}
        for idx, extra in enumerate(EXTRA_TABLES):
            label = _EXTRA_LABELS.get(extra, EXTRA_TABLE_HUMAN_NAMES.get(extra, extra))
            box = QCheckBox(label)
            box.setChecked(extra in on_by_default)
            self._extra_boxes[extra] = box
            extras_layout.addWidget(box, 1 + idx // 2, idx % 2)
        layout.addWidget(self._extras_box)
        self._update_extras_enabled()

        # Output path row stays outside the scroll area so it's always visible.
        path_row = QHBoxLayout()
        path_row.addWidget(QLabel("Output:"))
        self._path_edit = QLineEdit()
        path_row.addWidget(self._path_edit, 1)
        browse = QPushButton("Browse…")
        browse.clicked.connect(self._browse)
        path_row.addWidget(browse)
        outer.addLayout(path_row)

        # OK/Cancel.
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self._on_accept)
        buttons.rejected.connect(self.reject)
        outer.addWidget(buttons)

        self._update_path_hint()

    # --- Helpers ----------------------------------------------------------

    def _set_all(self, boxes, state: bool) -> None:
        for box in boxes.values():
            if box.isEnabled():
                box.setChecked(state)

    def _select_only(self, boxes, target_keys) -> None:
        """Tick exactly the boxes whose dict-key is in *target_keys*."""
        for key, box in boxes.items():
            if box.isEnabled():
                box.setChecked(key in target_keys)

    def _select_critical_extras(self) -> None:
        critical = {"ioc_hits", "findings", "accounts", "source_files"}
        for name, box in self._extra_boxes.items():
            box.setChecked(name in critical)

    def _update_extras_enabled(self) -> None:
        """Extras only flow into the XLSX backend right now."""
        enabled = self.selected_format == "xlsx" and self._has_store_extras
        self._extras_box.setEnabled(enabled)
        tooltip = (
            "Disponible solo con formato Excel (.xlsx)."
            if self.selected_format != "xlsx"
            else "Estos datos se incluyen como hojas adicionales en el Excel."
        )
        self._extras_box.setToolTip(tooltip)

    def _update_path_hint(self) -> None:
        if self.selected_format == "csv":
            self._path_edit.setPlaceholderText("Folder to write CSV files into…")
        elif self.selected_format == "json":
            self._path_edit.setPlaceholderText("…/webforensics.json")
        elif self.selected_format == "pdf":
            self._path_edit.setPlaceholderText("…/webforensics.pdf")
        elif self.selected_format == "xlsx":
            self._path_edit.setPlaceholderText("…/webforensics.xlsx")
        else:
            self._path_edit.setPlaceholderText("…/webforensics.html")

    def _browse(self) -> None:
        if self.selected_format == "csv":
            path = QFileDialog.getExistingDirectory(self, "Select output folder")
        else:
            ext_map = {"html": ".html", "json": ".json", "pdf": ".pdf",
                       "case": ".jsonld", "xlsx": ".xlsx"}
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
        from PyQt5.QtWidgets import QMessageBox
        if not self._path_edit.text().strip():
            QMessageBox.warning(self, "Falta la ruta", "Selecciona dónde guardar el reporte.")
            return
        if not self.selected_kinds and not self.selected_extras:
            QMessageBox.warning(self, "Sin selección", "Marca al menos una sección a exportar.")
            return
        if self._profile_boxes and not self.selected_profile_ids:
            QMessageBox.warning(self, "Sin perfiles", "Marca al menos un perfil a exportar.")
            return
        self.accept()
