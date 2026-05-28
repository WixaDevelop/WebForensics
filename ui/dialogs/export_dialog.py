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
from typing import Iterable, Optional

import re

from PyQt5.QtCore import QSettings, QStandardPaths, Qt
from PyQt5.QtWidgets import (
    QButtonGroup,
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
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
    "xlsx": "Excel (.xlsx) — versión técnica, una hoja por artefacto con resumen y glosario",
    "xlsx_review": "Excel (.xlsx) — versión de revisión, columnas y valores traducidos a español plano + guía de lectura",
    "xlsx_dummy": "Excel (.xlsx) — versión for dummies (formato MAI-TRAB-NAVEGADORES — 7 hojas: Historial / Descargas / Credenciales / Autocompletado / Busquedas + Snapshots)",
    "csv": "CSV — un archivo por artefacto, en una carpeta",
    "json": "JSON — documento único",
    "html": "HTML — reporte único",
    "pdf": "PDF — reporte único",
    "case": "CASE / UCO — formato de intercambio forense NIST",
}


# ---------------------------------------------------------------------------
# Convención del path / nombre de archivo
# ---------------------------------------------------------------------------

# Patrón estándar del directorio raíz de los reportes. El usuario puede
# sobrescribirlo desde el campo del diálogo.
_DEFAULT_BASE_FOLDER_NAME = "MAI-TRAB-NAVEGADORES"

# Etiqueta que va al medio del nombre de archivo: "<sujeto>-<TIPO>-<seq>.<ext>"
_DEFAULT_REPORT_TYPE = "Navegadores"

# Nombres-clave para QSettings (la última Caso / Sujeto / Secuencia / Base
# que usó el analista quedan persistidos para que la siguiente exportación
# arranque sugiriendo lo mismo).
_SETTINGS_GROUP = "ExportNamingConvention"


def _slugify(value: str) -> str:
    """Limpia espacios y caracteres no aptos para nombre de carpeta o archivo."""
    if not value:
        return ""
    cleaned = re.sub(r"[<>:\"/\\|?*\x00-\x1f]", "", value)
    cleaned = cleaned.strip().replace(" ", "_")
    return cleaned

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
            btn.toggled.connect(self._rebuild_path_from_convention)
        layout.addWidget(fmt_box)

        # Convención de archivo — caso/sujeto/secuencia + base folder.
        # Auto-genera el path siguiendo el patrón:
        #   <base>\<caso>\<sujeto>\<sujeto>-Navegadores-<seq>.<ext>
        conv_box = QGroupBox("Convención de archivo")
        conv_layout = QFormLayout(conv_box)
        settings = QSettings("WixaDevelop", "WebForensics")
        settings.beginGroup(_SETTINGS_GROUP)

        default_desktop = QStandardPaths.writableLocation(QStandardPaths.DesktopLocation)
        default_base = settings.value(
            "base_folder",
            str(Path(default_desktop) / _DEFAULT_BASE_FOLDER_NAME),
        )
        last_case = settings.value("caso", "")
        last_subject = settings.value("sujeto", "")
        last_seq = settings.value("secuencia", "001")
        last_report_type = settings.value("report_type", _DEFAULT_REPORT_TYPE)
        settings.endGroup()

        self._base_edit = QLineEdit(default_base)
        base_row = QHBoxLayout()
        base_row.addWidget(self._base_edit, 1)
        browse_base = QPushButton("…")
        browse_base.setFixedWidth(32)
        browse_base.setToolTip("Elegir la carpeta raíz")
        browse_base.clicked.connect(self._browse_base_folder)
        base_row.addWidget(browse_base)
        base_widget = QWidget()
        base_widget.setLayout(base_row)
        conv_layout.addRow("Carpeta raíz:", base_widget)

        self._case_edit = QLineEdit(last_case)
        self._case_edit.setPlaceholderText("Ej: 001-001")
        conv_layout.addRow("Caso:", self._case_edit)

        self._subject_edit = QLineEdit(last_subject)
        self._subject_edit.setPlaceholderText("Ej: fquispe_mailamericas")
        conv_layout.addRow("Sujeto:", self._subject_edit)

        self._report_type_edit = QLineEdit(last_report_type)
        self._report_type_edit.setPlaceholderText("Ej: Navegadores")
        conv_layout.addRow("Tipo de reporte:", self._report_type_edit)

        self._seq_edit = QLineEdit(last_seq)
        self._seq_edit.setPlaceholderText("Ej: 001")
        self._seq_edit.setMaxLength(8)
        conv_layout.addRow("Secuencia:", self._seq_edit)

        # Update the path whenever any of these change.
        for w_ in (self._base_edit, self._case_edit, self._subject_edit,
                   self._report_type_edit, self._seq_edit):
            w_.textChanged.connect(self._rebuild_path_from_convention)

        layout.addWidget(conv_box)

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
        # If the analyst already had last-used Caso + Sujeto, populate the
        # path automatically so they can just click OK.
        self._rebuild_path_from_convention()

    # --- Helpers ----------------------------------------------------------

    def _ext_for_format(self) -> str:
        ext_map = {"html": ".html", "json": ".json", "pdf": ".pdf",
                   "case": ".jsonld", "xlsx": ".xlsx", "xlsx_review": ".xlsx", "xlsx_dummy": ".xlsx",
                   "csv": ""}
        return ext_map.get(self.selected_format, ".xlsx")

    def _suggested_path_from_convention(self) -> Optional[Path]:
        """Construct the suggested output path from the convention fields.

        Pattern: ``<base>\\<caso>\\<sujeto>\\<sujeto>-<tipo>-<seq>.<ext>``
        Returns ``None`` when essential fields are missing (so we don't
        clobber whatever the user already typed in the path edit).

        For the CSV format the file extension is empty and the output is
        expected to be a folder — in that case we suggest a folder named
        ``<sujeto>-<tipo>-<seq>`` inside the same parent layout.
        """
        base = self._base_edit.text().strip()
        case = _slugify(self._case_edit.text())
        subject = _slugify(self._subject_edit.text())
        report = _slugify(self._report_type_edit.text()) or _DEFAULT_REPORT_TYPE
        seq = _slugify(self._seq_edit.text())
        if not base or not case or not subject or not seq:
            return None
        leaf_name = f"{subject}-{report}-{seq}"
        ext = self._ext_for_format()
        full = Path(base) / case / subject / (leaf_name + ext)
        return full

    def _rebuild_path_from_convention(self) -> None:
        """Refresh the output-path field when any convention input changes."""
        suggested = self._suggested_path_from_convention()
        if suggested is not None:
            self._path_edit.setText(str(suggested))

    def _browse_base_folder(self) -> None:
        current = self._base_edit.text().strip() or QStandardPaths.writableLocation(
            QStandardPaths.DesktopLocation
        )
        folder = QFileDialog.getExistingDirectory(
            self, "Seleccionar carpeta raíz para los reportes", current,
        )
        if folder:
            self._base_edit.setText(folder)

    def _persist_convention(self) -> None:
        """Save the last-used convention fields for next time."""
        settings = QSettings("WixaDevelop", "WebForensics")
        settings.beginGroup(_SETTINGS_GROUP)
        settings.setValue("base_folder", self._base_edit.text().strip())
        settings.setValue("caso", self._case_edit.text().strip())
        settings.setValue("sujeto", self._subject_edit.text().strip())
        settings.setValue("report_type", self._report_type_edit.text().strip())
        settings.setValue("secuencia", self._seq_edit.text().strip())
        settings.endGroup()

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
        """Extras only flow into the XLSX (technical / review) backends.

        The 'for dummies' XLSX has a fixed 7-sheet layout that does NOT
        carry extras — so the box gets disabled when that format is
        selected.
        """
        accepts_extras = self.selected_format in ("xlsx", "xlsx_review")
        enabled = accepts_extras and self._has_store_extras
        self._extras_box.setEnabled(enabled)
        if self.selected_format == "xlsx_dummy":
            tooltip = (
                "El formato 'for dummies' tiene un layout fijo de 7 hojas "
                "(Historial, Descargas, Credenciales, Autocompletado, Busquedas + "
                "Snapshots) — las tablas extras no se incluyen."
            )
        elif not accepts_extras:
            tooltip = "Disponible solo con formato Excel (.xlsx)."
        else:
            tooltip = "Estos datos se incluyen como hojas adicionales en el Excel."
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
        elif self.selected_format == "xlsx_review":
            self._path_edit.setPlaceholderText("…/webforensics-revision.xlsx")
        elif self.selected_format == "xlsx_dummy":
            self._path_edit.setPlaceholderText("…/<sujeto>-Navegadores-001.xlsx")
        else:
            self._path_edit.setPlaceholderText("…/webforensics.html")

    def _browse(self) -> None:
        if self.selected_format == "csv":
            path = QFileDialog.getExistingDirectory(self, "Select output folder")
        else:
            ext_map = {"html": ".html", "json": ".json", "pdf": ".pdf",
                       "case": ".jsonld", "xlsx": ".xlsx", "xlsx_review": ".xlsx", "xlsx_dummy": ".xlsx"}
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
        # Auto-create the parent directory tree the convention implies so
        # the analyst doesn't have to mkdir <base>\<caso>\<sujeto>\ by hand.
        out_path = self.output_path
        try:
            parent = out_path if self.selected_format == "csv" else out_path.parent
            parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            QMessageBox.critical(self, "Carpeta inválida",
                                 f"No pude crear la carpeta {parent}:\n{exc}")
            return
        # Remember Caso / Sujeto / Secuencia for next time.
        self._persist_convention()
        self.accept()
