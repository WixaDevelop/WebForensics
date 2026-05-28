"""Main application window — second iteration.

Compared to the v1 window, this one:

* Talks to a :class:`SessionStore` instead of holding profile bundles in
  memory, so analyses with millions of artifacts stay responsive.
* Has a dedicated Timeline tab fed by the ``events`` view.
* Has a Charts tab for activity overview.
* Has a detail panel under each artifact table.
* Has a toolbar with icons + dark/light theme toggle.
* Records every consequential action to the audit log.
* Supports save/open ``.wfs`` sessions.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Optional

from PyQt5.QtCore import QObject, Qt, QThread, pyqtSignal
from PyQt5.QtGui import QKeySequence
from PyQt5.QtWidgets import (
    QAction,
    QApplication,
    QFileDialog,
    QLabel,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QSplitter,
    QStatusBar,
    QStyle,
    QTabWidget,
    QToolBar,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from browsers.base import BrowserProfile
from controller import ForensicsController
from data.models import ARTIFACT_KINDS, ProfileBundle
from data.session import Session
from data.store import SessionStore
from exporters import EXPORTERS
from ui.dialogs.about_dialog import AboutDialog
from ui.dialogs.audit_dialog import AuditDialog
from ui.dialogs.bitlocker_dialog import BitLockerCredentialsDialog
from ui.dialogs.diff_dialog import DiffDialog
from ui.dialogs.export_dialog import ExportDialog
from ui.dialogs.folder_scan_dialog import FolderScanResultDialog
from ui.dialogs.ioc_dialog import IOCDialog
from ui.dialogs.profile_dialog import ProfileDialog
from ui.i18n import current_locale, on_change as on_locale_change, set_locale, tr
from ui.theme import dark_palette, light_palette
from ui.widgets.charts_view import ChartsView
from ui.widgets.data_table import DataTable
from ui.widgets.detail_panel import DetailPanel
from ui.widgets.findings_view import FindingsView
from ui.widgets.global_search import GlobalSearchDialog
from ui.widgets.network_graph_view import NetworkGraphView
from ui.widgets.search_terms_view import SearchTermsView
from ui.widgets.timeline_view import TimelineView
from utils.audit import AuditLog

logger = logging.getLogger(__name__)


def _kind_label(kind: str) -> str:
    """Turn ``cache_entries`` into ``Cache Entries`` for the UI."""
    return kind.replace("_", " ").title()


# ---------------------------------------------------------------------------
# Background worker — same shape as v1 but feeds the store directly
# ---------------------------------------------------------------------------


class _ExtractWorker(QObject):
    """Extracts profiles in the background and ingests each one as it lands."""

    progress = pyqtSignal(str)
    profile_ingested = pyqtSignal(int, object)  # (profile_id, ProfileBundle metadata)
    all_done = pyqtSignal()
    failed = pyqtSignal(str)

    def __init__(
        self,
        controller: ForensicsController,
        store: SessionStore,
        profiles: list[BrowserProfile],
    ) -> None:
        super().__init__()
        self._controller = controller
        self._store = store
        self._profiles = profiles

    def run(self) -> None:
        try:
            for profile in self._profiles:
                started = time.perf_counter()
                self.progress.emit(f"Extracting {profile.browser} — {profile.name}")
                bundle = self._controller.extract(profile)
                profile_id = self._store.ingest_bundle(bundle)
                elapsed = time.perf_counter() - started
                self.profile_ingested.emit(profile_id, bundle)
                counts = bundle.summary()
                total = sum(counts.values())
                self.progress.emit(
                    f"  {profile.browser} — {profile.name}: {total} items in {elapsed:.1f}s"
                )
        except Exception as exc:  # noqa: BLE001 — surface to UI
            logger.exception("Extraction failed")
            self.failed.emit(str(exc))
        finally:
            self.all_done.emit()


class _ImageWorker(QObject):
    """Streams profiles out of a forensic image, ingesting each as it lands."""

    progress = pyqtSignal(str)
    profile_ingested = pyqtSignal(int, object)
    diagnostic_ready = pyqtSignal(object)
    all_done = pyqtSignal()
    failed = pyqtSignal(str)

    def __init__(
        self,
        controller: ForensicsController,
        store: SessionStore,
        image_path: str,
        bitlocker_credentials=None,
    ) -> None:
        super().__init__()
        self._controller = controller
        self._store = store
        self._image_path = image_path
        self._bitlocker_credentials = bitlocker_credentials
        self._yielded = 0

    def run(self) -> None:
        try:
            for bundle in self._controller.extract_image(
                self._image_path,
                progress=self.progress.emit,
                on_diagnostic=self.diagnostic_ready.emit,
                bitlocker_credentials=self._bitlocker_credentials,
            ):
                profile_id = self._store.ingest_bundle(
                    bundle, source="image", image_path=self._image_path
                )
                self._yielded += 1
                self.profile_ingested.emit(profile_id, bundle)
        except Exception as exc:  # noqa: BLE001 — surface to UI
            logger.exception("Image extraction failed")
            self.failed.emit(str(exc))
        finally:
            self.all_done.emit()


# ---------------------------------------------------------------------------
# Main window
# ---------------------------------------------------------------------------


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("WebForensics")
        self.resize(1280, 800)

        self._controller = ForensicsController()
        self._session = Session.new()
        self._audit = AuditLog()
        self._is_dark = False

        self._build_toolbar_and_menus()
        self._build_status_bar()
        self._build_central()
        self._attach_session()
        self._update_action_state()

    # --- Construction -----------------------------------------------------

    def _icon(self, sp: int):
        return self.style().standardIcon(sp)

    def _build_toolbar_and_menus(self) -> None:
        # Toolbar
        tb = QToolBar("Main")
        tb.setMovable(False)
        tb.setIconSize(tb.iconSize() * 1.1)
        self.addToolBar(tb)
        self._toolbar = tb

        self._act_autodetect = QAction(self._icon(QStyle.SP_BrowserReload), tr("Auto-detect"), self)
        self._act_autodetect.setShortcut("Ctrl+R")
        self._act_autodetect.setToolTip(tr("Scan default install locations for browser profiles"))
        self._act_autodetect.triggered.connect(self._auto_detect_all)
        tb.addAction(self._act_autodetect)

        self._act_open_profile = QAction(self._icon(QStyle.SP_DirOpenIcon), tr("Open profile…"), self)
        self._act_open_profile.setShortcut("Ctrl+O")
        self._act_open_profile.triggered.connect(self._open_profile_dialog)
        tb.addAction(self._act_open_profile)

        self._act_scan_folder = QAction(self._icon(QStyle.SP_DirLinkIcon), tr("Auto-detect in folder…"), self)
        self._act_scan_folder.setShortcut("Ctrl+Shift+O")
        self._act_scan_folder.setToolTip(tr("Recursively scan a folder for browser profiles"))
        self._act_scan_folder.triggered.connect(self._scan_folder_dialog)
        tb.addAction(self._act_scan_folder)

        self._act_open_image = QAction(self._icon(QStyle.SP_DriveHDIcon), tr("Open image (E01)…"), self)
        self._act_open_image.setToolTip(tr("Open a forensic image (E01 / .dd / .img)"))
        self._act_open_image.triggered.connect(self._open_image_dialog)
        tb.addAction(self._act_open_image)

        tb.addSeparator()
        self._act_search = QAction(self._icon(QStyle.SP_FileDialogContentsView), tr("Search"), self)
        self._act_search.setShortcut("Ctrl+F")
        self._act_search.triggered.connect(self._open_global_search)
        tb.addAction(self._act_search)

        self._act_ioc = QAction(self._icon(QStyle.SP_MessageBoxWarning), tr("IOCs…"), self)
        self._act_ioc.setToolTip("Load and match Indicators of Compromise")
        self._act_ioc.triggered.connect(self._open_ioc_dialog)
        tb.addAction(self._act_ioc)

        self._act_export = QAction(self._icon(QStyle.SP_DialogSaveButton), tr("Export…"), self)
        self._act_export.setShortcut("Ctrl+E")
        self._act_export.triggered.connect(self._export_dialog)
        tb.addAction(self._act_export)

        tb.addSeparator()
        self._act_save = QAction(self._icon(QStyle.SP_DialogSaveButton), tr("Save session"), self)
        self._act_save.setShortcut(QKeySequence.Save)
        self._act_save.triggered.connect(self._save_session)
        tb.addAction(self._act_save)

        self._act_open_session = QAction(self._icon(QStyle.SP_DialogOpenButton), tr("Open session"), self)
        self._act_open_session.triggered.connect(self._open_session)
        tb.addAction(self._act_open_session)

        tb.addSeparator()
        self._act_theme = QAction(self._icon(QStyle.SP_DesktopIcon), tr("Dark theme"), self)
        self._act_theme.setCheckable(True)
        self._act_theme.triggered.connect(self._toggle_theme)
        tb.addAction(self._act_theme)

        # Language toggle — flip between EN and ES with a single click.
        self._act_lang = QAction(self._icon(QStyle.SP_FileIcon), "ES / EN", self)
        self._act_lang.setToolTip(tr("Language"))
        self._act_lang.triggered.connect(self._toggle_language)
        tb.addAction(self._act_lang)

        # Menus mirror the toolbar so screen readers / accelerators still work.
        mb = self.menuBar()
        self._menubar = mb
        file_menu = mb.addMenu(tr("&File"))
        self._file_menu = file_menu
        for act in (
            self._act_autodetect, self._act_open_profile, self._act_scan_folder,
            self._act_open_image,
            None,
            self._act_export, self._act_save, self._act_open_session,
        ):
            if act is None:
                file_menu.addSeparator()
            else:
                file_menu.addAction(act)
        file_menu.addSeparator()
        self._act_quit = QAction(tr("E&xit"), self)
        self._act_quit.setShortcut("Ctrl+Q")
        self._act_quit.triggered.connect(self.close)
        file_menu.addAction(self._act_quit)

        tools_menu = mb.addMenu(tr("&Tools"))
        self._tools_menu = tools_menu
        tools_menu.addAction(self._act_search)
        tools_menu.addAction(self._act_ioc)
        self._act_audit = QAction(tr("Audit log…"), self)
        self._act_audit.triggered.connect(self._show_audit)
        tools_menu.addAction(self._act_audit)
        self._act_diff = QAction(tr("Compare sessions…"), self)
        self._act_diff.triggered.connect(self._show_diff)
        tools_menu.addAction(self._act_diff)
        self._act_os = QAction(tr("Collect OS artifacts"), self)
        self._act_os.triggered.connect(self._collect_os_artifacts)
        tools_menu.addAction(self._act_os)
        self._act_enrich = QAction(tr("Enrich domains"), self)
        self._act_enrich.triggered.connect(self._enrich_domains)
        tools_menu.addAction(self._act_enrich)

        view_menu = mb.addMenu(tr("&View"))
        self._view_menu = view_menu
        view_menu.addAction(self._act_theme)

        help_menu = mb.addMenu(tr("&Help"))
        self._help_menu = help_menu
        self._act_about = QAction(tr("&About"), self)
        self._act_about.triggered.connect(self._show_about)
        help_menu.addAction(self._act_about)

        # Re-apply translations whenever locale flips at runtime.
        on_locale_change(self._apply_translations)

    def _build_status_bar(self) -> None:
        self._status = QStatusBar()
        self.setStatusBar(self._status)
        self._progress = QProgressBar()
        self._progress.setRange(0, 0)
        self._progress.hide()
        self._status.addPermanentWidget(self._progress)
        self._summary_label = QLabel("Ready")
        self._status.addPermanentWidget(self._summary_label)

    def _build_central(self) -> None:
        splitter = QSplitter(Qt.Horizontal)
        self.setCentralWidget(splitter)

        # Left tree
        self._tree = QTreeWidget()
        self._tree.setHeaderLabels(["Profile", "Items"])
        self._tree.setColumnWidth(0, 220)
        self._tree.itemSelectionChanged.connect(self._on_tree_selection)
        splitter.addWidget(self._tree)

        # Right side: tabs over each artifact + Timeline + Charts.
        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(8, 8, 8, 8)
        self._tabs = QTabWidget()
        right_layout.addWidget(self._tabs, 1)

        # Detail panel sits under whichever tab is active.
        self._detail = DetailPanel()
        self._detail.setMaximumHeight(220)
        right_layout.addWidget(self._detail)
        splitter.addWidget(right)
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([280, 1000])

        # Artifact tabs (one DataTable each).
        self._tables: dict[str, DataTable] = {}
        for kind in ARTIFACT_KINDS:
            table = DataTable(kind, self)
            table.row_selected.connect(self._detail.show_record)
            self._tables[kind] = table
            self._tabs.addTab(table, tr(_kind_label(kind)))

        # Timeline tab — already aware of the store.
        self._timeline = TimelineView(self)
        self._tabs.addTab(self._timeline, tr("Timeline"))

        # Search-terms tab.
        self._search_terms = SearchTermsView(self)
        self._tabs.addTab(self._search_terms, tr("Searches"))

        # Charts tab.
        self._charts = ChartsView(self)
        self._tabs.addTab(self._charts, tr("Charts"))

        # Findings tab (anti-forensics).
        self._findings = FindingsView(self)
        self._tabs.addTab(self._findings, tr("Findings"))

        # Network graph.
        self._graph = NetworkGraphView(self)
        self._tabs.addTab(self._graph, tr("Graph"))

        self._tabs.currentChanged.connect(self._on_tab_changed)

    def _attach_session(self) -> None:
        """Re-bind every widget to whatever the current session's store is."""
        store = self._session.store
        for table in self._tables.values():
            table.attach(store)
            # When the user tags a row in one table, refresh every table's
            # decoration cache so the blue highlight shows up everywhere.
            try:
                table.tagged.disconnect()
            except TypeError:
                pass
            table.tagged.connect(self._on_tags_changed)
        self._timeline.attach(store)
        self._search_terms.attach(store)
        self._charts.attach(store)
        self._findings.attach(store)
        self._graph.attach(store)
        self._refresh_tree()
        title = self._session.path.name if self._session.path else "untitled"
        self.setWindowTitle(f"WebForensics — {title}")

    # --- Actions: discovery & extraction ----------------------------------

    def _auto_detect_all(self) -> None:
        profiles = self._controller.discover_profiles()
        if not profiles:
            QMessageBox.information(
                self,
                "No profiles found",
                "No Chrome, Edge or Firefox profiles were detected on this system.",
            )
            return
        self._start_extraction(profiles)

    def _open_profile_dialog(self) -> None:
        dialog = ProfileDialog(self._controller, self)
        if dialog.exec_() != ProfileDialog.Accepted:
            return
        if dialog.selected_profiles:
            self._start_extraction(dialog.selected_profiles)

    def _scan_folder_dialog(self) -> None:
        """Recursively scan a user-chosen folder for browser profiles.

        Useful for mounted forensic images, external drives, evidence
        dumps, or any tree that doesn't match the standard ``%APPDATA%``
        layout. We reuse the same extraction worker as auto-detect.
        """
        folder = QFileDialog.getExistingDirectory(
            self, tr("Select folder to scan"),
        )
        if not folder:
            return

        # If the user picked a Windows drive root and we're running as
        # admin, offer to enumerate VSS snapshots on that volume so the
        # scan also covers historical states of the same profiles.
        include_vss = False
        try:
            from forensics.vss_local import check_shadow_availability
            avail = check_shadow_availability(folder)
        except ImportError:
            avail = None
        if avail and avail.shadows:
            reply = QMessageBox.question(
                self,
                tr("Include VSS shadow copies?"),
                tr(
                    "Windows reports {n} Volume Shadow Copy/copies on {drive}.\n"
                    "These are point-in-time snapshots that may contain pristine "
                    "copies of browser profiles from earlier dates — useful when "
                    "the live profile has been wiped or rolled forward.\n\n"
                    "Include them in the scan? (one extra pass per snapshot)"
                ).format(n=len(avail.shadows), drive=avail.drive or folder),
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.Yes,
            )
            include_vss = (reply == QMessageBox.Yes)

        self._summary_label.setText(tr("Scanning folder…"))
        QApplication.processEvents()
        try:
            profiles = self._controller.discover_profiles_in_folder(
                folder, progress=self._status.showMessage, include_vss=include_vss,
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("Folder scan failed")
            QMessageBox.critical(self, tr("Folder scan failed"), str(exc))
            self._summary_label.setText(self._global_summary_text())
            return
        if not profiles:
            QMessageBox.information(
                self,
                tr("No profiles found"),
                tr(
                    "No browser profiles were detected anywhere under:\n\n{folder}\n\n"
                    "The scanner looked for Chromium (History) and "
                    "Firefox/Tor (places.sqlite) signature files."
                ).format(folder=folder),
            )
            self._summary_label.setText(self._global_summary_text())
            return

        # Let the analyst review and uncheck noise (embedded WebView,
        # CEF caches, profiles they don't care about) before extraction.
        review = FolderScanResultDialog(profiles, folder, self)
        if review.exec_() != FolderScanResultDialog.Accepted:
            self._summary_label.setText(self._global_summary_text())
            return
        selected = review.selected_profiles
        if not selected:
            self._summary_label.setText(self._global_summary_text())
            return

        self._audit.record(
            "folder_scan",
            target=folder,
            found=len(profiles),
            extracted=len(selected),
            profiles=[f"{p.browser}::{p.path}" for p in selected],
        )
        self._start_extraction(selected)

    def _open_image_dialog(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Open forensic image",
            "",
            "Forensic images (*.E01 *.e01 *.dd *.img *.raw *.bin);;All files (*.*)",
        )
        if not path:
            return
        self._start_image_extraction(Path(path))

    def _start_image_extraction(self, image_path: Path) -> None:
        from forensics import ForensicImageError, probe_image
        from utils.hashing import sha256_file

        # Quick existence + small-hash check so we audit *what* was opened.
        try:
            digest = sha256_file(image_path)
        except OSError as exc:
            QMessageBox.critical(self, "Open failed", str(exc))
            return

        # Cheap up-front probe so we can prompt for BitLocker credentials
        # before kicking off the long-running extraction.
        bitlocker_credentials = None
        try:
            probe = probe_image(image_path)
        except ForensicImageError as exc:
            QMessageBox.critical(self, tr("Open failed"), str(exc))
            return
        if probe.bitlocker_partitions:
            # Always ask for credentials first — even when libbde says the
            # format is incompatible. Reasons:
            #   (1) Our native parser may unlock formats libbde can't.
            #   (2) Even if both backends fail, having the analyst's key in
            #       hand makes the post-fail fallback (auto-mount + Windows
            #       BitLocker) a single extra click.
            dialog = BitLockerCredentialsDialog(
                probe.bitlocker_partitions, self,
                libbde_compatible=not probe.libbde_incompatible,
            )
            if dialog.exec_() != BitLockerCredentialsDialog.Accepted:
                return
            bitlocker_credentials = dialog.credentials
            self._audit.record(
                "bitlocker_prompt",
                target=str(image_path),
                partitions=[p.addr for p in probe.bitlocker_partitions],
                supplied=bool(bitlocker_credentials),
                libbde_compatible=not probe.libbde_incompatible,
            )

        self._audit.record("open_image", target=str(image_path), sha256=digest)
        # Stash the path + creds so the post-extraction fallback (auto-mount
        # with Windows BitLocker) can re-launch against the same image.
        self._current_image_path = image_path
        self._current_image_creds = bitlocker_credentials
        self._progress.show()
        self._summary_label.setText(f"Reading image {image_path.name}…")
        self._tree.setEnabled(False)
        self._set_actions_enabled(False)

        self._thread = QThread(self)
        self._worker = _ImageWorker(
            self._controller, self._session.store, str(image_path),
            bitlocker_credentials=bitlocker_credentials,
        )
        self._worker.moveToThread(self._thread)
        self._image_diagnostic = None  # populated by the diagnostic signal
        self._thread.started.connect(self._worker.run)
        self._worker.progress.connect(lambda msg: self._status.showMessage(msg))
        self._worker.profile_ingested.connect(self._on_profile_ingested)
        self._worker.diagnostic_ready.connect(self._on_image_diagnostic)
        self._worker.failed.connect(self._on_extraction_failed)
        self._worker.all_done.connect(self._on_image_extraction_done)
        self._thread.start()

    def _start_extraction(self, profiles: list[BrowserProfile]) -> None:
        self._progress.show()
        self._summary_label.setText(f"Extracting {len(profiles)} profile(s)…")
        self._tree.setEnabled(False)
        self._set_actions_enabled(False)

        self._audit.record(
            "extract_start",
            target=",".join(str(p.path) for p in profiles),
            count=len(profiles),
        )

        self._thread = QThread(self)
        self._worker = _ExtractWorker(self._controller, self._session.store, profiles)
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.progress.connect(lambda msg: self._status.showMessage(msg))
        self._worker.profile_ingested.connect(self._on_profile_ingested)
        self._worker.failed.connect(self._on_extraction_failed)
        self._worker.all_done.connect(self._on_extraction_done)
        self._thread.start()

    def _on_profile_ingested(self, profile_id: int, bundle: ProfileBundle) -> None:
        # Update the tree (and let visible tabs re-query in the background).
        self._refresh_tree()
        self._audit.record(
            "extract_done",
            target=bundle.path,
            profile_id=profile_id,
            browser=bundle.browser,
            counts=bundle.summary(),
            errors=bundle.errors,
        )

    def _on_extraction_done(self) -> None:
        self._thread.quit()
        self._thread.wait()
        self._thread.deleteLater()
        self._worker.deleteLater()
        self._progress.hide()
        self._tree.setEnabled(True)
        self._set_actions_enabled(True)
        self._summary_label.setText(self._global_summary_text())
        # Auto-refresh the timeline/charts since they don't know about new data.
        self._timeline.refresh()
        self._charts.refresh()

    def _try_auto_mount_bitlocker(self, image_path: Path, probe) -> bool:
        """Offer the auto-mount + Windows BitLocker unlock workflow.

        Returns True when the workflow handled the analysis (kicked off
        a folder scan on the unlocked drive). False means the analyst
        declined or the auto-mount failed — caller should fall through
        to the legacy "scan readable partitions" path.
        """
        from forensics.auto_mount import (
            auto_unlock_image, find_mounter, is_admin,
            ARSENAL_DOWNLOAD, OSFMOUNT_DOWNLOAD,
        )
        from PyQt5.QtWidgets import QInputDialog, QLineEdit
        from PyQt5.QtCore import QUrl
        from PyQt5.QtGui import QDesktopServices

        size_gb = sum(p.byte_length for p in probe.bitlocker_partitions) / (1024 ** 3)
        admin = is_admin()
        mounter = find_mounter()

        # Build a single dialog that explains the situation and offers
        # the right next action depending on what's available locally.
        if mounter is not None and admin:
            # Best case: we can do the whole flow in-app right now.
            primary_btn = QMessageBox.Yes
            text = tr(
                "Esta imagen tiene una partición BitLocker ({size:.1f} GiB) con "
                "formato Win11 22H2+ que libbde no soporta todavía.\n\n"
                "WebForensics puede montar la imagen y desbloquearla por ti "
                "usando {mounter} + Windows BitLocker. Solo necesitas la "
                "recovery key.\n\n"
                "¿Continuar?"
            ).format(size=size_gb, mounter=mounter.name)
            buttons = QMessageBox.Yes | QMessageBox.No
        elif mounter is None and admin:
            # Admin but no mounter: explain and offer the download link.
            text = tr(
                "Esta imagen tiene una partición BitLocker ({size:.1f} GiB) con "
                "formato Win11 22H2+ que libbde no soporta todavía.\n\n"
                "Para que WebForensics pueda desbloquearla por ti, necesitas "
                "instalar Arsenal Image Mounter (gratis, ~10 MB).\n\n"
                "¿Abrir la página de descarga ahora?"
            ).format(size=size_gb)
            buttons = QMessageBox.Yes | QMessageBox.No
            primary_btn = QMessageBox.Yes
        elif mounter is not None and not admin:
            text = tr(
                "Esta imagen tiene una partición BitLocker ({size:.1f} GiB) que "
                "WebForensics puede desbloquear usando {mounter}, PERO esta "
                "instancia de la app NO está corriendo como Administrador.\n\n"
                "Cierra WebForensics y vuelve a abrirlo con clic derecho → "
                "'Ejecutar como administrador', después reintenta.\n\n"
                "¿Continuar el análisis con las particiones legibles (sin BitLocker)?"
            ).format(size=size_gb, mounter=mounter.name)
            buttons = QMessageBox.Yes | QMessageBox.No
            primary_btn = QMessageBox.No
        else:
            text = tr(
                "Esta imagen tiene una partición BitLocker ({size:.1f} GiB) con "
                "formato Win11 22H2+ que libbde no soporta todavía.\n\n"
                "Para desbloquearla automáticamente desde la app necesitas:\n"
                "  • Permisos de Administrador (clic derecho → Ejecutar como admin)\n"
                "  • Arsenal Image Mounter instalado (gratis en arsenalrecon.com)\n\n"
                "¿Abrir la página de descarga de Arsenal Image Mounter ahora?"
            ).format(size=size_gb)
            buttons = QMessageBox.Yes | QMessageBox.No
            primary_btn = QMessageBox.Yes

        msg = QMessageBox(self)
        msg.setIcon(QMessageBox.Question)
        msg.setWindowTitle(tr("BitLocker — desbloqueo automático"))
        msg.setText(text)
        msg.setStandardButtons(buttons)
        msg.setDefaultButton(primary_btn)
        reply = msg.exec_()

        # Branch on what the user picked + what we have available.
        if mounter is None and reply == QMessageBox.Yes:
            QDesktopServices.openUrl(QUrl(ARSENAL_DOWNLOAD))
            QMessageBox.information(self, tr("Instalación"), tr(
                "Se abrió la página de descarga en tu navegador. Después de "
                "instalar Arsenal Image Mounter, vuelve a abrir esta imagen "
                "en WebForensics."
            ))
            self._audit.record("bitlocker_install_prompt", target=str(image_path),
                               tool="Arsenal Image Mounter")
            return True  # We handled the flow; caller should not fall through.

        if not admin or mounter is None or reply != QMessageBox.Yes:
            # User declined, or env not ready. Fall back to scanning the
            # readable parts of the image (or just abort).
            if reply != QMessageBox.Yes:
                # User chose "No" — abort the whole open.
                return True
            return False

        # --- Real auto-mount path: ask for recovery key, then run it. ---
        key, ok = QInputDialog.getText(
            self, tr("Recovery key de BitLocker"),
            tr("Pega la recovery key de 48 dígitos (con o sin guiones):"),
            QLineEdit.Normal, "",
        )
        if not ok or not key.strip():
            return True  # user cancelled
        key = key.strip()

        self._summary_label.setText(tr("Montando y desbloqueando imagen…"))
        QApplication.processEvents()

        try:
            attempt = auto_unlock_image(image_path, recovery_password=key)
        except Exception as exc:  # noqa: BLE001
            logger.exception("Auto-mount failed")
            QMessageBox.critical(self, tr("Auto-mount falló"), str(exc))
            self._summary_label.setText(self._global_summary_text())
            return True

        self._audit.record(
            "bitlocker_automount",
            target=str(image_path),
            success=attempt.success,
            mounter=attempt.mounter_name,
            disk_number=attempt.disk_number,
            drives=attempt.drive_letters,
            unlocked=attempt.unlocked_drives,
            notes=attempt.notes,
        )

        if not attempt.success:
            QMessageBox.critical(self, tr("Auto-mount falló"), attempt.error)
            self._summary_label.setText(self._global_summary_text())
            return True

        # Park the cleanup so we dismount on session close.
        if not hasattr(self, "_pending_unmounts"):
            self._pending_unmounts = []
        if attempt.cleanup is not None:
            self._pending_unmounts.append(attempt.cleanup)

        # Pick the first drive we unlocked (most likely the C:-like main
        # volume) and kick off a recursive folder scan on it.
        target = attempt.unlocked_drives[0] if attempt.unlocked_drives else attempt.drive_letters[0]
        QMessageBox.information(self, tr("Imagen montada"), tr(
            "Imagen montada como disco {disk} con {n} unidad(es) accesible(s): {drives}\n"
            "Voy a escanear {target}\\ en busca de perfiles de navegador."
        ).format(
            disk=attempt.disk_number,
            n=len(attempt.drive_letters),
            drives=", ".join(attempt.drive_letters),
            target=target,
        ))
        # Re-use the existing folder-scan path.
        try:
            profiles = self._controller.discover_profiles_in_folder(
                target + "\\",
                progress=self._status.showMessage,
                include_vss=False,
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("Post-mount folder scan failed")
            QMessageBox.critical(self, tr("Folder scan failed"), str(exc))
            self._summary_label.setText(self._global_summary_text())
            return True
        if not profiles:
            QMessageBox.information(
                self, tr("No profiles found"),
                tr(
                    "No se encontraron perfiles de navegador en {drive}\\ tras "
                    "montar y desbloquear. Puedes intentar 'Auto-detectar en "
                    "carpeta…' manualmente sobre cada partición."
                ).format(drive=target),
            )
            self._summary_label.setText(self._global_summary_text())
            return True

        # Hand off to the existing review + extract path.
        review = FolderScanResultDialog(profiles, target + "\\", self)
        if review.exec_() != FolderScanResultDialog.Accepted:
            self._summary_label.setText(self._global_summary_text())
            return True
        selected = review.selected_profiles
        if not selected:
            self._summary_label.setText(self._global_summary_text())
            return True
        self._start_extraction(selected)
        return True

    def _on_image_diagnostic(self, diagnostic) -> None:
        """Stash the locator diagnostic so we can show it after the run."""
        self._image_diagnostic = diagnostic

    def _on_image_extraction_done(self) -> None:
        """Image-specific completion. Routes to one of three outcomes:

        * Profiles were staged → show normal Ready state.
        * Nothing staged AND BitLocker partitions remained locked → offer
          the auto-mount + Windows BitLocker workflow as fallback.
        * Nothing staged for other reasons → show the diagnostic dialog.
        """
        diag = self._image_diagnostic
        had_results = bool(diag and getattr(diag, "profiles_staged", 0))
        # Did the locator see BitLocker partitions it couldn't unlock?
        unlocked_failed = bool(
            diag
            and getattr(diag, "bitlocker_partitions", None)
            and len(getattr(diag, "bitlocker_unlocked", []))
                < len(getattr(diag, "bitlocker_partitions", []))
        )
        self._on_extraction_done()
        if had_results or diag is None:
            return
        if unlocked_failed:
            self._offer_bitlocker_mount_fallback(diag)
            return
        QMessageBox.warning(
            self,
            tr("No profiles found in image"),
            tr(
                "No browser profiles could be staged from this image.\n\n"
                "Diagnostic details:\n\n{details}"
            ).format(details=diag.to_text()),
        )

    def _offer_bitlocker_mount_fallback(self, diag) -> None:
        """Show a clear next-step dialog when the in-app unlock failed."""
        from forensics.auto_mount import find_mounter, is_admin
        admin = is_admin()
        mounter = find_mounter()
        size_gb = sum(p.byte_length for p in diag.bitlocker_partitions) / (1024 ** 3)
        last_error = diag.bitlocker_failed[-1] if diag.bitlocker_failed else ""

        if admin and mounter is not None:
            txt = tr(
                "El desbloqueo de BitLocker falló desde dentro de la app "
                "({size:.1f} GiB cifrados). El formato es muy reciente y los "
                "backends incluidos (libbde + parser nativo) no lo soportan.\n\n"
                "WebForensics puede ahora montar la imagen con {mounter} y "
                "usar el desbloqueador nativo de Windows con la misma clave "
                "que acabas de ingresar. ¿Continuar con ese flujo?"
            ).format(size=size_gb, mounter=mounter.name)
            reply = QMessageBox.question(
                self, tr("Probar desbloqueo automático con Windows"),
                txt, QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes,
            )
            if reply == QMessageBox.Yes:
                # Re-use the existing auto-mount path with a probe stub
                # made from the locator's already-discovered partitions.
                from types import SimpleNamespace
                stub = SimpleNamespace(
                    bitlocker_partitions=diag.bitlocker_partitions,
                    libbde_incompatible=True,
                    libbde_error=last_error,
                )
                img_path = getattr(self, "_current_image_path", None)
                if img_path is not None:
                    self._try_auto_mount_bitlocker(img_path, stub)
                return
        elif not admin:
            QMessageBox.warning(
                self, tr("Desbloqueo BitLocker falló"),
                tr(
                    "El desbloqueo desde la app falló y no se puede usar el "
                    "flujo de montaje automático porque WebForensics no se "
                    "está ejecutando como Administrador.\n\n"
                    "Cierra la app y vuelve a abrirla con clic derecho → "
                    "'Ejecutar como administrador', después reintenta.\n\n"
                    "Error técnico: {err}"
                ).format(err=last_error[:300]),
            )
            return
        else:
            QMessageBox.warning(
                self, tr("Desbloqueo BitLocker falló"),
                tr(
                    "El desbloqueo desde la app falló. Para usar el flujo de "
                    "montaje automático necesitas instalar Arsenal Image "
                    "Mounter (gratis, ~10 MB) desde arsenalrecon.com/downloads.\n\n"
                    "Error técnico: {err}"
                ).format(err=last_error[:300]),
            )
            return
        # User declined the fallback — show the full diagnostic.
        QMessageBox.warning(
            self, tr("No profiles found in image"),
            tr(
                "No browser profiles could be staged from this image.\n\n"
                "Diagnostic details:\n\n{details}"
            ).format(details=diag.to_text()),
        )

    def _on_extraction_failed(self, message: str) -> None:
        QMessageBox.critical(self, "Extraction failed", message)

    # --- Tree -------------------------------------------------------------

    def _refresh_tree(self) -> None:
        """Rebuild the left tree from the store.

        Profile names from image-staged extractions carry the Windows user
        as a prefix (``<user>/<profile_name>`` — see
        ``ForensicsController.extract_image``). VSS-snapshot-derived
        profiles tack on ``@shadow-...`` suffixes. We parse both so the
        tree shows a clean 3-level layout when there are multiple Windows
        users in the case (Usuario → Navegador → Perfil), or the legacy
        2-level layout when everything came from the same user (or from a
        live extraction without user info).
        """
        self._tree.clear()
        rows = self._session.store.list_profiles()

        # First pass: parse every row into (user, browser, profile_part, snapshot_label).
        parsed: list[dict] = []
        for row in rows:
            full_name = row["name"] or ""
            browser = row["browser"]
            if "/" in full_name:
                user, profile_part = full_name.split("/", 1)
            else:
                user = ""
                profile_part = full_name
            snapshot_label = ""
            if "@shadow-" in profile_part:
                profile_part, snapshot_label = profile_part.split("@shadow-", 1)
            try:
                count = sum(eval(row["summary"]).values()) if row["summary"] else 0  # safe: our JSON
            except Exception:  # noqa: BLE001
                count = 0
            parsed.append({
                "id": int(row["id"]),
                "user": user,
                "browser": browser,
                "profile_part": profile_part,
                "snapshot": snapshot_label,
                "count": count,
                "path": row["path"] or "",
            })

        distinct_users = {p["user"] for p in parsed}
        # Show the user level when the data spans more than one Windows
        # account, OR when there's a single non-empty user (image case
        # with one user) — but skip it for plain live extractions
        # (everything has empty user).
        show_user_level = bool(distinct_users - {""})

        if show_user_level:
            self._build_three_level_tree(parsed)
        else:
            self._build_two_level_tree(parsed)

    def _build_two_level_tree(self, parsed: list[dict]) -> None:
        groups: dict[str, QTreeWidgetItem] = {}
        for p in parsed:
            group = groups.get(p["browser"])
            if group is None:
                group = QTreeWidgetItem(self._tree, [p["browser"], ""])
                font = group.font(0)
                font.setBold(True)
                group.setFont(0, font)
                groups[p["browser"]] = group
                group.setExpanded(True)
            self._add_profile_leaf(group, p)
        # Aggregate browser-level totals.
        for group in groups.values():
            total = sum(int(group.child(i).text(1) or 0)
                        for i in range(group.childCount()))
            group.setText(1, str(total))

    def _build_three_level_tree(self, parsed: list[dict]) -> None:
        # User → Browser → Profile. Bold for users, italic for browsers.
        user_nodes: dict[str, QTreeWidgetItem] = {}
        browser_nodes: dict[tuple[str, str], QTreeWidgetItem] = {}
        for p in parsed:
            user_key = p["user"]
            user_label = user_key or tr("Equipo local")
            user_node = user_nodes.get(user_key)
            if user_node is None:
                user_node = QTreeWidgetItem(self._tree, [user_label, ""])
                font = user_node.font(0)
                font.setBold(True)
                font.setPointSize(font.pointSize() + 1)
                user_node.setFont(0, font)
                user_node.setToolTip(0, tr("Cuenta de Windows: ") + user_label)
                user_nodes[user_key] = user_node
                user_node.setExpanded(True)

            browser_key = (user_key, p["browser"])
            browser_node = browser_nodes.get(browser_key)
            if browser_node is None:
                browser_node = QTreeWidgetItem(user_node, [p["browser"], ""])
                font = browser_node.font(0)
                font.setItalic(True)
                browser_node.setFont(0, font)
                browser_nodes[browser_key] = browser_node
                browser_node.setExpanded(True)
            self._add_profile_leaf(browser_node, p)

        # Aggregate counts up the tree (browser totals + user totals).
        for browser_node in browser_nodes.values():
            total = sum(int(browser_node.child(i).text(1) or 0)
                        for i in range(browser_node.childCount()))
            browser_node.setText(1, str(total))
        for user_node in user_nodes.values():
            total = sum(int(user_node.child(i).text(1) or 0)
                        for i in range(user_node.childCount()))
            user_node.setText(1, str(total))

    def _add_profile_leaf(self, parent_node: QTreeWidgetItem, p: dict) -> None:
        label = p["profile_part"]
        if p["snapshot"]:
            label = f"{label}  ·  snapshot {p['snapshot']}"
        leaf = QTreeWidgetItem(parent_node, [label, str(p["count"])])
        leaf.setData(0, Qt.UserRole, p["id"])
        leaf.setToolTip(0, p["path"])
        if p["snapshot"]:
            # Visual hint that this row is a recovered snapshot rather
            # than the live profile state.
            font = leaf.font(0)
            font.setItalic(True)
            leaf.setFont(0, font)

    def _on_tree_selection(self) -> None:
        items = self._tree.selectedItems()
        if not items:
            return
        profile_id = items[0].data(0, Qt.UserRole)
        pid: Optional[int] = int(profile_id) if profile_id is not None else None
        for table in self._tables.values():
            table.set_profile(pid)
        self._charts.set_profile(pid)
        # Timeline always shows the whole session; that's the point of it.
        self._detail.show_record({})

    def _on_tab_changed(self, _index: int) -> None:
        # When you flip to Timeline, Charts, Searches, Findings or Graph, pull fresh data.
        current = self._tabs.currentWidget()
        if current is self._timeline:
            self._timeline.refresh()
        elif current is self._charts:
            self._charts.refresh()
        elif current is self._search_terms:
            self._search_terms.refresh()
        elif current is self._findings:
            self._findings.refresh()
        elif current is self._graph:
            self._graph.refresh()

    def _on_tags_changed(self) -> None:
        """Refresh every table so the blue tag highlight stays consistent."""
        for table in self._tables.values():
            table.refresh()

    # --- Export, search, sessions ----------------------------------------

    def _export_dialog(self) -> None:
        if self._session.store.row_count("profiles") == 0:
            QMessageBox.information(self, "Nada que exportar", "Carga un perfil primero.")
            return
        # Build the (profile_id, browser, name, total-count) tuples so the
        # dialog can render per-profile checkboxes with element counts.
        profile_rows: list[tuple[int, str, str, int]] = []
        for prof in self._session.store.list_profiles():
            try:
                summary = eval(prof["summary"]) if prof["summary"] else {}  # safe: our JSON dump
            except Exception:  # noqa: BLE001
                summary = {}
            count = sum(int(v) for v in summary.values()) if summary else 0
            profile_rows.append((int(prof["id"]), prof["browser"], prof["name"], count))

        dialog = ExportDialog(self, available_profiles=profile_rows)
        if dialog.exec_() != ExportDialog.Accepted:
            return

        selected_ids = set(dialog.selected_profile_ids) if dialog.selected_profile_ids else None
        bundles = self._reconstruct_bundles(profile_ids=selected_ids)
        exporter_cls = EXPORTERS[dialog.selected_format]
        # Only XLSX consumes the store + extras path today. Other formats
        # use the legacy signature so we don't break their behaviour.
        export_kwargs = {"kinds": dialog.selected_kinds}
        if dialog.selected_format in ("xlsx", "xlsx_review", "xlsx_dummy"):
            export_kwargs["store"] = self._session.store
            export_kwargs["extras"] = dialog.selected_extras
            export_kwargs["profile_ids"] = (
                list(selected_ids) if selected_ids else None
            )
        try:
            path = exporter_cls().export(bundles, dialog.output_path, **export_kwargs)
        except Exception as exc:  # noqa: BLE001
            logger.exception("Export failed")
            QMessageBox.critical(self, "Export failed", str(exc))
            return
        self._audit.record(
            "export",
            target=str(path),
            fmt=dialog.selected_format,
            kinds=dialog.selected_kinds,
            extras=dialog.selected_extras,
            profile_ids=sorted(selected_ids) if selected_ids else "all",
        )
        self._status.showMessage(f"Exportado a {path}", 8000)

    def _reconstruct_bundles(self, profile_ids: Optional[set[int]] = None) -> list[ProfileBundle]:
        """Rebuild ``ProfileBundle`` lists from the store for export.

        We could write a direct SQL-to-CSV/JSON path, but reusing the existing
        exporters keeps the code surface small and lets the analyst keep the
        same column shape they see in the UI.

        The store's per-artifact tables carry extra columns (``bates_id``,
        ``source_file_id``, …) added by post-ingest migrations. The
        dataclasses don't know about those columns, so we filter the
        payload down to the fields the dataclass actually accepts before
        instantiating. Without that filter every row triggers a
        ``TypeError`` and the exporter ends up empty.

        When *profile_ids* is provided, only those profiles are rebuilt
        — that's how the export dialog's per-profile checkboxes plug in.
        """
        import dataclasses
        from data.models import (
            AutofillEntry,
            Bookmark,
            CacheEntry,
            Cookie,
            Download,
            Extension,
            HistoryEntry,
            Login,
            OpenTab,
            Permission,
            WebStorageEntry,
        )
        type_map = {
            "history": HistoryEntry,
            "cookies": Cookie,
            "downloads": Download,
            "logins": Login,
            "bookmarks": Bookmark,
            "autofill": AutofillEntry,
            "extensions": Extension,
            "cache_entries": CacheEntry,
            "web_storage": WebStorageEntry,
            "open_tabs": OpenTab,
            "permissions": Permission,
        }
        # Pre-compute the accepted-field set for each dataclass so the
        # per-row loop just does a cheap set membership test.
        accepted_fields = {
            kind: {f.name for f in dataclasses.fields(cls)}
            for kind, cls in type_map.items()
        }
        bundles: list[ProfileBundle] = []
        for prof in self._session.store.list_profiles():
            pid = int(prof["id"])
            if profile_ids is not None and pid not in profile_ids:
                continue
            bundle = ProfileBundle(
                browser=prof["browser"],
                profile=prof["name"],
                path=prof["path"],
            )
            for kind, cls in type_map.items():
                rows = self._session.store.fetch(kind, profile_id=pid)
                items = []
                accepts = accepted_fields[kind]
                for row in rows:
                    payload = {
                        k: row[k] for k in row.keys()
                        if k in accepts and k not in ("id", "profile_id")
                    }
                    payload.setdefault("browser", prof["browser"])
                    payload.setdefault("profile", prof["name"])
                    try:
                        items.append(cls(**payload))
                    except TypeError as exc:
                        # Should not happen now that we filter — log loudly.
                        logger.error(
                            "Could not build %s from row %s: %s",
                            cls.__name__, dict(payload), exc,
                        )
                        continue
                setattr(bundle, kind, items)
            bundles.append(bundle)
        return bundles

    def _open_global_search(self) -> None:
        dialog = GlobalSearchDialog(self._session.store, self)
        dialog.navigate_requested.connect(self._jump_to_kind)
        dialog.show()

    def _jump_to_kind(self, kind: str, query: str) -> None:
        table = self._tables.get(kind)
        if table is None:
            return
        for index in range(self._tabs.count()):
            if self._tabs.widget(index) is table:
                self._tabs.setCurrentIndex(index)
                break
        # Push the search term into the table's filter for instant feedback.
        table._filter.setText(query)  # noqa: SLF001 — intentional shortcut

    def _save_session(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Save session",
            self._session.path.name if self._session.path else "session.wfs",
            "WebForensics session (*.wfs)",
        )
        if not path:
            return
        try:
            saved = self._session.save_as(path)
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Save failed", str(exc))
            return
        self._audit.record("save_session", target=str(saved))
        self.setWindowTitle(f"WebForensics — {saved.name}")
        self._status.showMessage(f"Session saved to {saved}", 8000)

    def _open_session(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Open session",
            "",
            "WebForensics session (*.wfs);;SQLite (*.db *.sqlite)",
        )
        if not path:
            return
        try:
            new_session = Session.open(path)
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Open failed", str(exc))
            return
        self._session.close()
        self._session = new_session
        self._attach_session()
        self._audit.record("open_session", target=path)
        self._summary_label.setText(self._global_summary_text())

    # --- Misc actions -----------------------------------------------------

    def _toggle_theme(self) -> None:
        self._is_dark = self._act_theme.isChecked()
        QApplication.instance().setPalette(dark_palette() if self._is_dark else light_palette())
        self._act_theme.setText(tr("Light theme") if self._is_dark else tr("Dark theme"))

    def _toggle_language(self) -> None:
        set_locale("es" if current_locale() == "en" else "en")

    def _apply_translations(self) -> None:
        """Re-label every visible string when the locale flips."""
        # noqa: refers to _kind_label below

        self._act_autodetect.setText(tr("Auto-detect"))
        self._act_autodetect.setToolTip(tr("Scan default install locations for browser profiles"))
        self._act_open_profile.setText(tr("Open profile…"))
        self._act_scan_folder.setText(tr("Auto-detect in folder…"))
        self._act_scan_folder.setToolTip(tr("Recursively scan a folder for browser profiles"))
        self._act_open_image.setText(tr("Open image (E01)…"))
        self._act_open_image.setToolTip(tr("Open a forensic image (E01 / .dd / .img)"))
        self._act_search.setText(tr("Search"))
        self._act_ioc.setText(tr("IOCs…"))
        self._act_export.setText(tr("Export…"))
        self._act_save.setText(tr("Save session"))
        self._act_open_session.setText(tr("Open session"))
        self._act_theme.setText(tr("Light theme") if self._is_dark else tr("Dark theme"))
        self._act_lang.setToolTip(tr("Language"))
        self._act_quit.setText(tr("E&xit"))
        self._act_about.setText(tr("&About"))
        self._act_audit.setText(tr("Audit log…"))
        self._file_menu.setTitle(tr("&File"))
        self._tools_menu.setTitle(tr("&Tools"))
        self._view_menu.setTitle(tr("&View"))
        self._help_menu.setTitle(tr("&Help"))
        # Tabs: artifact kinds first, then specials in their canonical order.
        for i, kind in enumerate(ARTIFACT_KINDS):
            self._tabs.setTabText(i, tr(_kind_label(kind)))
        offset = len(ARTIFACT_KINDS)
        labels = ("Timeline", "Searches", "Charts", "Findings")
        for i, label in enumerate(labels):
            if offset + i < self._tabs.count():
                self._tabs.setTabText(offset + i, tr(label))
        # Status bar default.
        if self._summary_label.text() == "Ready" or self._summary_label.text() == tr("Ready"):
            self._summary_label.setText(tr("Ready"))

    def _open_ioc_dialog(self) -> None:
        dialog = IOCDialog(self._session.store, self)
        dialog.exec_()
        # Any newly added hits/IOCs change row decorations — refresh tables.
        for table in self._tables.values():
            table.refresh()

    def _show_about(self) -> None:
        AboutDialog(self).exec_()

    def _show_audit(self) -> None:
        AuditDialog(self._audit, self).exec_()

    def _show_diff(self) -> None:
        DiffDialog(self).exec_()

    def _collect_os_artifacts(self) -> None:
        from forensics.os_artifacts import collect_all
        from PyQt5.QtWidgets import QMessageBox
        try:
            count = collect_all(
                self._session.store.connection(),
                browser_executables=("chrome.exe", "msedge.exe", "firefox.exe",
                                     "brave.exe", "opera.exe", "vivaldi.exe"),
            )
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "OS artifacts failed", str(exc))
            return
        QMessageBox.information(
            self, "Collected",
            f"{count} OS-artifact record(s) added (registry / prefetch / lnk / dns / hosts).",
        )
        self._audit.record("collect_os_artifacts", count=count)

    def _enrich_domains(self) -> None:
        from forensics.enrichment import enrich_domains
        from PyQt5.QtWidgets import QMessageBox
        try:
            added = enrich_domains(self._session.store.connection())
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Enrichment failed", str(exc))
            return
        QMessageBox.information(
            self, "Enriched",
            f"{added} domain(s) added to the intel cache.",
        )
        self._audit.record("enrich_domains", added=added)

    # --- Helpers ----------------------------------------------------------

    def _set_actions_enabled(self, enabled: bool) -> None:
        for act in (self._act_autodetect, self._act_open_profile, self._act_scan_folder,
                    self._act_open_image,
                    self._act_export, self._act_save, self._act_open_session,
                    self._act_search, self._act_ioc):
            act.setEnabled(enabled)
        self._update_action_state()

    def _update_action_state(self) -> None:
        has_data = self._session.store.row_count("profiles") > 0
        self._act_export.setEnabled(has_data)
        self._act_save.setEnabled(has_data)
        self._act_search.setEnabled(has_data)
        self._act_ioc.setEnabled(has_data)

    def _global_summary_text(self) -> str:
        s = self._session.store.summary()
        parts = [f"{k}: {v}" for k, v in s.items() if v]
        return " | ".join(parts) if parts else "Ready"

    # --- Lifecycle --------------------------------------------------------

    def closeEvent(self, event) -> None:  # noqa: N802
        # Dismount any virtual disks we attached during the session.
        for cleanup in getattr(self, "_pending_unmounts", []):
            try:
                cleanup.run()
            except Exception:  # noqa: BLE001
                logger.exception("Cleanup failed for %s", cleanup)
        self._session.close()
        super().closeEvent(event)


if __name__ == "__main__":  # pragma: no cover — convenience entry
    import sys
    app = QApplication(sys.argv)
    app.setPalette(light_palette())
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
