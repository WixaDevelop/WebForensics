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
from ui.dialogs.diff_dialog import DiffDialog
from ui.dialogs.export_dialog import ExportDialog
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
    all_done = pyqtSignal()
    failed = pyqtSignal(str)

    def __init__(
        self,
        controller: ForensicsController,
        store: SessionStore,
        image_path: str,
    ) -> None:
        super().__init__()
        self._controller = controller
        self._store = store
        self._image_path = image_path

    def run(self) -> None:
        try:
            for bundle in self._controller.extract_image(
                self._image_path, progress=self.progress.emit
            ):
                profile_id = self._store.ingest_bundle(
                    bundle, source="image", image_path=self._image_path
                )
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
            self._act_autodetect, self._act_open_profile, self._act_open_image,
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
        from forensics import ForensicImageError
        from utils.hashing import sha256_file

        # Quick existence + small-hash check so we audit *what* was opened.
        try:
            digest = sha256_file(image_path)
        except OSError as exc:
            QMessageBox.critical(self, "Open failed", str(exc))
            return

        self._audit.record("open_image", target=str(image_path), sha256=digest)
        self._progress.show()
        self._summary_label.setText(f"Reading image {image_path.name}…")
        self._tree.setEnabled(False)
        self._set_actions_enabled(False)

        self._thread = QThread(self)
        self._worker = _ImageWorker(self._controller, self._session.store, str(image_path))
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.progress.connect(lambda msg: self._status.showMessage(msg))
        self._worker.profile_ingested.connect(self._on_profile_ingested)
        self._worker.failed.connect(self._on_extraction_failed)
        self._worker.all_done.connect(self._on_extraction_done)
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

    def _on_extraction_failed(self, message: str) -> None:
        QMessageBox.critical(self, "Extraction failed", message)

    # --- Tree -------------------------------------------------------------

    def _refresh_tree(self) -> None:
        # Re-build from the store so the tree always matches reality.
        self._tree.clear()
        rows = self._session.store.list_profiles()
        groups: dict[str, QTreeWidgetItem] = {}
        for row in rows:
            browser = row["browser"]
            group = groups.get(browser)
            if group is None:
                group = QTreeWidgetItem(self._tree, [browser, ""])
                font = group.font(0)
                font.setBold(True)
                group.setFont(0, font)
                groups[browser] = group
                group.setExpanded(True)
            count = sum(eval(row["summary"]).values()) if row["summary"] else 0  # safe: our JSON
            leaf = QTreeWidgetItem(group, [row["name"], str(count)])
            leaf.setData(0, Qt.UserRole, int(row["id"]))
            leaf.setToolTip(0, row["path"])
        # Aggregate browser-level counts.
        for group in groups.values():
            total = sum(int(group.child(i).text(1) or 0) for i in range(group.childCount()))
            group.setText(1, str(total))

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
            QMessageBox.information(self, "Nothing to export", "Load a profile first.")
            return
        dialog = ExportDialog(self)
        if dialog.exec_() != ExportDialog.Accepted:
            return
        bundles = self._reconstruct_bundles()
        exporter_cls = EXPORTERS[dialog.selected_format]
        try:
            path = exporter_cls().export(
                bundles,
                dialog.output_path,
                kinds=dialog.selected_kinds,
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("Export failed")
            QMessageBox.critical(self, "Export failed", str(exc))
            return
        self._audit.record(
            "export",
            target=str(path),
            fmt=dialog.selected_format,
            kinds=dialog.selected_kinds,
        )
        self._status.showMessage(f"Exported to {path}", 8000)

    def _reconstruct_bundles(self) -> list[ProfileBundle]:
        """Rebuild ``ProfileBundle`` lists from the store for export.

        We could write a direct SQL-to-CSV/JSON path, but reusing the existing
        exporters keeps the code surface small and lets the analyst keep the
        same column shape they see in the UI.
        """
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
        bundles: list[ProfileBundle] = []
        for prof in self._session.store.list_profiles():
            bundle = ProfileBundle(
                browser=prof["browser"],
                profile=prof["name"],
                path=prof["path"],
            )
            for kind, cls in type_map.items():
                rows = self._session.store.fetch(kind, profile_id=int(prof["id"]))
                items = []
                for row in rows:
                    payload = {k: row[k] for k in row.keys()
                               if k not in ("id", "profile_id")}
                    payload.setdefault("browser", prof["browser"])
                    payload.setdefault("profile", prof["name"])
                    try:
                        items.append(cls(**payload))
                    except TypeError:
                        # Field names match by construction; ignore unexpected drift.
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
        for act in (self._act_autodetect, self._act_open_profile, self._act_open_image,
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
        self._session.close()
        super().closeEvent(event)


if __name__ == "__main__":  # pragma: no cover — convenience entry
    import sys
    app = QApplication(sys.argv)
    app.setPalette(light_palette())
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
