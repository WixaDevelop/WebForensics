"""Excel exporter that replicates the analyst-style layout the user
provided as a reference (``fquispe_mailamericas-Navegadores-001.xlsx``).

Differs from the other XLSX exporters:

* Only 7 sheets: ``Historial``, ``Historial_Snapshots``, ``Descargas``,
  ``Descargas_Snapshots``, ``Credenciales``, ``Autocompletado``,
  ``Busquedas``. No Resumen, no Guía de lectura, no Cookies / Cache /
  Web Storage / Open Tabs / Permissions / Extensions.
* Column headers in Spanish lowercase snake_case (``url``,
  ``fecha_visita``, ``tipo_visita`` …).
* Coded values translated in-cell to Spanish forms (``link`` →
  ``enlace``, ``form_submit`` → ``envio_formulario``, ``complete`` →
  ``Completada``, booleans → ``Si`` / ``No``).
* Banner-free: row 1 is the header, data starts row 2.
* Header style fixed to Calibri 10 bold white on dark blue
  ``#305496``. Freeze panes ``A2`` on every sheet, autofilter over the
  full data range. Datetimes formatted ``yyyy-mm-dd hh:mm:ss.000``.
* Profiles whose name contains ``@shadow-`` (or that the locator
  tagged as a VSS snapshot) get routed to the ``_Snapshots`` variants
  of the History / Downloads sheets, mirroring the example file's
  ``Snapshots/<version>/<name>`` convention.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, Optional
from urllib.parse import urlparse, parse_qs, unquote

from data.models import ARTIFACT_KINDS, ProfileBundle
from exporters.base import ExporterBase

try:  # pragma: no cover — openpyxl is declared in requirements.txt
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.utils import get_column_letter
    _HAS_OPENPYXL = True
except Exception:  # noqa: BLE001
    _HAS_OPENPYXL = False


# ---------------------------------------------------------------------------
# Style / format constants — matched to the reference file
# ---------------------------------------------------------------------------


_HEADER_FONT = ("Calibri", 10.0)
_HEADER_FILL_RGB = "00305496"   # dark blue (matches reference exactly)
_HEADER_FONT_COLOR = "00FFFFFF" # white
_DATETIME_FMT = "yyyy-mm-dd hh:mm:ss.000"
_REPORT_TZ = timezone(timedelta(hours=-5))  # UTC-5 — match the other exporters


# ---------------------------------------------------------------------------
# Visit-type translation (Chromium + Firefox visit_type values → Spanish)
# Values pulled from the reference file: 'enlace', 'envio_formulario',
# 'escrita', 'autocompletada', 'marco_manual', 'recarga', 'favorito',
# 'redireccion_automatica'.
# ---------------------------------------------------------------------------


_VISIT_TYPE_ES: dict[str, str] = {
    "typed":              "escrita",
    "link":               "enlace",
    "auto_bookmark":      "favorito",
    "bookmark":           "favorito",
    "auto_subframe":      "marco_automatico",
    "manual_subframe":    "marco_manual",
    "generated":          "autocompletada",
    "auto_toplevel":      "redireccion_automatica",
    "form_submit":        "envio_formulario",
    "reload":             "recarga",
    "keyword":            "palabra_clave",
    "keyword_generated":  "palabra_clave_generada",
    "embed":              "recurso_embebido",
    "redirect_permanent": "redireccion_permanente",
    "redirect_temporary": "redireccion_temporal",
    "download":           "descarga",
    "framed_link":        "enlace_en_marco",
    "carved":             "recuperada_borrada",
}


_DOWNLOAD_STATE_ES: dict[str, str] = {
    "complete":     "Completada",
    "in_progress":  "En progreso",
    "cancelled":    "Cancelada",
    "interrupted": "Interrumpida",
}


_SEARCH_ENGINE_TITLES: dict[str, str] = {
    "google":     "Google",
    "bing":       "Bing",
    "duckduckgo": "DuckDuckGo",
    "yahoo":      "Yahoo",
    "youtube":    "YouTube",
    "twitter":    "Twitter",
    "x":          "X",
    "brave":      "Brave Search",
    "yandex":     "Yandex",
    "ecosia":     "Ecosia",
    "github":     "GitHub",
}


# Column widths from the reference workbook (in Excel character units).
_COLUMN_WIDTHS: dict[str, dict[str, float]] = {
    "Historial": {
        "A": 12.0, "B": 32.0, "C": 75.0, "D": 55.0,
        "E": 26.0, "F": 24.0, "G": 16.0, "H": 20.0,
    },
    "Descargas": {
        "A": 12.0, "B": 32.0, "C": 75.0, "D": 75.0, "E": 75.0,
        "F": 14.0, "G": 14.0, "H": 16.0, "I": 26.0, "J": 26.0,
    },
    "Credenciales": {
        "A": 12.0, "B": 32.0, "C": 12.0, "D": 75.0,
        "E": 40.0, "F": 26.0, "G": 26.0, "H": 14.0, "I": 16.0,
    },
    "Autocompletado": {
        "A": 12.0, "B": 32.0, "C": 28.0, "D": 50.0,
        "E": 18.0, "F": 26.0, "G": 26.0,
    },
    "Busquedas": {
        "A": 12.0, "B": 32.0, "C": 16.0, "D": 55.0,
        "E": 75.0, "F": 55.0, "G": 26.0,
    },
}


# ---------------------------------------------------------------------------
# Value helpers
# ---------------------------------------------------------------------------


# openpyxl mirrors Excel's restriction: cells must not carry control
# characters \x00-\x08, \x0B-\x0C, \x0E-\x1F. These appear inside cookie
# values, IDB blobs and IM message bodies; we replace them with the
# Unicode replacement character so the workbook save never aborts.
import re as _re
_ILLEGAL_XLSX_CHARS = _re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F]")


def _clean(value):
    """Coerce *value* into something safe to drop into an openpyxl cell."""
    if value is None:
        return None
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    if isinstance(value, str):
        if _ILLEGAL_XLSX_CHARS.search(value):
            value = _ILLEGAL_XLSX_CHARS.sub("�", value)
        if len(value) > 32767:
            value = value[:32764] + "…"
    return value


def _to_local_dt(value) -> Optional[datetime]:
    """Convert datetime / ISO-8601 string to a naive UTC-5 datetime.

    Returns ``None`` for missing / unparseable values so cells stay
    blank (matching the reference file, which leaves missing dates as
    empty cells, not as text).
    """
    if value is None or value == "":
        return None
    dt: Optional[datetime] = None
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, str):
        if len(value) < 10 or value[4:5] != "-" or value[7:8] != "-":
            return None
        stripped = value.rstrip("Z")
        try:
            dt = datetime.fromisoformat(stripped)
        except (TypeError, ValueError):
            return None
        if value.endswith("Z") and dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(_REPORT_TZ).replace(tzinfo=None)


def _yes_no(value) -> str:
    """Render any truthy value as ``Si``, falsy as ``No``."""
    if value is None or value == "":
        return "No"
    try:
        return "Si" if int(value) else "No"
    except (TypeError, ValueError):
        return "Si" if value else "No"


def _round_or_none(value, ndigits=3):
    if value is None or value == "":
        return None
    try:
        return round(float(value), ndigits)
    except (TypeError, ValueError):
        return None


def _engine_title(slug) -> str:
    if not slug:
        return ""
    return _SEARCH_ENGINE_TITLES.get(str(slug).lower(), str(slug).title())


def _is_snapshot_bundle(bundle: ProfileBundle) -> bool:
    """Bundles staged from a VSS snapshot carry ``@shadow-`` in the name."""
    return "@shadow-" in (bundle.profile or "")


def _snapshot_profile_label(bundle: ProfileBundle) -> str:
    """Tag the perfil column to mirror the reference's ``Snapshots/...`` form.

    The reference file uses ``Snapshots/<version>/<profile>``; we don't
    have the Chromium release version, so we substitute the snapshot
    label (eg ``shadow-20260225-031003``) and keep the profile name.
    """
    profile = bundle.profile or ""
    if "@shadow-" in profile:
        base, _, suffix = profile.partition("@shadow-")
        return f"Snapshots/{suffix}/{base}"
    return f"Snapshots/{profile}"


# ---------------------------------------------------------------------------
# Search-term URL parsing (recovers the search query when extra extras
# weren't selected by the analyst).
# ---------------------------------------------------------------------------


_SEARCH_HOST_TO_PARAM: tuple[tuple[str, str, str], ...] = (
    ("google.",        "q",            "google"),
    ("bing.com",       "q",            "bing"),
    ("duckduckgo.com", "q",            "duckduckgo"),
    ("youtube.com",    "search_query", "youtube"),
    ("yahoo.com",      "p",            "yahoo"),
    ("yandex.",        "text",         "yandex"),
    ("search.brave.com", "q",          "brave"),
    ("ecosia.org",     "q",            "ecosia"),
    ("twitter.com",    "q",            "twitter"),
    ("x.com",          "q",            "x"),
    ("github.com",     "q",            "github"),
)


def _parse_search_from_url(url: str) -> Optional[tuple[str, str]]:
    """Return ``(engine, query)`` if *url* looks like a search-engine URL."""
    if not url:
        return None
    try:
        parsed = urlparse(url)
    except ValueError:
        return None
    if not parsed.netloc:
        return None
    host = parsed.netloc.lower()
    for needle, param, engine in _SEARCH_HOST_TO_PARAM:
        if needle in host:
            qs = parse_qs(parsed.query)
            values = qs.get(param)
            if not values:
                continue
            query = unquote(values[0]).strip()
            if query:
                return engine, query
    return None


# ---------------------------------------------------------------------------
# Exporter
# ---------------------------------------------------------------------------


class XlsxDummyExporter(ExporterBase):
    """Replicate the analyst-style workbook layout the user provided."""

    extension = ".xlsx"

    def export(
        self,
        bundles: Iterable[ProfileBundle],
        out_path: str | Path,
        kinds: Iterable[str] = ARTIFACT_KINDS,
        store=None,
        extras: Iterable[str] = (),
        profile_ids: Iterable[int] | None = None,
    ) -> Path:
        # ``store``, ``extras`` and ``profile_ids`` are accepted to keep the
        # signature compatible with :class:`XlsxExporter`. This format
        # ignores the store and extras (no Resumen / extras sheets) and
        # relies on the caller having already filtered bundles by profile.
        if not _HAS_OPENPYXL:
            raise RuntimeError(
                "openpyxl is not installed — run `pip install openpyxl` to enable XLSX export."
            )
        out = Path(out_path)
        if out.is_dir() or out.suffix.lower() != ".xlsx":
            out = (out / "webforensics.xlsx") if out.is_dir() else out.with_suffix(".xlsx")
        out.parent.mkdir(parents=True, exist_ok=True)

        bundles_list = list(bundles)
        live = [b for b in bundles_list if not _is_snapshot_bundle(b)]
        snaps = [b for b in bundles_list if _is_snapshot_bundle(b)]

        wb = Workbook()
        wb.remove(wb.active)

        # Order matters — must mirror the reference workbook exactly.
        self._write_historial(wb, "Historial", live)
        self._write_historial(wb, "Historial_Snapshots", snaps, is_snapshot=True)
        self._write_descargas(wb, "Descargas", live)
        self._write_descargas(wb, "Descargas_Snapshots", snaps, is_snapshot=True)
        self._write_credenciales(wb, "Credenciales", bundles_list)
        self._write_autocompletado(wb, "Autocompletado", bundles_list)
        self._write_busquedas(wb, "Busquedas", bundles_list, store=store)

        wb.save(out)
        return out

    # ------------------------------------------------------------------
    # Sheet builders
    # ------------------------------------------------------------------

    def _write_historial(self, wb, sheet_name: str, bundles: list[ProfileBundle],
                          *, is_snapshot: bool = False) -> None:
        headers = (
            "navegador", "perfil", "url", "titulo", "fecha_visita",
            "tipo_visita", "duracion_seg", "total_visitas_url",
        )
        ws = wb.create_sheet(sheet_name)
        self._write_header(ws, headers)
        row_idx = 2
        for bundle in bundles:
            perfil = _snapshot_profile_label(bundle) if is_snapshot else (bundle.profile or "")
            for h in bundle.history:
                ws.cell(row=row_idx, column=1, value=_clean(bundle.browser))
                ws.cell(row=row_idx, column=2, value=_clean(perfil))
                ws.cell(row=row_idx, column=3, value=_clean(h.url))
                ws.cell(row=row_idx, column=4, value=_clean(h.title))
                ws.cell(row=row_idx, column=5, value=_to_local_dt(h.last_visit))
                ws.cell(row=row_idx, column=6,
                        value=_VISIT_TYPE_ES.get(h.visit_type, h.visit_type or ""))
                # duracion_seg: not currently extracted by our HistoryEntry —
                # default to 0 so the schema matches the reference exactly.
                ws.cell(row=row_idx, column=7, value=0)
                ws.cell(row=row_idx, column=8, value=int(h.visit_count or 0))
                row_idx += 1
        self._finalise(ws, sheet_name, headers, row_idx)

    def _write_descargas(self, wb, sheet_name: str, bundles: list[ProfileBundle],
                          *, is_snapshot: bool = False) -> None:
        headers = (
            "navegador", "perfil", "url_origen", "url_pestana", "ruta_destino",
            "tamano_mb", "recibido_mb", "estado", "inicio_descarga", "fin_descarga",
        )
        ws = wb.create_sheet(sheet_name)
        self._write_header(ws, headers)
        row_idx = 2
        for bundle in bundles:
            perfil = _snapshot_profile_label(bundle) if is_snapshot else (bundle.profile or "")
            for d in bundle.downloads:
                ws.cell(row=row_idx, column=1, value=_clean(bundle.browser))
                ws.cell(row=row_idx, column=2, value=_clean(perfil))
                ws.cell(row=row_idx, column=3, value=_clean(d.url))
                # url_pestana = tab/referrer URL where the download was kicked
                # off. The closest match in our model is the referrer.
                ws.cell(row=row_idx, column=4, value=_clean(d.referrer or d.url))
                ws.cell(row=row_idx, column=5, value=_clean(d.target_path))
                ws.cell(row=row_idx, column=6,
                        value=_round_or_none(int(d.total_bytes or 0) / (1024 * 1024)))
                ws.cell(row=row_idx, column=7,
                        value=_round_or_none(int(d.received_bytes or 0) / (1024 * 1024)))
                ws.cell(row=row_idx, column=8,
                        value=_DOWNLOAD_STATE_ES.get(d.state, d.state or ""))
                ws.cell(row=row_idx, column=9, value=_to_local_dt(d.start_time))
                ws.cell(row=row_idx, column=10, value=_to_local_dt(d.end_time))
                row_idx += 1
        self._finalise(ws, sheet_name, headers, row_idx)

    def _write_credenciales(self, wb, sheet_name: str, bundles: list[ProfileBundle]) -> None:
        headers = (
            "navegador", "perfil", "almacen", "url_origen", "usuario",
            "fecha_creacion", "fecha_ultimo_uso", "veces_usada", "nunca_guardar",
        )
        ws = wb.create_sheet(sheet_name)
        self._write_header(ws, headers)
        row_idx = 2
        for bundle in bundles:
            perfil = bundle.profile or ""
            for l in bundle.logins:
                ws.cell(row=row_idx, column=1, value=_clean(bundle.browser))
                ws.cell(row=row_idx, column=2, value=_clean(perfil))
                # ``almacen`` documents where the password lives. Chromium
                # uses two stores: 'Local' for the profile's own DB and
                # 'Cuenta' for Google-account sync. Our model doesn't
                # distinguish; default to 'Local'.
                ws.cell(row=row_idx, column=3, value="Local")
                ws.cell(row=row_idx, column=4, value=_clean(l.origin_url))
                ws.cell(row=row_idx, column=5, value=_clean(l.username))
                ws.cell(row=row_idx, column=6, value=_to_local_dt(l.date_created))
                ws.cell(row=row_idx, column=7, value=_to_local_dt(l.date_last_used))
                ws.cell(row=row_idx, column=8, value=int(l.times_used or 0))
                # ``nunca_guardar`` mirrors Chromium's ``blacklisted_by_user``
                # flag (1 = user clicked "Nunca" when prompted). Our model
                # doesn't carry that flag yet — empty username + empty
                # password is the closest proxy.
                blacklisted = (not (l.username or "")) and (not (l.password or ""))
                ws.cell(row=row_idx, column=9, value=_yes_no(blacklisted))
                row_idx += 1
        self._finalise(ws, sheet_name, headers, row_idx)

    def _write_autocompletado(self, wb, sheet_name: str,
                                bundles: list[ProfileBundle]) -> None:
        headers = (
            "navegador", "perfil", "campo", "valor", "veces_ingresado",
            "fecha_creacion", "fecha_ultimo_uso",
        )
        ws = wb.create_sheet(sheet_name)
        self._write_header(ws, headers)
        row_idx = 2
        for bundle in bundles:
            perfil = bundle.profile or ""
            for a in bundle.autofill:
                ws.cell(row=row_idx, column=1, value=_clean(bundle.browser))
                ws.cell(row=row_idx, column=2, value=_clean(perfil))
                ws.cell(row=row_idx, column=3, value=_clean(a.field_name))
                ws.cell(row=row_idx, column=4, value=_clean(a.value))
                ws.cell(row=row_idx, column=5, value=int(a.count or 0))
                ws.cell(row=row_idx, column=6, value=_to_local_dt(a.first_used))
                ws.cell(row=row_idx, column=7, value=_to_local_dt(a.last_used))
                row_idx += 1
        self._finalise(ws, sheet_name, headers, row_idx)

    def _write_busquedas(self, wb, sheet_name: str,
                          bundles: list[ProfileBundle], store=None) -> None:
        headers = (
            "navegador", "perfil", "buscador", "consulta",
            "url_resultado", "titulo_resultado", "fecha_busqueda",
        )
        ws = wb.create_sheet(sheet_name)
        self._write_header(ws, headers)
        row_idx = 2

        # We rebuild the search list from the history URLs so the sheet
        # is correct even when no ``search_terms`` extra was selected.
        for bundle in bundles:
            perfil = bundle.profile or ""
            for h in bundle.history:
                parsed = _parse_search_from_url(h.url or "")
                if parsed is None:
                    continue
                engine, query = parsed
                ws.cell(row=row_idx, column=1, value=_clean(bundle.browser))
                ws.cell(row=row_idx, column=2, value=_clean(perfil))
                ws.cell(row=row_idx, column=3, value=_engine_title(engine))
                ws.cell(row=row_idx, column=4, value=_clean(query))
                ws.cell(row=row_idx, column=5, value=_clean(h.url))
                ws.cell(row=row_idx, column=6, value=_clean(h.title))
                ws.cell(row=row_idx, column=7, value=_to_local_dt(h.last_visit))
                row_idx += 1
        self._finalise(ws, sheet_name, headers, row_idx)

    # ------------------------------------------------------------------
    # Styling primitives — pixel-equal to the reference
    # ------------------------------------------------------------------

    def _write_header(self, ws, headers: tuple[str, ...]) -> None:
        font = Font(name=_HEADER_FONT[0], size=_HEADER_FONT[1],
                    bold=True, color=_HEADER_FONT_COLOR)
        fill = PatternFill(fill_type="solid", fgColor=_HEADER_FILL_RGB)
        for idx, name in enumerate(headers, start=1):
            cell = ws.cell(row=1, column=idx, value=name)
            cell.font = font
            cell.fill = fill

    def _finalise(self, ws, sheet_name: str,
                   headers: tuple[str, ...], next_row: int) -> None:
        n_cols = len(headers)
        last_data_row = next_row - 1
        # Apply the datetime number format to every cell whose value is a
        # datetime. We pick column-by-column from row 2 onwards.
        for col_idx in range(1, n_cols + 1):
            for r in range(2, last_data_row + 1):
                cell = ws.cell(row=r, column=col_idx)
                if isinstance(cell.value, datetime):
                    cell.number_format = _DATETIME_FMT

        # Column widths from the reference (best-fit per sheet base
        # name; snapshot variants reuse the same widths).
        base_name = sheet_name.rsplit("_Snapshots", 1)[0]
        widths = _COLUMN_WIDTHS.get(base_name) or _COLUMN_WIDTHS.get(sheet_name) or {}
        for letter, width in widths.items():
            ws.column_dimensions[letter].width = width

        # Freeze the header row and turn on autofilter — same as
        # reference, even when the sheet has no data (an autofilter on
        # row 1 only is what Excel writes when you click Filter on a
        # header-only sheet).
        ws.freeze_panes = "A2"
        end_col_letter = get_column_letter(n_cols)
        last_ref_row = max(last_data_row, 1)
        ws.auto_filter.ref = f"A1:{end_col_letter}{last_ref_row}"
