"""Excel (.xlsx) exporter with a summary + glossary sheet.

Each artifact lands on its own sheet with proper headers, freeze panes
and an auto-filter. A leading "Resumen" sheet aggregates counts per
profile, a "Glosario" section documents every artifact type, and a
"Hallazgos" section surfaces automatic statistics — top hosts,
categories, encrypted credentials, downloaded executables and so on.

All timestamps in the workbook are rendered in :data:`REPORT_TZ`
(UTC-5) so the analyst doesn't have to mentally convert from UTC.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, Optional
from urllib.parse import urlparse

from data.models import ARTIFACT_KINDS, ProfileBundle
from exporters.base import ExporterBase


# Single source of truth for the reporting timezone. UTC-5 covers
# Ecuador / Colombia / Peru / Eastern Standard Time (no DST). All
# datetimes the exporter writes pass through ``_to_local_dt`` and end
# up converted to this offset so Excel doesn't show raw UTC.
REPORT_TZ = timezone(timedelta(hours=-5))
REPORT_TZ_LABEL = "UTC-5"

# Names of every extra (non-bundle) store table we can export. Kept in
# this order so the workbook layout is predictable.
EXTRA_TABLES: tuple[str, ...] = (
    "search_terms",
    "accounts",
    "messages",
    "tokens",
    "user_agents",
    "findings",
    "iocs",
    "ioc_hits",
    "os_artifacts",
    "source_files",
    "domain_intel",
    "tags",
)

# Per-extra friendly description shown as the banner of each sheet and on
# the interpretation page (Spanish only).
EXTRA_INTERPRETATIONS: dict[str, str] = {
    "search_terms": (
        "Búsquedas del usuario: las palabras que el usuario tecleó en Google, Bing, DuckDuckGo, "
        "YouTube, Twitter/X, Brave Search, etc. Reconstruidas a partir de las URLs del historial. "
        "Cada fila incluye la consulta exacta, el motor usado y cuándo se hizo."
    ),
    "accounts": (
        "Cuentas detectadas: identidades online del usuario recuperadas de cookies y "
        "LocalStorage/IndexedDB. Incluye IDs internos (c_user de Facebook, twid de Twitter, "
        "google session, github user, discord snowflake…) y, cuando se pudo resolver, el handle "
        "humano. Una fila aquí es prueba muy fuerte de cuenta activa."
    ),
    "messages": (
        "Mensajes recuperados: chats que el usuario tenía abiertos en clientes web como "
        "WhatsApp Web, Discord o Telegram Web. Best-effort — los mensajes vienen de IndexedDB y "
        "no siempre se decodifican enteros. Cada fila tiene la app, el remitente, el contenido y "
        "el momento."
    ),
    "tokens": (
        "Tokens OAuth / JWT: tokens de autenticación encontrados en cookies o storage. Para los "
        "JWT que se pudieron decodificar, se incluyen issuer, subject, scope y expiración. Un "
        "token activo equivale a una sesión que se podría reabrir."
    ),
    "user_agents": (
        "User-Agent strings vistos: cadenas de identificación de navegador reconstruidas a partir "
        "de cabeceras en caché o de Storage. Útil para detectar uso de modo privado, dispositivos "
        "móviles secundarios, o automatización (bots / scrapers)."
    ),
    "findings": (
        "Hallazgos anti-forenses: alertas del analizador heurístico. Incluye huecos en la línea "
        "de tiempo, historial vacío con cookies sobrevivientes, hosts que solo aparecen en "
        "registros recuperados, eventos con timestamps en el futuro, etc. severity = critical/high "
        "amerita revisión inmediata."
    ),
    "iocs": (
        "Lista de IOCs (Indicators of Compromise) cargados en la sesión. Cada IOC es un valor "
        "(dominio, URL, hash, IP, email, username) con su severidad. La hoja 'IOC hits' muestra "
        "qué artefactos del navegador coincidieron con cada IOC."
    ),
    "ioc_hits": (
        "Coincidencias entre los IOCs cargados y los artefactos del navegador. Cada fila indica "
        "qué IOC coincidió con qué artefacto, en qué campo, y con qué valor. Estas son las pistas "
        "más urgentes de revisar."
    ),
    "os_artifacts": (
        "Artefactos del sistema operativo correlacionados con la actividad del navegador: "
        "Registro de Windows (TypedURLs, TypedPaths), Prefetch (lanzamientos del ejecutable del "
        "navegador), LNK recientes, hosts file estático y caché DNS. Confirman la actividad desde "
        "una perspectiva FUERA del navegador."
    ),
    "source_files": (
        "Cadena de custodia: cada archivo fuente que WebForensics tocó durante la extracción, "
        "con su SHA-256, tamaño, mtime/atime/ctime y (si vino de una imagen forense) ruta de la "
        "imagen y offset. Esta hoja es la prueba técnica de qué leyó la herramienta."
    ),
    "domain_intel": (
        "Enriquecimiento de dominios: información de WHOIS / GeoIP / TLD almacenada en caché para "
        "los dominios encontrados. Marca dominios con riesgo elevado (TLDs sospechosos, .onion, "
        "punycode) cuando se puede."
    ),
    "tags": (
        "Notas y etiquetas del analista: filas que el analista marcó manualmente como evidencia "
        "o anotó con comentarios. Estas son las anotaciones de revisión humanas, no automáticas."
    ),
}

EXTRA_TABLE_HUMAN_NAMES = {
    "search_terms": "Búsquedas",
    "accounts": "Cuentas detectadas",
    "messages": "Mensajes IM",
    "tokens": "Tokens (JWT/OAuth)",
    "user_agents": "User Agents",
    "findings": "Hallazgos forenses",
    "iocs": "IOCs cargados",
    "ioc_hits": "IOC matches",
    "os_artifacts": "Artefactos del SO",
    "source_files": "Cadena de custodia",
    "domain_intel": "Enriquecimiento dominios",
    "tags": "Notas del analista",
}

try:  # pragma: no cover — optional dep, declared in requirements.txt
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
    from openpyxl.utils import get_column_letter
    from openpyxl.worksheet.table import Table, TableStyleInfo
    _HAS_OPENPYXL = True
except Exception:  # noqa: BLE001
    _HAS_OPENPYXL = False


# ---------------------------------------------------------------------------
# Human-readable copy
# ---------------------------------------------------------------------------


# One paragraph per artifact in Spanish.
_ARTIFACT_INTERPRETATIONS: dict[str, str] = {
    "history": (
        "Historial de navegación: cada URL que el usuario visitó con su navegador. "
        "Incluye la fecha de la última visita y el número total de veces que abrió esa página. "
        "Un 'visit_type' de 'typed' significa que la URL fue escrita a mano (intención clara), "
        "mientras que 'link' significa que llegó haciendo clic en otra página. "
        "Filas marcadas con visit_type='carved' fueron recuperadas de espacio borrado del navegador."
    ),
    "cookies": (
        "Cookies: pequeños archivos que los sitios web dejan en el navegador para recordar "
        "sesiones, preferencias y rastrear actividad. Una cookie con host 'accounts.google.com' "
        "indica que el usuario interactuó con Google. La columna 'secure' indica si solo viaja por HTTPS; "
        "'http_only' es una protección anti-robo de cookie. Una sesión activa generalmente significa "
        "una visita reciente."
    ),
    "downloads": (
        "Descargas: archivos que el usuario bajó de internet. Muestra la URL de origen, dónde se "
        "guardó el archivo en disco ('target_path'), el tamaño y el estado (complete = descarga "
        "exitosa). Si el archivo sigue en el disco en esa ruta, es evidencia directa del download. "
        "Si NO está, el usuario lo borró pero el navegador todavía recuerda que existió."
    ),
    "logins": (
        "Credenciales guardadas: usuarios y contraseñas que el navegador almacenó. "
        "Si 'encrypted'=True significa que el password no se pudo descifrar (típico en imágenes "
        "forenses sin acceso a la clave DPAPI del usuario). Aunque no se vea el password, saber "
        "QUÉ sitios tienen credenciales guardadas es altamente informativo: muestra qué cuentas "
        "usaba el usuario."
    ),
    "bookmarks": (
        "Favoritos / Marcadores: sitios que el usuario guardó intencionalmente. "
        "Más significativos forensemente que el historial — son páginas que el usuario decidió "
        "conservar. Las fechas date_added muestran cuándo se guardó cada favorito."
    ),
    "autofill": (
        "Datos de autocompletado: lo que el usuario escribió en formularios web (nombre, dirección, "
        "número de teléfono, números de tarjeta, búsquedas, etc.) y que el navegador guardó para "
        "rellenar automáticamente en el futuro. 'count' es cuántas veces se usó ese valor."
    ),
    "extensions": (
        "Extensiones instaladas: complementos del navegador. Algunas son inocuas (bloqueadores de "
        "anuncios, traductores), otras son indicadores forenses fuertes — extensiones de VPN, de "
        "borrado de historial, de cripto-wallet, de descarga de video, de proxy. "
        "El extension_id permite buscarla en la Chrome Web Store o AMO."
    ),
    "cache_entries": (
        "Caché HTTP: URLs de recursos (imágenes, scripts, páginas) que el navegador descargó y "
        "guardó localmente para evitar volver a pedirlos. Es un rastro INDIRECTO — aparece aquí "
        "incluso si la URL no está en el historial. Forensemente útil para reconstruir qué páginas "
        "vio el usuario más allá del historial visible."
    ),
    "web_storage": (
        "LocalStorage / IndexedDB: bases de datos que los sitios web usan para guardar datos "
        "persistentes en el navegador (tokens de autenticación, configuración de la web, mensajes "
        "de chat, drafts). Es una mina de oro forense — apps como WhatsApp Web, Discord o Telegram "
        "almacenan los mensajes aquí."
    ),
    "open_tabs": (
        "Pestañas abiertas: las páginas que el navegador tenía abiertas la última vez que se cerró. "
        "Refleja lo que el usuario estaba mirando justo antes de apagar/cerrar. Si la columna "
        "session = 'last' es la sesión anterior; 'current' es la actual."
    ),
    "permissions": (
        "Permisos otorgados: a qué sitios el usuario les dio acceso a cámara, micrófono, "
        "ubicación, notificaciones, etc. Si aparece 'allow' en 'camera' o 'microphone' para un "
        "sitio sospechoso, es un hallazgo notable."
    ),
}


# Legend printed in the History sheet banner so the analyst doesn't have
# to memorise Chromium/Firefox visit_type codes. Pulled from the
# ``_VISIT_TYPES`` dicts in ``browsers/chromium.py`` and ``browsers/firefox.py``.
_VISIT_TYPE_LEGEND: dict[str, str] = {
    "typed": "el usuario escribió la URL a mano en la barra de direcciones (intención clara)",
    "link": "el usuario hizo clic en un enlace desde otra página",
    "auto_bookmark": "navegó desde un favorito guardado",
    "bookmark": "navegó desde un favorito (Firefox)",
    "auto_subframe": "iframe/subframe cargado automáticamente (no es navegación del usuario)",
    "manual_subframe": "iframe/subframe que el usuario activó",
    "generated": "URL generada por el autocompletado de la barra de direcciones",
    "auto_toplevel": "navegación automática a nivel de pestaña (rara, suele ser redirección)",
    "form_submit": "envío de formulario (login, búsqueda, etc.)",
    "reload": "recarga de la página (F5, Ctrl+R)",
    "keyword": "búsqueda hecha escribiendo una palabra clave del navegador",
    "keyword_generated": "URL generada por una búsqueda con palabra clave",
    "embed": "recurso embebido (Firefox)",
    "redirect_permanent": "redirección HTTP 301",
    "redirect_temporary": "redirección HTTP 302/303/307",
    "download": "la URL terminó en una descarga",
    "framed_link": "clic en un enlace dentro de un iframe (Firefox)",
    "carved": "fila recuperada de espacio borrado (no estaba viva en la base de datos)",
}


_CATEGORY_LABELS_ES = {
    "banking": "Banca / finanzas",
    "social": "Redes sociales",
    "im": "Mensajería",
    "mail": "Correo electrónico",
    "streaming": "Streaming / video",
    "shopping": "Compras",
    "search": "Buscadores",
    "news": "Noticias",
    "dev": "Desarrollo / código",
    "government": "Gobierno",
    "education": "Educación",
    "darkweb": "Dark web",
    "vpn_proxy": "VPN / proxy",
    "crypto": "Criptomonedas",
    "adult": "Adulto",
    "gambling": "Apuestas",
    "cloud": "Nube / almacenamiento",
    "advertising": "Publicidad",
}


# Per-column tooltips so a non-technical reader gets context when they
# hover or check the second header row.
_FIELD_HINTS: dict[str, dict[str, str]] = {
    "history": {
        "url": "URL completa de la página",
        "title": "Título mostrado en la pestaña",
        "visit_count": "Número total de visitas registradas",
        "typed_count": "Veces que la URL fue escrita a mano (intención clara)",
        "last_visit": "Fecha y hora de la última visita (UTC-5)",
        "visit_type": "Cómo se llegó a la página: typed=escrita, link=clic, bookmark=desde favorito, carved=recuperada de borrado",
        "deleted": "True si la entrada fue recuperada de espacio borrado",
        "from_visit_url": "Página de la que se vino (referrer)",
        "category": "Clasificación automática (banking, social, im…)",
    },
    "cookies": {
        "host": "Sitio que dejó la cookie (clave del 'a qué sitio se conectó')",
        "name": "Nombre interno de la cookie",
        "value": "Contenido (a menudo cifrado o token opaco)",
        "expires": "Cuándo expira la cookie",
        "created": "Cuándo el sitio creó la cookie en este equipo",
        "last_access": "Última vez que el navegador la envió al sitio",
        "secure": "Solo viaja por HTTPS",
        "http_only": "JavaScript no puede leerla (anti-robo)",
        "same_site": "Política contra peticiones desde otros dominios",
        "encrypted": "True si no se pudo descifrar el valor (común en imagen sin DPAPI)",
    },
    "downloads": {
        "url": "URL de origen del archivo",
        "target_path": "Ruta local donde se guardó (si todavía existe = evidencia directa)",
        "referrer": "Página desde donde se inició la descarga",
        "mime_type": "Tipo MIME (image/jpeg, application/pdf…)",
        "total_bytes": "Tamaño total en MB (binario, 1 MB = 1 048 576 bytes)",
        "received_bytes": "MB realmente descargados (binario, 1 MB = 1 048 576 bytes)",
        "state": "complete=ok, cancelled=cancelado, interrupted=cortado",
        "start_time": "Cuándo empezó la descarga",
        "end_time": "Cuándo terminó",
    },
    "logins": {
        "origin_url": "Sitio donde se guardó la credencial",
        "action_url": "URL del formulario de login",
        "username": "Usuario guardado",
        "password": "Contraseña descifrada (vacío si encrypted=True)",
        "date_created": "Primera vez que el usuario guardó esta credencial",
        "date_last_used": "Última vez que se usó el autocompletado",
        "times_used": "Número de veces que se rellenó automáticamente",
        "encrypted": "True si el password no pudo descifrarse",
    },
    "bookmarks": {
        "folder": "Carpeta dentro de los favoritos",
        "name": "Nombre que el usuario le puso al favorito",
        "url": "URL guardada",
        "date_added": "Cuándo lo guardó",
        "date_modified": "Última edición del favorito",
    },
    "autofill": {
        "field_name": "Nombre del campo del formulario (email, telefono, address…)",
        "value": "Valor que el usuario escribió",
        "count": "Veces que ese valor se usó",
        "first_used": "Primera vez que lo escribió",
        "last_used": "Última vez que lo reutilizó",
    },
    "extensions": {
        "extension_id": "ID único (buscable en Chrome Web Store / AMO)",
        "name": "Nombre visible de la extensión",
        "version": "Versión instalada",
        "description": "Lo que dice hacer",
        "enabled": "Si estaba activa o desinstalada/desactivada",
        "install_path": "Carpeta local donde vive",
    },
    "cache_entries": {
        "url": "URL del recurso cacheado",
        "mime_type": "Tipo de contenido",
        "size": "Tamaño en MB (binario, 1 MB = 1 048 576 bytes)",
        "fetched_at": "Cuándo el navegador la pidió por primera vez",
        "last_used": "Última vez que la sirvió desde caché",
        "status_code": "Código HTTP que respondió el servidor",
        "source": "Origen del archivo cacheado",
    },
    "web_storage": {
        "origin": "Sitio web dueño del dato",
        "kind": "localstorage / sessionstorage / indexeddb",
        "key": "Clave (nombre del dato)",
        "value": "Contenido (puede ser texto, JSON, blob…)",
        "last_modified": "Última modificación del dato",
        "source": "Archivo del que se extrajo",
    },
    "open_tabs": {
        "session": "current=actual, last=sesión anterior",
        "window_idx": "Índice de la ventana del navegador",
        "tab_idx": "Posición de la pestaña dentro de la ventana",
        "url": "URL abierta",
        "title": "Título de la pestaña",
        "last_active": "Última vez que estuvo activa",
        "pinned": "True si era una pestaña fijada",
    },
    "permissions": {
        "origin": "Sitio al que se le concedió/denegó permiso",
        "permission": "Qué permiso (notifications, geolocation, camera, microphone…)",
        "setting": "allow=permitido, block=bloqueado, ask=preguntar cada vez",
        "last_modified": "Cuándo se cambió el permiso",
    },
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _host(url: str) -> str:
    if not url:
        return ""
    try:
        return urlparse(url).netloc or url
    except Exception:  # noqa: BLE001
        return url


# openpyxl mirrors Excel's own restriction: cells must not carry control
# characters \x00-\x08, \x0B-\x0C, \x0E-\x1F. They sneak in via cookie
# values, LocalStorage blobs, IM message bodies and similar binary-leaning
# fields — and they crash the workbook with ``IllegalCharacterError`` at
# save time. We strip them here so the export never fails on a single
# tainted byte.
import re as _re
_ILLEGAL_XLSX_CHARS = _re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F]")


def _clean_for_excel(value):
    """Make *value* safe to write into an openpyxl cell.

    - ``bytes`` get decoded with replacement so we don't lose the row.
    - ``str`` has its illegal control characters mapped to ``\\ufffd``
      (the standard Unicode replacement char, visible in Excel as a
      diamond-question mark — the analyst can spot tampered cells).
    - Everything else (int, float, bool, datetime, None) passes through.
    """
    if value is None:
        return None
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    if isinstance(value, str) and _ILLEGAL_XLSX_CHARS.search(value):
        return _ILLEGAL_XLSX_CHARS.sub("�", value)
    return value


# Columns we never want to see in the export. ``deleted`` and ``category``
# are internal markers — the deleted flag is conveyed by the dedicated
# carved-row banner / visit_type='carved' on history, and category is an
# automated tag that doesn't add value to the analyst's report.
_HIDDEN_COLUMNS: set[str] = {"deleted", "category"}

# Byte-counting columns we want shown as binary megabytes (MiB) instead
# of raw bytes. Mapping value is the new column name shown in the sheet.
# 1 MB = 1024 KB = 1 048 576 bytes (the user explicitly asked for the
# binary form, not the decimal SI MB).
_BYTES_TO_MB_COLUMNS: dict[str, str] = {
    "total_bytes": "total_mb",
    "received_bytes": "received_mb",
    "size": "size_mb",
}

_BYTES_PER_MB = 1024 * 1024


def _visible_fieldname(name: str) -> Optional[str]:
    """Return the *display* column name for *name*, or ``None`` if hidden."""
    if name in _HIDDEN_COLUMNS:
        return None
    return _BYTES_TO_MB_COLUMNS.get(name, name)


def _value_for_export(name: str, value):
    """Apply per-column transformations before the value reaches the cell.

    For byte columns the integer count is divided by ``1024*1024`` and
    rounded to 4 decimals so 1 KB shows up as ``0.001`` MB rather than a
    long floating-point number. ``None`` / non-numeric falls through
    untouched.
    """
    if name in _BYTES_TO_MB_COLUMNS:
        if value is None or value == "":
            return value
        try:
            return round(float(value) / _BYTES_PER_MB, 4)
        except (TypeError, ValueError):
            return value
    return value


def _truncate(value, limit: int = 32767):
    """Sanitize + tz-convert + length-clamp any value going into a cell.

    Three jobs in one helper so every ``ws.cell(...value=...)`` call is
    covered by going through here:

    1. :func:`_format_dt` — convert any datetime (object or ISO string)
       to a naive datetime in UTC-5 so Excel shows local time.
    2. :func:`_clean_for_excel` — strip control characters cookie / IDB /
       IM payloads routinely carry, which otherwise crash
       ``Workbook.save`` with ``IllegalCharacterError``.
    3. Length clamp to Excel's 32 767-char cell limit.
    """
    value = _format_dt(value)
    value = _clean_for_excel(value)
    if isinstance(value, str) and len(value) > limit:
        return value[: limit - 3] + "…"
    return value


def _format_dt(value):
    """Render *value* as a naive datetime in :data:`REPORT_TZ` (UTC-5).

    Accepts both ``datetime`` objects (aware or naive — naive assumed
    UTC, since all extractors emit UTC) and ISO-8601 strings (which is
    what :meth:`ArtifactBase.to_dict` produces). Anything else passes
    through unchanged so we don't break URL / text columns that happen
    to live in the same row.

    The returned datetime is naive because openpyxl needs naive
    datetimes to format them as date cells; the tz info is stripped
    after the conversion to UTC-5 happened.
    """
    if value is None or value == "":
        return value
    dt: Optional[datetime] = None
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, str):
        # Cheap pre-check: ISO datetimes start with YYYY-MM-DD. Anything
        # else (URLs, plain text, etc.) skips the parse cost.
        if len(value) >= 10 and value[4:5] == "-" and value[7:8] == "-":
            stripped = value.rstrip("Z")
            try:
                dt = datetime.fromisoformat(stripped)
            except (TypeError, ValueError):
                return value
            if value.endswith("Z") and dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
    if dt is None:
        return value
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(REPORT_TZ)
    return dt.replace(tzinfo=None)


# ---------------------------------------------------------------------------
# Exporter
# ---------------------------------------------------------------------------


class XlsxExporter(ExporterBase):
    """Excel workbook with one sheet per artifact + an interpretation sheet.

    Optionally pulls additional forensic data tables (search terms,
    accounts, IM messages, JWT tokens, OS artifacts, IOCs, findings,
    chain-of-custody, analyst notes, domain enrichment) directly from
    the :class:`SessionStore` when one is provided — see the *store*
    and *extras* kwargs.
    """

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
        """Write the XLSX workbook to *out_path*.

        ``profile_ids`` filters the extra-table sheets (search_terms,
        accounts, …) to only rows belonging to those profile IDs. When
        ``None`` every row in the store is included. ``bundles`` is
        already filtered by the caller.
        """
        if not _HAS_OPENPYXL:
            raise RuntimeError(
                "openpyxl is not installed — run `pip install openpyxl` to enable XLSX export."
            )
        out = Path(out_path)
        if out.is_dir() or out.suffix.lower() != ".xlsx":
            out = (out / "webforensics.xlsx") if out.is_dir() else out.with_suffix(".xlsx")
        out.parent.mkdir(parents=True, exist_ok=True)

        kinds_list = [k for k in kinds if k in ARTIFACT_KINDS]
        extras_list = [e for e in extras if e in EXTRA_TABLES]
        bundles_list = list(bundles)
        pid_filter = list(profile_ids) if profile_ids is not None else None

        wb = Workbook()
        wb.remove(wb.active)

        self._write_overview(wb, bundles_list, kinds_list, extras_list, store)
        self._write_profiles(wb, bundles_list)

        for kind in kinds_list:
            self._write_artifact_sheet(wb, kind, bundles_list)

        # Forensic extras (only when the caller passed a store).
        if store is not None and extras_list:
            for table in extras_list:
                self._write_extra_sheet(wb, store, table, pid_filter)

        self._write_errors(wb, bundles_list)

        wb.save(out)
        return out

    # --- Sheets -----------------------------------------------------------

    def _write_overview(
        self,
        wb,
        bundles: list[ProfileBundle],
        kinds: list[str],
        extras: list[str] = (),
        store=None,
    ) -> None:
        ws = wb.create_sheet("Resumen")
        title_font = Font(name="Calibri", size=18, bold=True, color="1F4E78")
        section_font = Font(name="Calibri", size=12, bold=True, color="1F4E78")
        body_font = Font(name="Calibri", size=11)
        wrap = Alignment(wrap_text=True, vertical="top")

        ws["A1"] = "WebForensics — reporte de análisis"
        ws["A1"].font = title_font
        ws.merge_cells("A1:F1")

        ws["A3"] = (
            "Reporte de extracción y análisis de perfiles de navegador. "
            "Cada hoja contiene un tipo de artefacto independiente. "
            "El glosario al final de esta hoja documenta el significado de cada uno. "
            f"Todas las fechas y horas están en hora local {REPORT_TZ_LABEL}."
        )
        ws["A3"].font = body_font
        ws["A3"].alignment = wrap
        ws.merge_cells("A3:F4")

        # Profile summary block
        ws["A6"] = "Perfiles analizados"
        ws["A6"].font = section_font
        ws["A7"] = "Navegador"
        ws["B7"] = "Perfil"
        ws["C7"] = "Total elementos"
        for col, kind in enumerate(kinds, start=4):
            ws.cell(row=7, column=col, value=kind)
            ws.cell(row=7, column=col).font = section_font
        ws["A7"].font = section_font
        ws["B7"].font = section_font
        ws["C7"].font = section_font

        row = 8
        for bundle in bundles:
            ws.cell(row=row, column=1, value=bundle.browser)
            ws.cell(row=row, column=2, value=bundle.profile)
            total = sum(len(bundle.get(k)) for k in kinds)
            ws.cell(row=row, column=3, value=total)
            for col, kind in enumerate(kinds, start=4):
                ws.cell(row=row, column=col, value=len(bundle.get(kind)))
            row += 1
        if not bundles:
            ws.cell(row=row, column=1, value="(sin perfiles)")
            row += 1

        # Glosario de artefactos
        row += 2
        ws.cell(row=row, column=1, value="Glosario de artefactos")
        ws.cell(row=row, column=1).font = section_font
        row += 1
        for kind in kinds:
            es = _ARTIFACT_INTERPRETATIONS.get(kind, "")
            ws.cell(row=row, column=1, value=kind).font = Font(bold=True)
            ws.cell(row=row, column=2, value=es).alignment = wrap
            ws.merge_cells(start_row=row, start_column=2, end_row=row, end_column=6)
            row += 2

        # Explain the extras too if any were selected.
        if extras:
            row += 1
            ws.cell(row=row, column=1, value="Datos forenses adicionales").font = section_font
            row += 1
            for extra in extras:
                es = EXTRA_INTERPRETATIONS.get(extra, "")
                ws.cell(row=row, column=1, value=EXTRA_TABLE_HUMAN_NAMES.get(extra, extra)).font = Font(bold=True)
                ws.cell(row=row, column=2, value=es).alignment = wrap
                ws.merge_cells(start_row=row, start_column=2, end_row=row, end_column=6)
                row += 2

        # Estadísticas y hallazgos automáticos
        row += 1
        ws.cell(row=row, column=1, value="Hallazgos").font = section_font
        row += 1
        for line in self._highlights(bundles, extras, store):
            ws.cell(row=row, column=1, value="•")
            ws.cell(row=row, column=2, value=line).alignment = wrap
            ws.merge_cells(start_row=row, start_column=2, end_row=row, end_column=6)
            row += 1

        # Column widths
        widths = (16, 28, 14, 14, 14, 14)
        for idx, w in enumerate(widths, start=1):
            ws.column_dimensions[get_column_letter(idx)].width = w
        ws.row_dimensions[3].height = 60
        ws.freeze_panes = "A7"

    def _write_profiles(self, wb, bundles: list[ProfileBundle]) -> None:
        ws = wb.create_sheet("Perfiles")
        headers = ("Navegador", "Perfil", "Ruta", "Total artefactos", "Errores")
        self._write_header_row(ws, headers)
        for row_idx, bundle in enumerate(bundles, start=2):
            total = sum(len(bundle.get(k)) for k in ARTIFACT_KINDS)
            ws.cell(row=row_idx, column=1, value=bundle.browser)
            ws.cell(row=row_idx, column=2, value=bundle.profile)
            ws.cell(row=row_idx, column=3, value=_truncate(bundle.path))
            ws.cell(row=row_idx, column=4, value=total)
            ws.cell(row=row_idx, column=5, value="; ".join(bundle.errors[:5]))
        self._finalize(ws, headers, max(2, len(bundles) + 1))

    def _write_artifact_sheet(
        self,
        wb,
        kind: str,
        bundles: list[ProfileBundle],
    ) -> None:
        # Excel sheet names: 31 chars max, no certain chars.
        sheet_name = kind.replace("_", " ").title()[:31]
        ws = wb.create_sheet(sheet_name)

        # First: a 2-row banner with the friendly description. History
        # tacks on the visit_type legend so the analyst doesn't have to
        # cross-reference what each code means.
        banner = _ARTIFACT_INTERPRETATIONS.get(kind, "")
        if kind == "history":
            legend_lines = ["", "Tipos de visita (columna visit_type):"]
            for code, meaning in _VISIT_TYPE_LEGEND.items():
                legend_lines.append(f"  • {code}: {meaning}")
            banner = banner + "\n" + "\n".join(legend_lines)
        ws["A1"] = banner
        ws["A1"].font = Font(italic=True, color="444444")
        ws["A1"].alignment = Alignment(wrap_text=True, vertical="top")
        # Make the row tall enough to show the multi-line legend for History.
        ws.row_dimensions[1].height = 320 if kind == "history" else 48

        rows: list[dict] = []
        for bundle in bundles:
            for item in bundle.get(kind):
                rows.append(item.to_dict())

        if not rows:
            ws["A3"] = "(sin datos)"
            ws.merge_cells("A1:H1")
            return

        # Union of all keys, stable order, hidden columns excluded.
        fieldnames: list[str] = []
        for r in rows:
            for k in r:
                if k not in fieldnames and _visible_fieldname(k) is not None:
                    fieldnames.append(k)
        display_names = [_visible_fieldname(k) for k in fieldnames]

        # Merge banner across all columns.
        last_col_letter = get_column_letter(len(fieldnames))
        ws.merge_cells(f"A1:{last_col_letter}1")

        # Header row at row 3, data starts at row 4.
        header_row = 3
        self._write_header_row(ws, display_names, row=header_row)

        # Column tooltips (Excel comments) using the field hints. The
        # hint table is keyed by the *raw* field name, so we look up
        # using ``name`` even when the display column is renamed.
        hints = _FIELD_HINTS.get(kind, {})
        from openpyxl.comments import Comment
        for col_idx, name in enumerate(fieldnames, start=1):
            hint = hints.get(name)
            if hint:
                cell = ws.cell(row=header_row, column=col_idx)
                cell.comment = Comment(hint, "WebForensics")

        for r_idx, row in enumerate(rows, start=header_row + 1):
            for c_idx, name in enumerate(fieldnames, start=1):
                value = _value_for_export(name, row.get(name))
                # _truncate runs _format_dt + _clean_for_excel internally —
                # do NOT call _format_dt here too or naive datetimes get
                # converted twice and shift by another -5 hours.
                ws.cell(row=r_idx, column=c_idx, value=_truncate(value))

        self._finalize(ws, display_names, header_row + len(rows), header_row=header_row)

    def _write_extra_sheet(
        self,
        wb,
        store,
        table: str,
        profile_ids: list[int] | None = None,
    ) -> None:
        """Dump an arbitrary SessionStore table to its own sheet.

        Uses a SELECT * to stay schema-agnostic. When *profile_ids* is
        provided AND the target table has a ``profile_id`` column, the
        query is filtered to those profiles so per-profile exports stay
        consistent across all sheets.
        """
        human = EXTRA_TABLE_HUMAN_NAMES.get(table, table)
        sheet_name = human[:31]
        ws = wb.create_sheet(sheet_name)

        es = EXTRA_INTERPRETATIONS.get(table, "")
        ws["A1"] = es
        ws["A1"].font = Font(italic=True, color="444444")
        ws["A1"].alignment = Alignment(wrap_text=True, vertical="top")
        ws.row_dimensions[1].height = 56

        try:
            conn = store.connection()
            # Detect whether this table carries a profile_id we can filter on.
            table_cols = {
                r[1] for r in conn.execute(f"PRAGMA table_info({table})")
            }
            sql = f"SELECT * FROM {table}"
            params: tuple = ()
            if profile_ids and "profile_id" in table_cols:
                placeholders = ",".join("?" for _ in profile_ids)
                sql += f" WHERE profile_id IN ({placeholders})"
                params = tuple(profile_ids)
            cursor = conn.execute(sql, params)
            columns = [d[0] for d in cursor.description] if cursor.description else []
            rows = cursor.fetchall()
        except Exception as exc:  # noqa: BLE001
            ws["A2"] = f"(error leyendo tabla: {exc})"
            return

        if not columns:
            ws["A3"] = "(sin columnas)"
            return

        # Apply the same hidden-column + bytes-to-MB transforms the
        # per-artifact sheets use, so behaviour is consistent across the
        # whole workbook (e.g. source_files.size → size_mb).
        columns = [c for c in columns if _visible_fieldname(c) is not None]
        display_columns = [_visible_fieldname(c) for c in columns]

        if not rows:
            last_col_letter = get_column_letter(max(1, len(columns)))
            ws.merge_cells(f"A1:{last_col_letter}1")
            ws["A3"] = "(sin datos)"
            return

        last_col_letter = get_column_letter(len(columns))
        ws.merge_cells(f"A1:{last_col_letter}1")

        header_row = 3
        self._write_header_row(ws, display_columns, row=header_row)
        for r_idx, row in enumerate(rows, start=header_row + 1):
            for c_idx, col in enumerate(columns, start=1):
                value = _value_for_export(col, row[col])
                # _truncate handles tz conversion + char sanitisation in one shot.
                ws.cell(row=r_idx, column=c_idx, value=_truncate(value))
        self._finalize(ws, display_columns, header_row + len(rows), header_row=header_row)

    def _write_errors(self, wb, bundles: list[ProfileBundle]) -> None:
        # Collect all errors with their profile context.
        errors: list[tuple[str, str, str]] = []
        for bundle in bundles:
            for err in bundle.errors:
                errors.append((bundle.browser, bundle.profile, err))
        if not errors:
            return
        ws = wb.create_sheet("Errores")
        ws["A1"] = (
            "Mensajes informativos y de error del proceso de extracción. La mayoría son notas "
            "(p. ej. 'image source = X.E01' o 'carved N deleted history records'), no fallos críticos."
        )
        ws["A1"].alignment = Alignment(wrap_text=True, vertical="top")
        ws["A1"].font = Font(italic=True, color="444444")
        ws.row_dimensions[1].height = 36
        headers = ("Navegador", "Perfil", "Mensaje")
        ws.merge_cells("A1:C1")
        self._write_header_row(ws, headers, row=3)
        for idx, (br, prof, err) in enumerate(errors, start=4):
            ws.cell(row=idx, column=1, value=br)
            ws.cell(row=idx, column=2, value=prof)
            ws.cell(row=idx, column=3, value=_truncate(err))
        self._finalize(ws, headers, 3 + len(errors), header_row=3)

    # --- Findings -----------------------------------------------------

    def _highlights(
        self,
        bundles: list[ProfileBundle],
        extras: list[str] = (),
        store=None,
    ) -> list[str]:
        """Generate plain-language bullet points about the dataset."""
        out: list[str] = []
        if not bundles:
            return ["No se analizaron perfiles."]

        total_hist = sum(len(b.history) for b in bundles)
        total_cookies = sum(len(b.cookies) for b in bundles)
        total_logins = sum(len(b.logins) for b in bundles)
        total_dl = sum(len(b.downloads) for b in bundles)
        total_ext = sum(len(b.extensions) for b in bundles)

        out.append(
            f"Se procesaron {len(bundles)} perfil(es): "
            f"{total_hist:,} entradas de historial, {total_cookies:,} cookies, "
            f"{total_logins:,} credenciales guardadas, {total_dl:,} descargas, "
            f"{total_ext:,} extensiones."
        )

        # Top hosts in history.
        host_counter: Counter[str] = Counter()
        for b in bundles:
            for h in b.history:
                host = _host(h.url)
                if host:
                    host_counter[host] += int(h.visit_count) or 1
        if host_counter:
            top = host_counter.most_common(5)
            top_text = ", ".join(f"{h} ({c:,})" for h, c in top)
            out.append(f"Hosts más visitados (por visit_count): {top_text}.")

        # Category counts.
        cat_counter: Counter[str] = Counter()
        for b in bundles:
            for h in b.history:
                if h.category:
                    cat_counter[h.category] += 1
        if cat_counter:
            cat_pairs = [(c, n) for c, n in cat_counter.most_common() if c]
            label = ", ".join(
                f"{_CATEGORY_LABELS_ES.get(c, c)} = {n}" for c, n in cat_pairs[:8]
            )
            out.append(f"Categorías de navegación detectadas: {label}.")

        # Notable categories: highlight dark web / vpn / banking / crypto.
        notable = {"darkweb", "vpn_proxy", "crypto", "gambling", "adult"}
        for cat in notable:
            n = cat_counter.get(cat, 0)
            if n:
                out.append(
                    f"⚠ Se detectaron {n} entrada(s) en la categoría '{_CATEGORY_LABELS_ES.get(cat, cat)}'. "
                    f"Revisa la hoja 'History' filtrando por category = '{cat}'."
                )

        # Saved credentials inventory.
        cred_sites = {l.origin_url for b in bundles for l in b.logins if l.origin_url}
        if cred_sites:
            sample = ", ".join(sorted(cred_sites)[:10])
            extra = "" if len(cred_sites) <= 10 else f" (y {len(cred_sites)-10} más)"
            out.append(
                f"Hay credenciales guardadas para {len(cred_sites)} sitio(s): {sample}{extra}. "
                f"Revisa la hoja 'Logins' para detalle."
            )

        # Encrypted logins/cookies.
        n_enc_logins = sum(1 for b in bundles for l in b.logins if l.encrypted)
        n_enc_cookies = sum(1 for b in bundles for c in b.cookies if c.encrypted)
        if n_enc_logins or n_enc_cookies:
            out.append(
                f"No se pudieron descifrar {n_enc_logins} contraseña(s) ni {n_enc_cookies} cookie(s). "
                f"Esto es esperable en imágenes forenses cuando no se tiene la clave DPAPI del usuario."
            )

        # Carved (deleted) content.
        n_carved = sum(1 for b in bundles for h in b.history if h.deleted)
        if n_carved:
            out.append(
                f"Se recuperaron {n_carved} entrada(s) de historial BORRADO por el usuario "
                f"(visit_type = 'carved' en la hoja 'History')."
            )

        # Risky extensions heuristic.
        risky_keywords = ("vpn", "proxy", "tor", "wallet", "crypto", "anonym", "history clean", "incognito")
        risky_ext = [
            f"{b.browser}/{e.name}"
            for b in bundles for e in b.extensions
            if any(k in (e.name or "").lower() or k in (e.description or "").lower() for k in risky_keywords)
        ]
        if risky_ext:
            out.append(
                "Extensiones potencialmente relevantes (VPN/proxy/crypto/anti-forenses): "
                + ", ".join(risky_ext[:8])
                + ("…" if len(risky_ext) > 8 else "")
            )

        # Downloads — list executables and archives.
        risky_dl = [
            d for b in bundles for d in b.downloads
            if (d.target_path or "").lower().endswith((".exe", ".msi", ".bat", ".ps1", ".zip", ".rar", ".7z"))
        ]
        if risky_dl:
            out.append(
                f"Se descargaron {len(risky_dl)} archivo(s) ejecutable o comprimido(s). "
                f"Revisa la hoja 'Downloads' filtrando por extensión .exe, .msi, .zip, etc."
            )

        # Highlights from extra tables when we have a store.
        if store is not None and extras:
            try:
                for table in extras:
                    count = self._count_table(store, table)
                    if count:
                        out.append(
                            f"{EXTRA_TABLE_HUMAN_NAMES.get(table, table)}: {count:,} fila(s). "
                            f"Detalle en la hoja correspondiente."
                        )
            except Exception:  # noqa: BLE001
                pass
            # Specific spotlights worth calling out.
            try:
                ioc_hits_count = self._count_table(store, "ioc_hits")
                if "ioc_hits" in extras and ioc_hits_count:
                    out.append(
                        f"⚠ Se registraron {ioc_hits_count:,} coincidencia(s) de IOC. "
                        f"Revisa primero la hoja 'IOC matches'."
                    )
            except Exception:  # noqa: BLE001
                pass
            try:
                critical_findings = self._count_findings_by_severity(store, ("critical", "high"))
                if "findings" in extras and critical_findings:
                    out.append(
                        f"⚠ Hallazgos forenses críticos / altos: {critical_findings}. "
                        f"Revisa la hoja 'Findings' filtrando por severity = critical o high."
                    )
            except Exception:  # noqa: BLE001
                pass

        return out

    def _count_table(self, store, table: str) -> int:
        try:
            row = store.connection().execute(f"SELECT COUNT(*) AS n FROM {table}").fetchone()
            return int(row["n"] or 0)
        except Exception:  # noqa: BLE001
            return 0

    def _count_findings_by_severity(self, store, severities) -> int:
        placeholders = ",".join("?" for _ in severities)
        try:
            row = store.connection().execute(
                f"SELECT COUNT(*) AS n FROM findings WHERE severity IN ({placeholders})",
                tuple(severities),
            ).fetchone()
            return int(row["n"] or 0)
        except Exception:  # noqa: BLE001
            return 0

    # --- Styling helpers ---------------------------------------------

    def _write_header_row(self, ws, headers: Iterable[str], row: int = 1) -> None:
        fill = PatternFill("solid", fgColor="1F4E78")
        font = Font(bold=True, color="FFFFFF")
        thin = Side(border_style="thin", color="DDDDDD")
        border = Border(left=thin, right=thin, top=thin, bottom=thin)
        for col_idx, name in enumerate(headers, start=1):
            cell = ws.cell(row=row, column=col_idx, value=name)
            cell.fill = fill
            cell.font = font
            cell.border = border

    def _finalize(
        self,
        ws,
        headers,
        last_row: int,
        header_row: int = 1,
    ) -> None:
        n_cols = len(list(headers))
        if n_cols == 0:
            return
        # Auto-size columns based on header + sample of values.
        for col_idx in range(1, n_cols + 1):
            max_len = 0
            letter = get_column_letter(col_idx)
            for r in range(header_row, min(header_row + 200, last_row + 1)):
                v = ws.cell(row=r, column=col_idx).value
                if v is None:
                    continue
                s = str(v)
                if len(s) > max_len:
                    max_len = len(s)
            ws.column_dimensions[letter].width = min(max(12, max_len + 2), 60)
        # Freeze the header so data scrolls under it.
        ws.freeze_panes = ws.cell(row=header_row + 1, column=1).coordinate
        # AutoFilter on the data range.
        if last_row > header_row:
            end_letter = get_column_letter(n_cols)
            ws.auto_filter.ref = f"A{header_row}:{end_letter}{last_row}"
