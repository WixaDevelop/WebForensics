"""Excel export variant for non-technical review (legal, accounting, etc).

Same data as the technical XLSX exporter — no row is hidden, no column
is dropped — but every value-side technical term is translated to plain
Spanish and a leading "Guía de lectura" sheet documents how to read
the workbook from scratch.

What changes vs the technical XLSX:

* Column headers shown as plain Spanish phrases (``url`` →
  ``Dirección web``, ``last_visit`` → ``Última visita``, etc).
* Coded values translated in-cell:
  - ``visit_type='typed'`` → ``URL ingresada en la barra de direcciones``
  - ``state='complete'``  → ``Descarga completada``
  - ``severity='high'``    → ``Severidad alta``
  - booleans as ``Sí`` / ``No``
* Internal-only columns (``bates_id``, ``source_file_id``, ``profile_id``)
  hidden — they only matter inside the app.
* First sheet is a "Guía de lectura" that introduces what a browser
  profile is, what each kind of artefact represents, how to filter in
  Excel, and what NOT to infer from the data.

The technical XLSX exporter remains the default for analysts.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Iterable

from data.models import ARTIFACT_KINDS, ProfileBundle
from exporters.xlsx_exporter import (
    EXTRA_INTERPRETATIONS,
    EXTRA_TABLES,
    EXTRA_TABLE_HUMAN_NAMES,
    REPORT_TZ_LABEL,
    XlsxExporter,
    _ARTIFACT_INTERPRETATIONS,
    _BYTES_TO_MB_COLUMNS,
    _VISIT_TYPE_LEGEND,
    _clean_for_excel,
    _format_dt,
    _value_for_export,
)

try:  # pragma: no cover — declared in requirements.txt
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
    from openpyxl.utils import get_column_letter
except Exception:  # noqa: BLE001
    Workbook = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Plain-Spanish column names
# ---------------------------------------------------------------------------


# Headers shown to the reviewer. Whatever doesn't have a mapping falls
# back to the raw column name (with bytes-to-MB renaming applied as in
# the technical exporter).
_REVIEW_HEADER_NAMES: dict[str, str] = {
    # Common across artifacts
    "browser":        "Navegador",
    "profile":        "Perfil",
    "id":             "ID interno",
    # History
    "url":            "Dirección web",
    "title":          "Título de la página",
    "visit_count":    "Visitas registradas",
    "typed_count":    "Visitas con URL ingresada manualmente",
    "last_visit":     "Última visita registrada",
    "visit_type":     "Tipo de visita",
    "from_visit_url": "Página de procedencia (referrer)",
    # Cookies
    "host":           "Dominio que dejó la cookie",
    "name":           "Nombre",
    "value":          "Valor",
    "path":           "Ruta dentro del sitio",
    "expires":        "Fecha de expiración",
    "created":        "Fecha de creación",
    "last_access":    "Último envío al sitio",
    "secure":         "Solo HTTPS",
    "http_only":      "Inaccesible para JavaScript",
    "same_site":      "Política SameSite",
    "encrypted":      "Cifrado (no descifrable)",
    # Downloads
    "target_path":    "Ruta local del archivo descargado",
    "referrer":       "Página desde donde se inició la descarga",
    "mime_type":      "Tipo de archivo (MIME)",
    "total_mb":       "Tamaño total (MB)",
    "received_mb":    "MB efectivamente descargados",
    "state":          "Estado de la descarga",
    "start_time":     "Inicio de la descarga",
    "end_time":       "Fin de la descarga",
    # Logins
    "origin_url":     "Sitio web",
    "action_url":     "URL del formulario de login",
    "username":       "Usuario",
    "password":       "Contraseña descifrada",
    "date_created":   "Primera vez guardada",
    "date_last_used": "Última vez utilizada",
    "times_used":     "Veces utilizada",
    # Bookmarks
    "folder":         "Carpeta",
    "date_added":     "Fecha en que se guardó el favorito",
    "date_modified":  "Última modificación del favorito",
    # Autofill
    "field_name":     "Nombre del campo del formulario",
    "count":          "Veces que el valor fue reutilizado",
    "first_used":     "Primera vez registrada",
    "last_used":      "Última vez registrada",
    # Extensions
    "extension_id":   "ID de la extensión",
    "version":        "Versión",
    "description":    "Descripción",
    "enabled":        "Habilitada",
    "install_path":   "Ruta local de instalación",
    # Cache
    "size_mb":        "Tamaño (MB)",
    "fetched_at":     "Primera vez descargado",
    "status_code":    "Código HTTP",
    "source":         "Origen del registro",
    # Web storage
    "origin":         "Dominio dueño del dato",
    "kind":           "Tipo de almacén",
    "key":            "Clave",
    "last_modified":  "Última modificación",
    # Open tabs
    "session":        "Sesión",
    "window_idx":     "Ventana #",
    "tab_idx":        "Pestaña #",
    "last_active":    "Última vez activa",
    "pinned":         "Fijada",
    # Permissions
    "permission":     "Permiso",
    "setting":        "Configuración",
    # Extras
    "engine":         "Motor de búsqueda",
    "query":          "Consulta",
    "ts":             "Marca temporal",
    "service":        "Servicio",
    "identifier":     "Identificador interno",
    "email":          "Correo electrónico",
    "detail":         "Detalle",
    "last_seen":      "Última vez vista",
    "app":            "Aplicación",
    "chat_id":        "ID del chat",
    "chat_name":      "Nombre del chat",
    "sender_id":      "ID del remitente",
    "sender_name":    "Nombre del remitente",
    "body":           "Contenido del mensaje",
    "issuer":         "Emisor",
    "subject":        "Sujeto",
    "scope":          "Permisos / scope",
    "expires_at":     "Expira en",
    "user_agent":     "User-Agent",
    "first_seen":     "Primera vez vista",
    "seen_count":     "Veces vista",
    "severity":       "Severidad",
    "category":       "Categoría",  # only used by extras tables that we don't filter
    "loaded_at":      "Cargado en la sesión",
    "matched_field":  "Campo en el que coincidió",
    "matched_value":  "Valor de la coincidencia",
    "created_at":     "Creado en",
    "artifact_kind":  "Tipo de artefacto",
    "artifact_id":    "ID del artefacto",
    "ioc_id":         "ID del IOC",
    "source_path":    "Ruta del origen",
    "extra":          "Metadatos extra",
    "sha256":         "SHA-256 (huella criptográfica)",
    "mtime":          "Última modificación del archivo",
    "atime":          "Último acceso al archivo",
    "ctime":          "Creación del archivo",
    "image_path":     "Ruta de la imagen forense",
    "image_offset":   "Offset dentro de la imagen",
    "read_at":        "Leído por la herramienta en",
    "domain":         "Dominio",
    "registrar":      "Registrador",
    "registered_at":  "Fecha de registro",
    "asn":            "ASN (proveedor)",
    "country":        "País",
    "risk":           "Nivel de riesgo",
    "notes":          "Notas",
    "refreshed_at":   "Datos actualizados en",
    "tag":            "Etiqueta",
    "note":           "Nota del analista",
}


# Columns hidden in the review export. Mix of:
#  * pure bookkeeping (id, profile_id, bates_id, source_file_id)
#  * positional / internal indices (window_idx, tab_idx, image_offset)
#  * very technical HTTP / cookie internals (path, same_site, status_code,
#    referrer, from_visit_url)
#  * source-path columns the reviewer can't act on (source, source_path,
#    install_path, extra)
#  * cross-table foreign keys (chat_id, sender_id, ioc_id, artifact_id)
# Everything else stays — and when the remaining column is technical
# we attach a plain-Spanish tooltip with a concrete example.
_REVIEW_HIDE_EXTRA: set[str] = {
    # Bookkeeping
    "id", "profile_id", "bates_id", "source_file_id",
    # Positional / internal indices
    "window_idx", "tab_idx", "image_offset",
    # HTTP / cookie internals only an analyst reads
    "path", "same_site", "status_code", "referrer", "from_visit_url",
    # Internal source paths
    "source", "source_path", "install_path",
    # Heavy / unstructured payloads
    "extra",
    # Cross-table FKs
    "chat_id", "sender_id", "ioc_id", "artifact_id",
    "matched_field",
    # Inner long blob
    "value" if False else None,  # cookie/storage values can stay (already sanitised)
}
_REVIEW_HIDE_EXTRA.discard(None)


# Plain-Spanish tooltips with a concrete mini-example. Used in the
# review export to override the technical tooltips inherited from
# ``exporters.xlsx_exporter._FIELD_HINTS``. The lookup is by raw
# column name (the same key used by the parent).
_REVIEW_HINTS: dict[str, str] = {
    # --- History ----------------------------------------------------------
    "url": "Dirección web completa. Ej: 'https://www.bbva.com.ec/personas/banca-digital' "
           "= la página de banca digital del BBVA.",
    "title": "Título que el sitio mostró en la pestaña. Ej: 'BBVA — Banca en Línea'.",
    "visit_count": "Veces que el navegador registró que se abrió esa URL. "
                   "Ej: '12' = se abrió 12 veces en total.",
    "typed_count": "De todas las visitas, cuántas comenzaron escribiendo la dirección "
                   "directamente en la barra superior del navegador. Ej: '3' = se escribió "
                   "a mano 3 veces; las otras visitas vinieron de clicks en enlaces o favoritos.",
    "last_visit": "Última vez que el navegador registró la apertura de esta URL, en hora "
                  "local UTC-5. Ej: '2026-05-27 14:30:00' = miércoles 27 de mayo a las 2:30 pm.",
    "visit_type": "De qué manera se llegó a la URL (escribiéndola, click en enlace, "
                  "favorito, etc.). Ver la leyenda al pie del banner para el detalle.",
    # --- Cookies ----------------------------------------------------------
    "host": "Dominio del sitio que generó la cookie. "
            "Ej: '.google.com' = cualquier cookie de Google y sus subdominios.",
    "name": "Nombre interno de la cookie. Ej: 'SID' suele ser una cookie de sesión de Google.",
    "value": "Contenido de la cookie. Suele ser un código opaco (ej: 'A1B2C3...') o aparece "
             "vacío si no se pudo descifrar.",
    "expires": "Cuándo la cookie deja de ser válida según el sitio que la creó. Ej: "
               "'2027-01-01 00:00:00' = válida hasta el inicio de 2027.",
    "created": "Momento en que el navegador guardó esta cookie por primera vez en este equipo.",
    "last_access": "Última vez que el navegador envió esta cookie al sitio. Indica actividad reciente.",
    "secure": "'Sí' = la cookie solo se transmite por conexiones cifradas (HTTPS). "
              "'No' = puede viajar también por HTTP no cifrado.",
    "http_only": "'Sí' = solo el servidor puede leerla, JavaScript en la página no. Es una "
                 "protección contra robo de cookies.",
    "encrypted": "'Sí' = el valor está cifrado por Windows DPAPI y la app no pudo descifrarlo "
                 "(suele requerir el perfil original de Windows abierto). 'No' = el contenido "
                 "está visible en la columna 'Valor'.",
    # --- Downloads --------------------------------------------------------
    "target_path": "Ruta en el disco donde el navegador guardó el archivo descargado. Ej: "
                   "'C:\\Users\\juan\\Downloads\\contrato.pdf'. Verificar la existencia real "
                   "del archivo en esa ruta requiere revisar el sistema aparte.",
    "mime_type": "Tipo de archivo. Ejemplos comunes: 'application/pdf' = documento PDF, "
                 "'image/jpeg' = foto JPG, 'video/mp4' = video, 'application/zip' = comprimido, "
                 "'application/x-msi' / 'application/x-msdownload' = instalador de Windows.",
    "total_mb": "Tamaño total del archivo en megabytes (binario). Ej: '5.0' = 5 MB.",
    "received_mb": "Cuántos MB se llegaron a descargar. Si coincide con el total, la descarga "
                   "se completó; si es menor, quedó incompleta.",
    "state": "Estado de la descarga: 'Descarga completada', 'Descarga en curso', 'Descarga "
             "cancelada' o 'Descarga interrumpida'.",
    "start_time": "Cuándo empezó la descarga (hora local UTC-5).",
    "end_time": "Cuándo terminó la descarga. Si está vacío, no terminó.",
    # --- Logins -----------------------------------------------------------
    "origin_url": "Sitio web donde se guardó el usuario y contraseña. "
                  "Ej: 'https://github.com' = se guardó una credencial de GitHub.",
    "username": "Nombre de usuario / correo guardado para ese sitio.",
    "password": "Contraseña descifrada. Si está vacía y la columna 'Cifrado' dice 'Sí', "
                "significa que no se pudo descifrar (no se tiene la clave del Windows original).",
    "date_created": "Primera vez que se guardó esta credencial en el navegador.",
    "date_last_used": "Última vez que el autocompletado del navegador usó esta credencial.",
    "times_used": "Veces que el autocompletado del navegador rellenó esta credencial.",
    # --- Bookmarks --------------------------------------------------------
    "folder": "Carpeta dentro de los favoritos del navegador. Ej: 'Barra de favoritos/Bancos'.",
    "date_added": "Cuándo se guardó el favorito.",
    "date_modified": "Última vez que se editó el favorito (nombre o URL).",
    # --- Autofill ---------------------------------------------------------
    "field_name": "Nombre del campo en el formulario. Ej: 'email', 'telefono', 'address-line1'.",
    "count": "Veces que ese valor se usó para autocompletar.",
    "first_used": "Primera vez que el navegador registró este valor.",
    "last_used": "Última vez que el navegador autocompletó este valor.",
    # --- Extensions -------------------------------------------------------
    "extension_id": "Identificador único de la extensión (32 letras). Ej: "
                    "'cjpalhdlnbpafiamejdnhcphjbkeiagm' es el ID de uBlock Origin. Pegándolo "
                    "en chrome.google.com/webstore o addons.mozilla.org se identifica la extensión.",
    "version": "Versión instalada de la extensión. Ej: '1.55.0'.",
    "description": "Descripción que pone el autor de la extensión.",
    "enabled": "'Sí' = estaba habilitada al hacer la extracción. 'No' = instalada pero desactivada.",
    # --- Cache ------------------------------------------------------------
    "size_mb": "Tamaño del recurso en caché, en MB. Ej: '0.5' = medio MB.",
    "fetched_at": "Primera vez que el navegador descargó este recurso al caché.",
    # --- Web storage ------------------------------------------------------
    "origin": "Sitio web dueño del dato. Ej: 'https://web.whatsapp.com'.",
    "kind": "Tipo de almacén interno del navegador. 'LocalStorage' = datos permanentes; "
            "'SessionStorage' = solo mientras esté abierta la pestaña; 'IndexedDB' = base de "
            "datos local (suele contener mensajes de WhatsApp Web, Discord, etc.).",
    "key": "Nombre del dato guardado. Ej: 'user_preferences', 'last_login_token'.",
    "last_modified": "Última vez que el dato fue modificado.",
    # --- Permissions ------------------------------------------------------
    "permission": "Tipo de permiso solicitado por el sitio. Ej: 'camera' = cámara, "
                  "'microphone' = micrófono, 'geolocation' = ubicación, 'notifications' = "
                  "avisos en pantalla, 'midi' / 'usb' / 'serial' = dispositivos conectados.",
    "setting": "Decisión registrada para ese permiso: 'Permitido', 'Bloqueado', 'Pregunta cada vez', "
               "'Solo por sesión'.",
    # --- Extras: search_terms ---------------------------------------------
    "engine": "Buscador donde se hizo la consulta. Ej: 'google', 'bing', 'duckduckgo', 'youtube'.",
    "query": "Lo que se escribió en el buscador. Ej: 'precios celular samsung'.",
    "ts": "Cuándo ocurrió (hora local UTC-5).",
    # --- Extras: accounts -------------------------------------------------
    "service": "Servicio identificado. Ej: 'google', 'facebook', 'twitter', 'github', 'discord'.",
    "identifier": "ID interno que el servicio usa para esa cuenta. Ej: en Facebook es un número "
                  "como '100012345678901'.",
    "email": "Correo asociado a la cuenta cuando se pudo determinar.",
    "detail": "Detalles adicionales (rol, foto de perfil, etc.) cuando se pudieron recuperar.",
    "last_seen": "Última vez que la cuenta apareció en datos del navegador.",
    # --- Extras: messages -------------------------------------------------
    "app": "App de mensajería de donde salió el mensaje. Ej: 'whatsapp', 'discord', 'telegram'.",
    "chat_name": "Nombre del chat o grupo. Ej: 'Familia', 'Trabajo - Ventas'.",
    "sender_name": "Nombre del que envió el mensaje, tal como aparece en la app.",
    "body": "Contenido del mensaje recuperado.",
    # --- Extras: tokens ---------------------------------------------------
    "issuer": "Quién emitió el token. Ej: 'https://accounts.google.com'.",
    "subject": "Para qué cuenta es el token. Suele ser un ID o correo.",
    "scope": "Permisos que tiene el token. Ej: 'email profile openid' = puede leer correo, "
             "perfil y autenticar.",
    "expires_at": "Cuándo el token deja de ser válido.",
    # --- Extras: user_agents ----------------------------------------------
    "user_agent": "Cadena con la que el navegador se identifica a los servidores. Ej: "
                  "'Mozilla/5.0 (Windows NT 10.0; Win64; x64) ... Chrome/120.0.0.0' = "
                  "Chrome 120 en Windows 10/11 de 64 bits. Sirve para detectar uso desde "
                  "otros dispositivos (móvil, otro PC, etc.).",
    "first_seen": "Primera vez que se vio esta cadena.",
    "seen_count": "Veces que se vio esta cadena durante el análisis.",
    # --- Extras: findings -------------------------------------------------
    "severity": "Importancia del hallazgo. 'Crítica' = revisar inmediatamente, 'Alta' = revisar "
                "pronto, 'Media' = atender después, 'Baja' = informativo, 'Informativa' = "
                "solo dato.",
    "title": "Resumen del hallazgo en una línea.",
    # --- Extras: iocs / ioc_hits ------------------------------------------
    "matched_value": "Valor exacto encontrado en el caso que coincidió con un IOC marcado por "
                     "el analista. Ej: dominio 'malware.example.com'.",
    "loaded_at": "Cuándo el analista cargó este IOC en la sesión.",
    # --- Extras: os_artifacts ---------------------------------------------
    # 'kind' here gets the storage hint above — same word, different table.
    # We accept the slight ambiguity; both hints are short and contextually clear.
    # --- Extras: source_files (cadena de custodia) ------------------------
    "sha256": "Huella digital única del archivo (64 caracteres en hexadecimal). Si dos archivos "
              "tienen el mismo SHA-256 son idénticos byte por byte; si cambia un solo byte el "
              "SHA-256 cambia por completo. Ej: '7e2c3a8f4b1d...'. Esta huella prueba que el "
              "archivo no fue alterado.",
    "image_path": "Si el archivo se leyó desde una imagen forense, la ruta del archivo de imagen "
                  "(ej: 'B:\\caso1\\evidencia.E01').",
    "mtime": "Última modificación del archivo en el sistema original.",
    "atime": "Último acceso al archivo en el sistema original.",
    "ctime": "Creación del archivo en el sistema original.",
    "read_at": "Cuándo WebForensics leyó este archivo durante la extracción.",
    # --- Extras: domain_intel ---------------------------------------------
    "domain": "Dominio web. Ej: 'banco.example.com'.",
    "registrar": "Empresa donde fue registrado el dominio. Ej: 'GoDaddy', 'Namecheap'.",
    "registered_at": "Cuándo se creó el registro del dominio.",
    "asn": "Proveedor de internet que aloja el dominio. Ej: 'AS15169 — Google LLC'.",
    "country": "País donde se registró el dominio. Ej: 'EC' = Ecuador, 'US' = Estados Unidos.",
    "risk": "Nivel de riesgo según la heurística de la app: 'info' / 'medium' / 'high'.",
    # --- Extras: tags -----------------------------------------------------
    "tag": "Etiqueta libre que el analista escribió. Ej: 'evidencia', 'sospechoso', 'revisar'.",
    "note": "Nota adicional del analista sobre la fila marcada.",
    "created_at": "Cuándo el analista creó la nota o etiqueta.",
}


# ---------------------------------------------------------------------------
# Per-value translation tables
# ---------------------------------------------------------------------------


# Translation of every visit_type code to a phrase the reviewer can
# read without prior knowledge. Includes the rarer / browser-specific
# codes so even if a row carries one of them, the cell value remains
# legible — the banner legend only documents the common ones.
_VISIT_TYPE_HUMAN = {
    "typed":             "URL ingresada en la barra de direcciones",
    "link":              "Click en un enlace de otra página",
    "auto_bookmark":     "Apertura desde un favorito",
    "bookmark":          "Apertura desde un favorito",
    "auto_subframe":     "Subframe / iframe cargado automáticamente",
    "manual_subframe":   "Subframe / iframe activado desde la página",
    "generated":         "URL generada por autocompletado",
    "auto_toplevel":     "Navegación automática (redirección)",
    "form_submit":       "Envío de formulario",
    "reload":            "Recarga (F5 / Ctrl+R)",
    "keyword":           "Búsqueda con palabra clave del navegador",
    "keyword_generated": "URL generada por palabra clave",
    "embed":             "Recurso embebido en la página",
    "redirect_permanent": "Redirección HTTP 301 (permanente)",
    "redirect_temporary": "Redirección HTTP 302 / 303 / 307",
    "download":          "URL que terminó en descarga",
    "framed_link":       "Click en enlace dentro de iframe",
    "carved":            "Fila recuperada de espacio borrado",
}


_DOWNLOAD_STATE_HUMAN = {
    "complete":     "Descarga completada",
    "in_progress":  "Descarga en curso",
    "cancelled":    "Descarga cancelada",
    "interrupted": "Descarga interrumpida",
}


_SEVERITY_HUMAN = {
    "critical": "Crítica",
    "high":     "Alta",
    "medium":   "Media",
    "low":      "Baja",
    "info":     "Informativa",
}


_PERMISSION_SETTING_HUMAN = {
    "allow":   "Permitido",
    "block":   "Bloqueado",
    "ask":     "Pregunta cada vez",
    "session": "Solo por sesión",
}


_STORAGE_KIND_HUMAN = {
    "localstorage":   "LocalStorage",
    "sessionstorage": "SessionStorage",
    "indexeddb":      "IndexedDB",
}


_TAB_SESSION_HUMAN = {
    "current": "Sesión activa",
    "last":    "Sesión anterior",
}


# Columns whose VALUES should be translated. Keyed by raw column name
# (so it works the same way in artifact sheets and extras sheets).
_VALUE_TRANSLATORS: dict[str, dict[str, str]] = {
    "visit_type":  _VISIT_TYPE_HUMAN,
    "state":       _DOWNLOAD_STATE_HUMAN,
    "severity":    _SEVERITY_HUMAN,
    "setting":     _PERMISSION_SETTING_HUMAN,
    "kind":        _STORAGE_KIND_HUMAN,  # benign collision with iocs.kind / messages.kind
    "session":     _TAB_SESSION_HUMAN,
}


# Booleans → Sí / No instead of True / False.
_BOOLEAN_COLUMNS: set[str] = {
    "secure", "http_only", "encrypted", "enabled", "pinned",
}


def _translate_value(name: str, value):
    """Apply per-column value translation for the review export."""
    if value is None or value == "":
        return value
    if name in _BOOLEAN_COLUMNS:
        # SQLite stores booleans as 0/1, dataclass-based bundles as bool.
        try:
            return "Sí" if int(value) else "No"
        except (TypeError, ValueError):
            return value
    if name in _VALUE_TRANSLATORS:
        return _VALUE_TRANSLATORS[name].get(str(value), value)
    return value


def _review_header(raw_name: str) -> str:
    """Return the analyst-friendly display name for *raw_name*."""
    # Bytes-to-MB rename already happened in the parent class — use the
    # post-rename name when looking up.
    return _REVIEW_HEADER_NAMES.get(raw_name, raw_name)


def _review_visible(raw_name: str):
    """Same as the parent's _visible_fieldname but also hides internal
    bookkeeping columns (id, profile_id, bates_id, source_file_id)."""
    if raw_name in _REVIEW_HIDE_EXTRA:
        return None
    from exporters.xlsx_exporter import _visible_fieldname
    return _visible_fieldname(raw_name)


# ---------------------------------------------------------------------------
# Exporter
# ---------------------------------------------------------------------------


class XlsxReviewExporter(XlsxExporter):
    """Same workbook structure as :class:`XlsxExporter`, friendlier wording.

    Overrides the four sheet writers so they all use the plain-Spanish
    column names and translate coded values in-cell. The "Resumen"
    sheet from the parent is kept and a new "Guía de lectura" sheet is
    inserted before it.
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
        if Workbook is None:
            raise RuntimeError(
                "openpyxl is not installed — run `pip install openpyxl` to enable XLSX export."
            )
        out = Path(out_path)
        if out.is_dir() or out.suffix.lower() != ".xlsx":
            out = (out / "webforensics-revision.xlsx") if out.is_dir() else out.with_suffix(".xlsx")
        out.parent.mkdir(parents=True, exist_ok=True)

        kinds_list = [k for k in kinds if k in ARTIFACT_KINDS]
        extras_list = [e for e in extras if e in EXTRA_TABLES]
        bundles_list = list(bundles)
        pid_filter = list(profile_ids) if profile_ids is not None else None

        wb = Workbook()
        wb.remove(wb.active)

        # First sheet: long-form reading guide.
        self._write_reading_guide(wb, bundles_list, kinds_list, extras_list)
        # Then the parent's summary + per-artifact + extras + errors.
        self._write_overview(wb, bundles_list, kinds_list, extras_list, store)
        self._write_profiles(wb, bundles_list)
        for kind in kinds_list:
            self._write_artifact_sheet(wb, kind, bundles_list)
        if store is not None and extras_list:
            for table in extras_list:
                self._write_extra_sheet(wb, store, table, pid_filter)
        self._write_errors(wb, bundles_list)

        wb.save(out)
        return out

    # --- Reading guide ---------------------------------------------------

    def _write_reading_guide(
        self,
        wb,
        bundles: list[ProfileBundle],
        kinds: list[str],
        extras: list[str],
    ) -> None:
        ws = wb.create_sheet("Guía de lectura")
        title_font = Font(name="Calibri", size=18, bold=True, color="1F4E78")
        section_font = Font(name="Calibri", size=12, bold=True, color="1F4E78")
        wrap = Alignment(wrap_text=True, vertical="top")

        ws["A1"] = "Cómo leer este reporte"
        ws["A1"].font = title_font
        ws.merge_cells("A1:F1")

        intro = (
            "Este libro de Excel contiene la información extraída de uno o más perfiles de "
            "navegador web durante una revisión forense. Cada hoja corresponde a una categoría "
            "de información que el navegador guarda automáticamente mientras se usa.\n\n"
            "Este reporte documenta QUÉ se encontró en los archivos del navegador. La "
            "interpretación de qué significa cada hallazgo — si una visita fue intencional, si "
            "una cuenta es propia del titular del equipo, si una descarga se completó "
            "correctamente — corresponde al analista responsable del caso. Las filas y celdas "
            "muestran datos tal como el navegador los registró, sin inferencias.\n\n"
            f"Todas las fechas y horas están convertidas a hora local {REPORT_TZ_LABEL}. Todos "
            "los tamaños se muestran en MB (binario: 1 MB = 1 048 576 bytes)."
        )
        ws["A3"] = intro
        ws["A3"].alignment = wrap
        ws.merge_cells("A3:F8")

        row = 10
        ws.cell(row=row, column=1, value="¿Qué es un perfil de navegador?").font = section_font
        row += 1
        ws.cell(row=row, column=1, value=(
            "Cada navegador (Chrome, Edge, Firefox, etc.) guarda en una carpeta dentro del "
            "sistema operativo los datos de uso de una cuenta de Windows: historial, cookies, "
            "favoritos, contraseñas guardadas, etc. Esa carpeta se llama 'perfil'. Un mismo "
            "equipo puede tener varios perfiles si el navegador permite cuentas separadas o "
            "si distintas cuentas de Windows usaron el equipo."
        )).alignment = wrap
        ws.merge_cells(start_row=row, start_column=1, end_row=row, end_column=6)
        ws.row_dimensions[row].height = 80
        row += 2

        ws.cell(row=row, column=1, value="Cómo navegar este libro").font = section_font
        row += 1
        nav_lines = [
            "• La hoja 'Resumen' enumera los perfiles procesados y un glosario por tipo de dato.",
            "• Cada hoja con nombre de un artefacto (Historial, Cookies, Descargas, etc.) tiene "
            "un encabezado con la explicación de qué muestra y, debajo, los datos en formato tabla.",
            "• En cada hoja puedes filtrar y ordenar usando los menús desplegables del encabezado "
            "de la tabla (las flechitas pequeñas a la derecha de cada columna).",
            "• Para buscar un término en todas las hojas: Ctrl+F → 'Opciones' → 'Buscar en: Libro'.",
            "• Las columnas con encabezado en gris claro tienen un comentario flotante explicando "
            "qué significa el campo. Pasa el cursor por encima del encabezado para verlo.",
        ]
        for line in nav_lines:
            ws.cell(row=row, column=1, value=line).alignment = wrap
            ws.merge_cells(start_row=row, start_column=1, end_row=row, end_column=6)
            ws.row_dimensions[row].height = 32
            row += 1
        row += 1

        ws.cell(row=row, column=1, value="Qué NO se puede afirmar a partir de estos datos").font = section_font
        row += 1
        warnings = [
            "• La presencia de una URL en el historial NO demuestra por sí sola que un humano la "
            "visitó conscientemente: scripts, redirecciones automáticas, pre-carga y notificaciones "
            "del navegador también generan entradas en historial.",
            "• La presencia de una cookie de un servicio NO equivale a tener una sesión activa "
            "en ese servicio: las cookies pueden caducar, ser eliminadas o haber sido depositadas "
            "por scripts de terceros.",
            "• La presencia de credenciales guardadas para un sitio NO prueba que la cuenta es "
            "del titular del equipo: el navegador guarda lo que se le indique sin verificación.",
            "• Las filas marcadas como 'carved' o 'eliminadas' fueron recuperadas del espacio "
            "borrado del archivo SQLite del navegador, pero el mecanismo que produjo la "
            "eliminación (acción humana, limpieza automática, fin de sesión, etc.) no está "
            "registrado en el dato.",
            "• Los hallazgos en la hoja 'Hallazgos forenses' son alertas heurísticas automáticas "
            "que ameritan revisión humana, no conclusiones definitivas.",
        ]
        for w_line in warnings:
            ws.cell(row=row, column=1, value=w_line).alignment = wrap
            ws.merge_cells(start_row=row, start_column=1, end_row=row, end_column=6)
            ws.row_dimensions[row].height = 50
            row += 1
        row += 1

        ws.cell(row=row, column=1, value="Glosario rápido con ejemplos").font = section_font
        row += 1
        glossary = [
            ("URL",
             "Dirección web completa. Es todo lo que aparece en la barra de direcciones del "
             "navegador. Ej: 'https://www.bbva.com.ec/personas/banca-digital' = página de banca "
             "digital del BBVA Ecuador."),
            ("Dominio",
             "El nombre del sitio sin las barras ni prefijos. De la URL 'https://www.google.com/"
             "search?q=hola', el dominio es 'google.com'."),
            ("Cookie",
             "Archivito pequeño que un sitio web deja en el navegador para reconocerte cuando "
             "vuelves. Ej: cuando entras a Facebook y al día siguiente ya estás dentro sin "
             "volver a poner tu usuario, es porque Facebook dejó una cookie en tu navegador."),
            ("HTTPS / HTTP",
             "Forma en que el navegador se comunica con un sitio. 'https://' (con la 's' de "
             "Secure) significa que la conversación va cifrada — nadie en la red puede leerla. "
             "'http://' es sin cifrar y se considera inseguro."),
            ("SHA-256",
             "Huella digital del archivo. Es un código de 64 letras y números (ej: "
             "'7e2c3a8f4b1d...'). Si dos archivos tienen exactamente el mismo SHA-256 son "
             "idénticos byte por byte. Si cambia un solo byte del archivo, el SHA-256 cambia por "
             "completo. Sirve para probar que un archivo no fue alterado."),
            ("MIME",
             "Forma de clasificar archivos. Ejemplos: 'application/pdf' = PDF; 'image/jpeg' = "
             "foto JPG; 'video/mp4' = video; 'application/zip' = comprimido ZIP; "
             "'application/x-msi' = instalador de Windows; 'text/html' = página web."),
            ("LocalStorage / IndexedDB",
             "Lugares donde los sitios web guardan información dentro del navegador. WhatsApp "
             "Web por ejemplo guarda allí los mensajes. Los sitios de noticias guardan tus "
             "preferencias de lectura. Discord guarda allí la lista de canales y mensajes "
             "recientes."),
            ("JWT",
             "Es un tipo de 'pase digital' que los servicios web usan para identificar al "
             "usuario. Cuando una app móvil o web te deja entrar sin volver a pedir contraseña, "
             "lleva un JWT escondido en cada petición. Decodificarlo muestra para qué cuenta es, "
             "qué permisos tiene y cuándo expira."),
            ("IOC",
             "Indicador de algo malo. Antes del análisis, el analista carga una lista de "
             "dominios, IPs o hashes sospechosos (ej: dominios de malware conocidos), y la app "
             "marca todas las apariciones de esos valores dentro del caso."),
            ("VSS / Shadow Copy",
             "Fotos del estado del disco que Windows toma automáticamente cada cierto tiempo. "
             "Permiten recuperar archivos como estaban hace una semana o un mes — incluso si el "
             "usuario los borró o los modificó después."),
            ("DPAPI",
             "Sistema de Windows que cifra las contraseñas guardadas y algunas cookies. La "
             "clave para descifrar está atada al perfil de Windows original. Si solo tenemos "
             "una imagen forense del disco pero no el equipo encendido con la sesión original "
             "abierta, esas contraseñas y cookies aparecen como 'Cifrado: Sí' y no se pueden leer."),
            ("Carved",
             "Recuperado del espacio borrado. Cuando alguien borra el historial o las cookies, "
             "los datos no desaparecen al instante: quedan en huecos del archivo hasta que algo "
             "nuevo los sobreescribe. 'Carved' es lo que la app pudo rescatar de esos huecos."),
            ("UTC-5",
             "Zona horaria del reporte. Todas las fechas y horas del libro están convertidas "
             "a UTC-5 (hora local de Ecuador / Colombia / Perú). Si la hora original era UTC "
             "(hora universal), restar 5 horas da la hora local."),
            ("MB (megabytes)",
             "Unidad de tamaño. En este reporte 1 MB = 1024 KB = 1 048 576 bytes. Para dar "
             "una idea: una foto típica = 2-5 MB; un PDF típico = 0.5-2 MB; un video corto "
             "de Whatsapp = 5-20 MB; un instalador grande = 100+ MB."),
        ]
        for term, definition in glossary:
            ws.cell(row=row, column=1, value=term).font = Font(bold=True)
            ws.cell(row=row, column=2, value=definition).alignment = wrap
            ws.merge_cells(start_row=row, start_column=2, end_row=row, end_column=6)
            ws.row_dimensions[row].height = 56
            row += 1

        # Column widths.
        widths = (24, 24, 14, 14, 14, 14)
        for idx, w in enumerate(widths, start=1):
            ws.column_dimensions[get_column_letter(idx)].width = w

    # --- Overrides ------------------------------------------------------

    def _write_artifact_sheet(self, wb, kind, bundles):
        # Reuse the parent's body but with reviewer-friendly headers and
        # value translation. We don't call ``super()`` because we need
        # to mutate column names + cell values in lock-step.
        sheet_name = kind.replace("_", " ").title()[:31]
        ws = wb.create_sheet(sheet_name)

        banner = _ARTIFACT_INTERPRETATIONS.get(kind, "")
        if kind == "history":
            legend_lines = ["", "Tipos de visita (columna 'Tipo de visita'):"]
            for code, meaning in _VISIT_TYPE_LEGEND.items():
                human_label = _VISIT_TYPE_HUMAN.get(code, code)
                legend_lines.append(f"  • {human_label}: {meaning}")
            banner = banner + "\n" + "\n".join(legend_lines)
        ws["A1"] = banner
        ws["A1"].font = Font(italic=True, color="444444")
        ws["A1"].alignment = Alignment(wrap_text=True, vertical="top")
        ws.row_dimensions[1].height = 360 if kind == "history" else 56

        rows: list[dict] = []
        for bundle in bundles:
            for item in bundle.get(kind):
                rows.append(item.to_dict())

        if not rows:
            ws["A3"] = "(sin datos para esta categoría)"
            ws.merge_cells("A1:H1")
            return

        # Collect raw fieldnames respecting per-export filters.
        fieldnames: list[str] = []
        for r in rows:
            for k in r:
                if k in fieldnames:
                    continue
                if _review_visible(k) is not None:
                    fieldnames.append(k)
        display_names = [_review_header(_review_visible(k)) for k in fieldnames]

        last_col_letter = get_column_letter(len(fieldnames))
        ws.merge_cells(f"A1:{last_col_letter}1")

        header_row = 3
        self._write_header_row(ws, display_names, row=header_row)

        # Column tooltips — prefer the plain-Spanish + example tooltips
        # defined in _REVIEW_HINTS, fall back to the technical ones for
        # any column we haven't rewritten yet.
        from openpyxl.comments import Comment
        from exporters.xlsx_exporter import _FIELD_HINTS
        technical_hints = _FIELD_HINTS.get(kind, {})
        for col_idx, name in enumerate(fieldnames, start=1):
            hint = _REVIEW_HINTS.get(name) or technical_hints.get(name)
            if hint:
                ws.cell(row=header_row, column=col_idx).comment = Comment(hint, "WebForensics")

        for r_idx, row in enumerate(rows, start=header_row + 1):
            for c_idx, name in enumerate(fieldnames, start=1):
                value = _value_for_export(name, row.get(name))
                value = _translate_value(name, value)
                ws.cell(row=r_idx, column=c_idx, value=_truncate_review(value))

        self._finalize(ws, display_names, header_row + len(rows), header_row=header_row)

    def _write_extra_sheet(self, wb, store, table, profile_ids=None):
        # Same body as the parent's extras sheet, with column rename + value translation.
        human = EXTRA_TABLE_HUMAN_NAMES.get(table, table)
        ws = wb.create_sheet(human[:31])
        es = EXTRA_INTERPRETATIONS.get(table, "")
        ws["A1"] = es
        ws["A1"].font = Font(italic=True, color="444444")
        ws["A1"].alignment = Alignment(wrap_text=True, vertical="top")
        ws.row_dimensions[1].height = 64

        try:
            conn = store.connection()
            table_cols = {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
            sql = f"SELECT * FROM {table}"
            params: tuple = ()
            if profile_ids and "profile_id" in table_cols:
                placeholders = ",".join("?" for _ in profile_ids)
                sql += f" WHERE profile_id IN ({placeholders})"
                params = tuple(profile_ids)
            cursor = conn.execute(sql, params)
            raw_columns = [d[0] for d in cursor.description] if cursor.description else []
            rows = cursor.fetchall()
        except Exception as exc:  # noqa: BLE001
            ws["A2"] = f"(error leyendo tabla: {exc})"
            return

        if not raw_columns:
            ws["A3"] = "(sin columnas)"
            return

        columns = [c for c in raw_columns if _review_visible(c) is not None]
        display_columns = [_review_header(_review_visible(c)) for c in columns]

        if not rows:
            ws.merge_cells(f"A1:{get_column_letter(max(1, len(columns)))}1")
            ws["A3"] = "(sin datos para esta categoría)"
            return

        ws.merge_cells(f"A1:{get_column_letter(len(columns))}1")
        header_row = 3
        self._write_header_row(ws, display_columns, row=header_row)

        # Per-column tooltips with plain-Spanish examples.
        from openpyxl.comments import Comment
        for col_idx, raw in enumerate(columns, start=1):
            hint = _REVIEW_HINTS.get(raw)
            if hint:
                ws.cell(row=header_row, column=col_idx).comment = Comment(hint, "WebForensics")

        for r_idx, row in enumerate(rows, start=header_row + 1):
            for c_idx, col in enumerate(columns, start=1):
                value = _value_for_export(col, row[col])
                value = _translate_value(col, value)
                ws.cell(row=r_idx, column=c_idx, value=_truncate_review(value))
        self._finalize(ws, display_columns, header_row + len(rows), header_row=header_row)


def _truncate_review(value, limit: int = 32767):
    """Variant of the parent's _truncate that runs after value translation.

    Translation can produce strings ("Sí", "Permitido", "URL ingresada en
    la barra de direcciones") that the parent's sanitisation step still
    has to clean (in case translation passed an untranslated raw byte
    value through), then truncate.
    """
    value = _format_dt(value)
    value = _clean_for_excel(value)
    if isinstance(value, str) and len(value) > limit:
        return value[: limit - 3] + "…"
    return value
