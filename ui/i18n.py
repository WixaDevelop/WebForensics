"""Tiny in-process translator.

Qt's full ``QTranslator`` workflow (.ts → .qm via lupdate / lrelease) is heavier
than this app needs — we only have a few dozen visible strings and no plural
forms. So we keep the table in Python: ``tr(key)`` looks up the active locale
and falls back to the key itself.

To add a language: add it to ``_TABLE`` with the same keys.
"""

from __future__ import annotations

from typing import Callable, List

# Current locale code; ``en`` is the source language.
_locale = "en"
_observers: List[Callable[[], None]] = []


_TABLE: dict[str, dict[str, str]] = {
    # ── Toolbar / menu actions ────────────────────────────────────────────
    "Auto-detect":       {"es": "Auto-detectar"},
    "Open profile…":     {"es": "Abrir perfil…"},
    "Auto-detect in folder…":     {"es": "Auto-detectar en carpeta…"},
    "Recursively scan a folder for browser profiles":
        {"es": "Escanear recursivamente una carpeta en busca de perfiles"},
    "Select folder to scan": {"es": "Selecciona la carpeta a escanear"},
    "Scanning folder…":      {"es": "Escaneando carpeta…"},

    # ── Folder scan results dialog ───────────────────────────────────────
    "Folder scan results":   {"es": "Resultados del escaneo"},
    "Found {total} profile(s) under {folder}\n  • {primary} primary browser profile(s)\n  • {embedded} embedded WebView2 / CEF profile(s) (apps with built-in browsers)\n\nTick the profiles you want to extract. Embedded profiles can hold tokens, cookies and history from the host app's auth flows.":
        {"es": "Se encontraron {total} perfil(es) en {folder}\n  • {primary} perfil(es) de navegador principal\n  • {embedded} perfil(es) WebView2 / CEF embebidos (apps con navegador integrado)\n\nMarca los perfiles que quieres extraer. Los embebidos pueden contener tokens, cookies e historial de los flujos de autenticación de la app contenedora."},
    "Select all":            {"es": "Seleccionar todo"},
    "Primary only":          {"es": "Solo principales"},
    "Select none":           {"es": "Deseleccionar todo"},
    "Primary browsers":      {"es": "Navegadores principales"},
    "Embedded WebView / CEF profiles": {"es": "Perfiles WebView / CEF embebidos"},
    "Path":                  {"es": "Ruta"},

    # ── VSS prompt ──────────────────────────────────────────────────────
    "Include VSS shadow copies?": {"es": "¿Incluir VSS shadow copies?"},
    "Windows reports {n} Volume Shadow Copy/copies on {drive}.\nThese are point-in-time snapshots that may contain pristine copies of browser profiles from earlier dates — useful when the live profile has been wiped or rolled forward.\n\nInclude them in the scan? (one extra pass per snapshot)":
        {"es": "Windows reporta {n} VSS snapshot(s) en {drive}.\nSon copias del volumen tomadas en momentos pasados que pueden contener perfiles de navegador en estados anteriores — útil cuando el perfil en vivo fue borrado o sobreescrito.\n\n¿Incluirlas en el escaneo? (una pasada extra por snapshot)"},
    "Folder scan failed":    {"es": "Fallo al escanear la carpeta"},
    "No profiles found":     {"es": "No se encontraron perfiles"},
    "No profiles found in image": {"es": "No se encontraron perfiles en la imagen"},

    # ── BitLocker dialog ─────────────────────────────────────────────────
    "BitLocker partition detected": {"es": "Partición BitLocker detectada"},
    "One or more partitions in this image are encrypted with BitLocker. Supply at least one credential below to unlock them.":
        {"es": "Una o más particiones de esta imagen están cifradas con BitLocker. Proporcione al menos una credencial para desbloquearlas."},
    "Password:":          {"es": "Contraseña:"},
    "User/login password": {"es": "Contraseña de usuario/login"},
    "Recovery key:":      {"es": "Clave de recuperación:"},
    "48-digit recovery key (with or without dashes)":
        {"es": "Clave de recuperación de 48 dígitos (con o sin guiones)"},
    "Startup key:":       {"es": "Clave de inicio:"},
    "Path to a .bek startup key file":
        {"es": "Ruta a un archivo de clave de inicio .bek"},
    "Browse…":            {"es": "Examinar…"},
    "Select BitLocker startup key (.bek)":
        {"es": "Selecciona el archivo de clave de inicio (.bek)"},
    "FVEK (hex):":        {"es": "FVEK (hex):"},
    "Full volume encryption key (hex, optional)":
        {"es": "Clave de cifrado de volumen completo (hex, opcional)"},
    "Skip BitLocker":     {"es": "Omitir BitLocker"},
    "Continue without unlocking — only readable partitions will be scanned.":
        {"es": "Continuar sin desbloquear — solo se escanearán las particiones legibles."},
    "Open failed":        {"es": "Error al abrir"},
    "BitLocker format not supported by libbde":
        {"es": "Formato BitLocker no soportado por libbde"},
    "This image contains a BitLocker-encrypted partition ({size:.1f} GiB) that uses a newer format libbde cannot parse yet.\n\nRecommended workflow:\n1. Mount the image with Arsenal Image Mounter, OSFMount or FTK Imager (read-only).\n2. In Windows, right-click the BitLocker partition → \"Unlock drive…\" → enter your recovery key.\n3. Back here, use \"Auto-detect in folder…\" and point it at the mounted drive root (e.g. F:\\).\n\nlibbde error: {err}\n\nContinue scanning the readable partitions of this image anyway?":
        {"es": "Esta imagen contiene una partición cifrada con BitLocker ({size:.1f} GiB) que usa un formato más nuevo que libbde todavía no sabe leer (Win11 22H2+).\n\nFlujo recomendado:\n1. Monta la imagen con Arsenal Image Mounter, OSFMount o FTK Imager (sólo lectura).\n2. En Windows, clic derecho sobre la partición BitLocker → \"Desbloquear unidad…\" → introduce la recovery key.\n3. Vuelve aquí y usa \"Auto-detectar en carpeta…\" apuntando a la raíz de la unidad montada (ej. F:\\).\n4. Opcional: si quieres escanear también VSS snapshots de la imagen, expón los con 'vshadow.exe -el=<id>' o 'vssadmin list shadows' tras montar.\n\nError de libbde: {err}\n\n¿Continuar escaneando las particiones legibles de esta imagen de todos modos?"},
    "No browser profiles could be staged from this image.\n\nDiagnostic details:\n\n{details}":
        {"es": "No se pudieron extraer perfiles de navegador de esta imagen.\n\nDetalle del diagnóstico:\n\n{details}"},
    "No browser profiles were detected anywhere under:\n\n{folder}\n\nThe scanner looked for Chromium (History) and Firefox/Tor (places.sqlite) signature files.":
        {"es": "No se detectaron perfiles de navegador bajo:\n\n{folder}\n\nEl escáner buscó archivos firma de Chromium (History) y Firefox/Tor (places.sqlite)."},
    "Open image (E01)…": {"es": "Abrir imagen (E01)…"},
    "Search":            {"es": "Buscar"},
    "Export…":           {"es": "Exportar…"},
    "Save session":      {"es": "Guardar sesión"},
    "Open session":      {"es": "Abrir sesión"},
    "Dark theme":        {"es": "Tema oscuro"},
    "Light theme":       {"es": "Tema claro"},
    "IOCs…":             {"es": "IOCs…"},
    "Findings":          {"es": "Hallazgos"},
    "Language":          {"es": "Idioma"},
    "English":           {"es": "Inglés"},
    "Spanish":           {"es": "Español"},

    # ── Menus ─────────────────────────────────────────────────────────────
    "&File":             {"es": "&Archivo"},
    "&Tools":            {"es": "&Herramientas"},
    "&View":             {"es": "&Ver"},
    "&Help":             {"es": "Ay&uda"},
    "E&xit":             {"es": "&Salir"},
    "&About":            {"es": "&Acerca de"},
    "Audit log…":        {"es": "Registro de auditoría…"},
    "Compare sessions…": {"es": "Comparar sesiones…"},
    "Collect OS artifacts": {"es": "Recolectar artefactos del SO"},
    "Enrich domains":       {"es": "Enriquecer dominios"},
    "Graph":                {"es": "Grafo"},

    # ── Tabs ──────────────────────────────────────────────────────────────
    "History":     {"es": "Historial"},
    "Cookies":     {"es": "Cookies"},
    "Downloads":   {"es": "Descargas"},
    "Logins":      {"es": "Credenciales"},
    "Bookmarks":   {"es": "Marcadores"},
    "Autofill":    {"es": "Autocompletar"},
    "Extensions":  {"es": "Extensiones"},
    "Timeline":    {"es": "Línea de tiempo"},
    "Charts":      {"es": "Gráficos"},
    "Searches":    {"es": "Búsquedas"},
    "Cache Entries": {"es": "Caché"},
    "Web Storage":   {"es": "Almacenamiento web"},
    "Open Tabs":     {"es": "Pestañas abiertas"},
    "Permissions":   {"es": "Permisos"},

    # ── Status bar / generic ──────────────────────────────────────────────
    "Ready":          {"es": "Listo"},
    "Profile":        {"es": "Perfil"},
    "Items":          {"es": "Elementos"},
    "Extracting":     {"es": "Extrayendo"},
    "Done":           {"es": "Listo"},

    # ── Dialog buttons ────────────────────────────────────────────────────
    "OK":     {"es": "Aceptar"},
    "Cancel": {"es": "Cancelar"},
    "Close":  {"es": "Cerrar"},
    "Load file…":    {"es": "Cargar archivo…"},
    "Match now":     {"es": "Hacer match ahora"},
    "Clear all":     {"es": "Limpiar todo"},
    "Run analysers": {"es": "Ejecutar analizadores"},
    "Reset":         {"es": "Restablecer"},

    # ── Tooltips ──────────────────────────────────────────────────────────
    "Scan default install locations for browser profiles":
        {"es": "Escanear las rutas de instalación por defecto en busca de perfiles"},
    "Open a forensic image (E01 / .dd / .img)":
        {"es": "Abrir una imagen forense (E01 / .dd / .img)"},
}


def tr(key: str) -> str:
    """Return the translation of *key* in the active locale.

    Unknown keys are returned as-is so missing strings still render.
    """
    if _locale == "en":
        return key
    bucket = _TABLE.get(key)
    if not bucket:
        return key
    return bucket.get(_locale, key)


def set_locale(locale: str) -> None:
    """Switch the active locale and notify observers (so the UI can re-render)."""
    global _locale
    if locale not in ("en", "es"):
        return
    if locale == _locale:
        return
    _locale = locale
    for observer in list(_observers):
        try:
            observer()
        except Exception:  # noqa: BLE001 — never let one bad widget break the rest
            pass


def current_locale() -> str:
    return _locale


def on_change(observer: Callable[[], None]) -> None:
    """Register a callback to fire whenever the locale changes."""
    if observer not in _observers:
        _observers.append(observer)
