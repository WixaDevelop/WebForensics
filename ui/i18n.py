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
