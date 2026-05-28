"""WebForensics — entry point.

Browser forensics tool for Google Chrome, Microsoft Edge (Chromium) and
Mozilla Firefox. Launches the Qt GUI.
"""

import sys


def _is_windows_admin() -> bool:
    if sys.platform != "win32":
        return False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001
        return False


def _elevate_if_needed() -> bool:
    """Relaunch the current process via UAC when started without admin.

    Returns ``True`` if we are already admin (or not on Windows).
    Returns ``False`` if the user cancelled the UAC prompt — the caller
    keeps running unelevated and the features that require admin will
    show their own "se requieren permisos de Administrador" messages.
    When relaunching succeeds, the current (unelevated) process exits.

    The packaged ``.exe`` carries a ``requireAdministrator`` manifest, so
    in production this function is a no-op. It only fires when someone
    runs ``python main.py`` from a non-elevated shell during development.
    """
    if sys.platform != "win32" or _is_windows_admin():
        return True
    import ctypes
    # Quote each argv entry so paths with spaces survive the round-trip
    # through ShellExecute's single-string parameter list.
    params = " ".join(f'"{a}"' for a in sys.argv[1:])
    rc = ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable,
        f'"{sys.argv[0]}" {params}'.strip(),
        None, 1,
    )
    if rc > 32:
        sys.exit(0)  # the elevated copy is now running
    return False     # user cancelled UAC; continue without admin


def main() -> int:
    _elevate_if_needed()
    from PyQt5.QtWidgets import QApplication
    from ui.main_window import MainWindow

    app = QApplication(sys.argv)
    app.setApplicationName("WebForensics")
    app.setOrganizationName("WixaDevelop")
    window = MainWindow()
    window.show()
    return app.exec_()


if __name__ == "__main__":
    sys.exit(main())
