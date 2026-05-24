"""WebForensics — entry point.

Browser forensics tool for Google Chrome, Microsoft Edge (Chromium) and
Mozilla Firefox. Launches the Qt GUI.
"""

import sys

from PyQt5.QtWidgets import QApplication

from ui.main_window import MainWindow


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("WebForensics")
    app.setOrganizationName("WixaDevelop")
    window = MainWindow()
    window.show()
    return app.exec_()


if __name__ == "__main__":
    sys.exit(main())
