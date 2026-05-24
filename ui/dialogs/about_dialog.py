"""Static "About" dialog."""

from __future__ import annotations

from PyQt5.QtWidgets import QDialog, QDialogButtonBox, QLabel, QVBoxLayout


_ABOUT_HTML = """
<h2>WebForensics</h2>
<p>Forensic analysis tool for Google Chrome, Microsoft Edge (Chromium) and
Mozilla Firefox profiles.</p>
<p>Extracts history, cookies, downloads, saved logins, bookmarks, autofill
data and installed extensions; exports to CSV, JSON or an HTML report.</p>
<p><b>License:</b> Custom Non-Commercial — contact
<a href="mailto:wiixa.devp@gmail.com">wiixa.devp@gmail.com</a> for commercial use.</p>
<p><b>Repository:</b>
<a href="https://github.com/WixaDevelop/WebForensics">github.com/WixaDevelop/WebForensics</a></p>
"""


class AboutDialog(QDialog):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("About WebForensics")
        self.setMinimumWidth(420)
        layout = QVBoxLayout(self)
        label = QLabel(_ABOUT_HTML)
        label.setOpenExternalLinks(True)
        label.setWordWrap(True)
        layout.addWidget(label)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok)
        buttons.accepted.connect(self.accept)
        layout.addWidget(buttons)
