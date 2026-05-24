"""Light and dark Qt palettes used by the toolbar's theme toggle."""

from __future__ import annotations

from PyQt5.QtGui import QColor, QPalette


def light_palette() -> QPalette:
    p = QPalette()
    p.setColor(QPalette.Window, QColor("#f6f8fa"))
    p.setColor(QPalette.WindowText, QColor("#1f2328"))
    p.setColor(QPalette.Base, QColor("#ffffff"))
    p.setColor(QPalette.AlternateBase, QColor("#f6f8fa"))
    p.setColor(QPalette.ToolTipBase, QColor("#ffffff"))
    p.setColor(QPalette.ToolTipText, QColor("#1f2328"))
    p.setColor(QPalette.Text, QColor("#1f2328"))
    p.setColor(QPalette.Button, QColor("#f0f3f6"))
    p.setColor(QPalette.ButtonText, QColor("#1f2328"))
    p.setColor(QPalette.Highlight, QColor("#2563eb"))
    p.setColor(QPalette.HighlightedText, QColor("#ffffff"))
    return p


def dark_palette() -> QPalette:
    p = QPalette()
    p.setColor(QPalette.Window, QColor("#1f2328"))
    p.setColor(QPalette.WindowText, QColor("#e6edf3"))
    p.setColor(QPalette.Base, QColor("#22272e"))
    p.setColor(QPalette.AlternateBase, QColor("#2d333b"))
    p.setColor(QPalette.ToolTipBase, QColor("#2d333b"))
    p.setColor(QPalette.ToolTipText, QColor("#e6edf3"))
    p.setColor(QPalette.Text, QColor("#e6edf3"))
    p.setColor(QPalette.Button, QColor("#2d333b"))
    p.setColor(QPalette.ButtonText, QColor("#e6edf3"))
    p.setColor(QPalette.Highlight, QColor("#316dca"))
    p.setColor(QPalette.HighlightedText, QColor("#ffffff"))
    p.setColor(QPalette.Disabled, QPalette.Text, QColor("#7d8590"))
    p.setColor(QPalette.Disabled, QPalette.ButtonText, QColor("#7d8590"))
    return p
