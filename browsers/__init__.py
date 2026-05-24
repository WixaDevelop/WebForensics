"""Browser-specific extractors."""

from browsers.base import BrowserBase, BrowserProfile
from browsers.brave import BraveBrowser
from browsers.chrome import ChromeBrowser
from browsers.edge import EdgeBrowser
from browsers.firefox import FirefoxBrowser
from browsers.opera import OperaBrowser
from browsers.opera_gx import OperaGXBrowser
from browsers.tor import TorBrowser
from browsers.vivaldi import VivaldiBrowser

__all__ = [
    "BrowserBase",
    "BrowserProfile",
    "BraveBrowser",
    "ChromeBrowser",
    "EdgeBrowser",
    "FirefoxBrowser",
    "OperaBrowser",
    "OperaGXBrowser",
    "TorBrowser",
    "VivaldiBrowser",
]
