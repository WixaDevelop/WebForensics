"""Common interface for exporters."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Iterable

from data.models import ARTIFACT_KINDS, ProfileBundle


class ExporterBase(ABC):
    extension: str = ""

    @abstractmethod
    def export(
        self,
        bundles: Iterable[ProfileBundle],
        out_path: str | Path,
        kinds: Iterable[str] = ARTIFACT_KINDS,
    ) -> Path:
        """Write the chosen artifacts to ``out_path`` and return the final path."""
