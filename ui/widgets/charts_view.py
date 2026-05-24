"""Activity dashboard.

Four small charts painted with ``QPainter`` (no matplotlib or PyQtChart
dependency):

* **Hour-of-day** — when is this user typically active?
* **Day-by-day** — visit volume per day over the last 30 days.
* **Top hosts** — top 10 visited domains.
* **Downloads/month** — monthly download counts over the last 12 months.

All four query the ``SessionStore`` directly so they refresh as new profiles
load.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Optional
from urllib.parse import urlparse

from PyQt5.QtCore import QRect, QRectF, Qt
from PyQt5.QtGui import QBrush, QColor, QFont, QPainter, QPen
from PyQt5.QtWidgets import (
    QGridLayout,
    QLabel,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from data.store import SessionStore


# ---------------------------------------------------------------------------
# Low-level bar chart widget
# ---------------------------------------------------------------------------


class _BarChart(QWidget):
    """Vertical or horizontal bars with axis labels — painted from scratch."""

    def __init__(
        self,
        title: str,
        horizontal: bool = False,
        bar_colour: str = "#2563eb",
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self._title = title
        self._horizontal = horizontal
        self._bar_colour = QColor(bar_colour)
        self._data: list[tuple[str, float]] = []
        self.setMinimumHeight(180)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

    def set_data(self, data: list[tuple[str, float]]) -> None:
        self._data = list(data)
        self.update()

    # The whole widget is one paintEvent — short and self-contained.
    def paintEvent(self, _event) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        rect = self.rect().adjusted(8, 6, -8, -8)

        # Title bar.
        painter.setPen(QColor("#1f2328"))
        painter.setFont(QFont("Segoe UI", 9, QFont.Bold))
        title_rect = QRect(rect.left(), rect.top(), rect.width(), 18)
        painter.drawText(title_rect, Qt.AlignLeft | Qt.AlignVCenter, self._title)

        chart_area = QRect(rect.left(), rect.top() + 22, rect.width(), rect.height() - 22)

        if not self._data:
            painter.setPen(QColor("#888"))
            painter.setFont(QFont("Segoe UI", 9))
            painter.drawText(chart_area, Qt.AlignCenter, "no data")
            return

        if self._horizontal:
            self._paint_horizontal(painter, chart_area)
        else:
            self._paint_vertical(painter, chart_area)

    # --- Paint routines ---------------------------------------------------

    def _paint_vertical(self, painter: QPainter, area: QRect) -> None:
        max_value = max((v for _, v in self._data), default=1) or 1
        bottom = area.bottom() - 18  # leave room for x-axis labels
        height = bottom - area.top()
        n = len(self._data)
        gap = 4
        bar_width = max(2, (area.width() - gap * (n + 1)) // n)

        painter.setFont(QFont("Segoe UI", 8))
        painter.setPen(QColor("#666"))
        x = area.left() + gap
        for label, value in self._data:
            bar_height = int(height * (value / max_value))
            bar_rect = QRectF(x, bottom - bar_height, bar_width, bar_height)
            painter.fillRect(bar_rect, QBrush(self._bar_colour))
            # X-axis label.
            text_rect = QRect(x - 4, bottom + 2, bar_width + 8, 14)
            painter.drawText(text_rect, Qt.AlignCenter, label)
            x += bar_width + gap

        # Y-axis baseline.
        painter.setPen(QPen(QColor("#d1d9e0"), 1))
        painter.drawLine(area.left(), bottom, area.right(), bottom)

    def _paint_horizontal(self, painter: QPainter, area: QRect) -> None:
        max_value = max((v for _, v in self._data), default=1) or 1
        n = len(self._data)
        gap = 4
        bar_height = max(8, (area.height() - gap * (n + 1)) // n)
        label_width = 130

        painter.setFont(QFont("Segoe UI", 8))
        y = area.top() + gap
        for label, value in self._data:
            # Label on the left.
            painter.setPen(QColor("#444"))
            label_rect = QRect(area.left(), y, label_width, bar_height)
            painter.drawText(label_rect, Qt.AlignLeft | Qt.AlignVCenter, label[:32])

            # Bar.
            track_left = area.left() + label_width + 4
            track_width = area.right() - track_left - 40
            bar_w = int(track_width * (value / max_value))
            bar_rect = QRectF(track_left, y, bar_w, bar_height)
            painter.fillRect(bar_rect, QBrush(self._bar_colour))

            # Value on the right.
            painter.setPen(QColor("#444"))
            value_rect = QRect(track_left + bar_w + 4, y, 60, bar_height)
            painter.drawText(value_rect, Qt.AlignLeft | Qt.AlignVCenter, str(int(value)))
            y += bar_height + gap


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------


class ChartsView(QWidget):
    """Composes the four charts and queries the store on attach/refresh."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._store: Optional[SessionStore] = None
        self._profile_id: Optional[int] = None
        self._build_ui()

    # --- UI ---------------------------------------------------------------

    def _build_ui(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(8, 8, 8, 8)

        self._header = QLabel("<i>Load profiles to see activity.</i>")
        self._header.setStyleSheet("color: #555;")
        outer.addWidget(self._header)

        grid = QGridLayout()
        self._chart_hour = _BarChart("Visits by hour of day", bar_colour="#2563eb")
        self._chart_day = _BarChart("Visits per day (last 30 days)", bar_colour="#16a34a")
        self._chart_hosts = _BarChart("Top hosts", horizontal=True, bar_colour="#7c3aed")
        self._chart_downloads = _BarChart("Downloads per month", bar_colour="#a16207")
        grid.addWidget(self._chart_hour, 0, 0)
        grid.addWidget(self._chart_day, 0, 1)
        grid.addWidget(self._chart_hosts, 1, 0)
        grid.addWidget(self._chart_downloads, 1, 1)
        outer.addLayout(grid, 1)

    # --- Public API -------------------------------------------------------

    def attach(self, store: SessionStore) -> None:
        self._store = store
        self.refresh()

    def set_profile(self, profile_id: Optional[int]) -> None:
        self._profile_id = profile_id
        self.refresh()

    def refresh(self) -> None:
        if self._store is None:
            return
        self._header.setText(
            "Aggregated across all loaded profiles."
            if self._profile_id is None
            else "Filtered to the selected profile."
        )
        self._refresh_hour()
        self._refresh_day()
        self._refresh_hosts()
        self._refresh_downloads()

    # --- Queries ----------------------------------------------------------

    def _profile_clause(self) -> str:
        return f" AND profile_id = {int(self._profile_id)}" if self._profile_id else ""

    def _refresh_hour(self) -> None:
        conn = self._store.connection()
        rows = conn.execute(
            "SELECT substr(last_visit, 12, 2) AS hh, COUNT(*) AS n "
            "FROM history WHERE last_visit IS NOT NULL " + self._profile_clause() +
            " GROUP BY hh ORDER BY hh"
        ).fetchall()
        # Build a 0..23 series so the chart shows every hour even at zero.
        by_hour = {row["hh"]: row["n"] for row in rows if row["hh"]}
        data = [(f"{h:02d}", float(by_hour.get(f"{h:02d}", 0))) for h in range(24)]
        self._chart_hour.set_data(data)

    def _refresh_day(self) -> None:
        conn = self._store.connection()
        today = datetime.now(timezone.utc).date()
        start = today - timedelta(days=29)
        rows = conn.execute(
            "SELECT substr(last_visit, 1, 10) AS dd, COUNT(*) AS n "
            "FROM history WHERE last_visit >= ? " + self._profile_clause() +
            " GROUP BY dd ORDER BY dd",
            (start.isoformat() + "T00:00:00",),
        ).fetchall()
        by_day = {row["dd"]: row["n"] for row in rows}
        # Build a continuous 30-day series.
        data = []
        for i in range(30):
            day = start + timedelta(days=i)
            data.append((day.strftime("%d/%m"), float(by_day.get(day.isoformat(), 0))))
        self._chart_day.set_data(data)

    def _refresh_hosts(self) -> None:
        conn = self._store.connection()
        rows = conn.execute(
            "SELECT url FROM history WHERE url IS NOT NULL " + self._profile_clause() +
            " LIMIT 20000"
        ).fetchall()
        counter: Counter[str] = Counter()
        for row in rows:
            host = urlparse(str(row["url"])).hostname or ""
            if host:
                counter[host] += 1
        top = counter.most_common(10)
        self._chart_hosts.set_data([(host, float(n)) for host, n in top])

    def _refresh_downloads(self) -> None:
        conn = self._store.connection()
        rows = conn.execute(
            "SELECT substr(start_time, 1, 7) AS ym, COUNT(*) AS n "
            "FROM downloads WHERE start_time IS NOT NULL " + self._profile_clause() +
            " GROUP BY ym ORDER BY ym DESC LIMIT 12"
        ).fetchall()
        rows = list(reversed(rows))  # chronological left-to-right
        self._chart_downloads.set_data([(row["ym"], float(row["n"])) for row in rows])
