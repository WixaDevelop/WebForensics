"""Network graph of referrer chains.

Renders every host in ``history`` as a node and every ``(from_visit_url, url)``
pair as a directed edge using ``QGraphicsScene``. Layout is a simple
force-directed spring (Fruchterman-Reingold), implemented inline so we don't
pull in NetworkX / matplotlib.

Click a node → it expands to show every URL recorded for that host and the
inbound/outbound edge counts. Useful for "who linked here" investigations.
"""

from __future__ import annotations

import math
import random
from collections import defaultdict
from typing import Optional
from urllib.parse import urlparse

from PyQt5.QtCore import QPointF, QRectF, Qt, pyqtSignal
from PyQt5.QtGui import QBrush, QColor, QFont, QPainter, QPainterPath, QPen
from PyQt5.QtWidgets import (
    QGraphicsEllipseItem,
    QGraphicsItem,
    QGraphicsLineItem,
    QGraphicsScene,
    QGraphicsTextItem,
    QGraphicsView,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from data.store import SessionStore


_NODE_R = 8.0
_MAX_NODES = 300


class _Node(QGraphicsEllipseItem):
    """One host. Drag to reposition, click to surface details."""

    def __init__(self, host: str, weight: int, parent_view: "NetworkGraphView") -> None:
        super().__init__(-_NODE_R, -_NODE_R, _NODE_R * 2, _NODE_R * 2)
        self.host = host
        self.weight = weight
        self.setFlag(QGraphicsItem.ItemIsMovable)
        self.setFlag(QGraphicsItem.ItemSendsGeometryChanges)
        self.setAcceptHoverEvents(True)
        self._parent_view = parent_view
        # Bigger node + warmer colour for hosts with more visits.
        r = min(_NODE_R + math.sqrt(weight) * 1.2, 28)
        self.setRect(-r, -r, r * 2, r * 2)
        hue = max(0, min(0.6, 0.6 - math.log(weight + 1) / 6))
        colour = QColor.fromHslF(hue, 0.65, 0.55)
        self.setBrush(QBrush(colour))
        self.setPen(QPen(QColor("#1f2328"), 1))
        label = QGraphicsTextItem(host, self)
        label.setDefaultTextColor(QColor("#1f2328"))
        label.setFont(QFont("Segoe UI", 8))
        label.setPos(r + 2, -r)
        self._label = label

    def hoverEnterEvent(self, event):  # noqa: N802
        self.setPen(QPen(QColor("#cf222e"), 2))
        super().hoverEnterEvent(event)

    def hoverLeaveEvent(self, event):  # noqa: N802
        self.setPen(QPen(QColor("#1f2328"), 1))
        super().hoverLeaveEvent(event)

    def mousePressEvent(self, event):  # noqa: N802
        self._parent_view.show_node_info(self.host)
        super().mousePressEvent(event)


class NetworkGraphView(QWidget):
    """Spring-layout graph of host → referrer-host edges."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._store: Optional[SessionStore] = None
        self._profile_id: Optional[int] = None
        self._build_ui()

    def _build_ui(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(8, 8, 8, 8)

        controls = QHBoxLayout()
        controls.addWidget(QLabel("<b>Network graph</b>"))
        controls.addStretch(1)
        controls.addWidget(QLabel("Max nodes:"))
        self._limit = QSpinBox()
        self._limit.setRange(10, 1000)
        self._limit.setValue(150)
        self._limit.setSingleStep(25)
        controls.addWidget(self._limit)
        rebuild = QPushButton("Rebuild")
        rebuild.clicked.connect(self._build_graph)
        controls.addWidget(rebuild)
        outer.addLayout(controls)

        info = QLabel(
            "<small>Nodes are hosts found in history. Edges are referrer "
            "relationships (URL B was reached from URL A). Drag nodes to "
            "rearrange. Click for details.</small>"
        )
        info.setStyleSheet("color: #555;")
        info.setWordWrap(True)
        outer.addWidget(info)

        self._scene = QGraphicsScene()
        self._view = QGraphicsView(self._scene)
        self._view.setRenderHint(QPainter.Antialiasing)
        self._view.setDragMode(QGraphicsView.RubberBandDrag)
        outer.addWidget(self._view, 1)

        self._details = QLabel("")
        self._details.setStyleSheet("color: #444;")
        outer.addWidget(self._details)

    # --- Public API -------------------------------------------------------

    def attach(self, store: SessionStore) -> None:
        self._store = store
        self._build_graph()

    def set_profile(self, profile_id: Optional[int]) -> None:
        self._profile_id = profile_id
        self._build_graph()

    def refresh(self) -> None:
        self._build_graph()

    # --- Internal ---------------------------------------------------------

    def _build_graph(self) -> None:
        if self._store is None:
            return
        self._scene.clear()
        conn = self._store.connection()
        clause = ""
        params: tuple = ()
        if self._profile_id is not None:
            clause = " AND profile_id=?"
            params = (int(self._profile_id),)
        rows = conn.execute(
            "SELECT url, from_visit_url FROM history "
            "WHERE url IS NOT NULL " + clause + " LIMIT 100000",
            params,
        ).fetchall()

        weights: dict[str, int] = defaultdict(int)
        edges: dict[tuple[str, str], int] = defaultdict(int)
        for row in rows:
            host = urlparse(str(row["url"] or "")).hostname or ""
            if not host:
                continue
            host = host.lower()
            weights[host] += 1
            referrer = (row["from_visit_url"] or "")
            if not referrer:
                continue
            ref_host = urlparse(str(referrer)).hostname or ""
            ref_host = ref_host.lower()
            if not ref_host or ref_host == host:
                continue
            edges[(ref_host, host)] += 1

        max_nodes = min(self._limit.value(), _MAX_NODES)
        top_hosts = sorted(weights.items(), key=lambda x: x[1], reverse=True)[:max_nodes]
        allowed = {h for h, _w in top_hosts}
        if not allowed:
            self._details.setText("No history with referrers in this profile.")
            return

        # Initial layout — random within a circle so the spring solver has
        # something to work with.
        positions: dict[str, QPointF] = {}
        radius = 280
        rng = random.Random(42)
        for i, (host, weight) in enumerate(top_hosts):
            angle = 2 * math.pi * i / len(top_hosts)
            positions[host] = QPointF(
                radius * math.cos(angle) + rng.uniform(-25, 25),
                radius * math.sin(angle) + rng.uniform(-25, 25),
            )

        # Spring layout — Fruchterman-Reingold, capped at 60 iterations so it
        # finishes quickly even for 300-node graphs.
        area = (radius * 2) ** 2
        k = math.sqrt(area / len(positions))
        edge_list = [(a, b) for (a, b) in edges if a in allowed and b in allowed]
        for _step in range(60):
            disp = {h: QPointF(0, 0) for h in positions}
            # Repulsion.
            host_keys = list(positions.keys())
            for i in range(len(host_keys)):
                for j in range(i + 1, len(host_keys)):
                    a, b = host_keys[i], host_keys[j]
                    dx = positions[a].x() - positions[b].x()
                    dy = positions[a].y() - positions[b].y()
                    dist = max(1.0, math.hypot(dx, dy))
                    force = (k * k) / dist
                    disp[a] += QPointF(dx / dist * force, dy / dist * force)
                    disp[b] -= QPointF(dx / dist * force, dy / dist * force)
            # Attraction along edges.
            for a, b in edge_list:
                dx = positions[a].x() - positions[b].x()
                dy = positions[a].y() - positions[b].y()
                dist = max(1.0, math.hypot(dx, dy))
                force = (dist * dist) / k
                disp[a] -= QPointF(dx / dist * force, dy / dist * force)
                disp[b] += QPointF(dx / dist * force, dy / dist * force)
            # Apply with cooling.
            for host, point in positions.items():
                dxy = disp[host]
                dist = max(1.0, math.hypot(dxy.x(), dxy.y()))
                limit = min(dist, 12.0)
                positions[host] = QPointF(
                    point.x() + dxy.x() / dist * limit,
                    point.y() + dxy.y() / dist * limit,
                )

        # Draw edges first so nodes sit on top.
        for (a, b), count in edges.items():
            if a not in positions or b not in positions:
                continue
            pa = positions[a]
            pb = positions[b]
            line = QGraphicsLineItem(pa.x(), pa.y(), pb.x(), pb.y())
            line.setPen(QPen(QColor("#bbb"), max(0.5, min(3.0, math.log(count + 1)))))
            line.setZValue(-1)
            self._scene.addItem(line)

        # Draw nodes.
        self._nodes: dict[str, _Node] = {}
        for host, point in positions.items():
            node = _Node(host, weights[host], self)
            node.setPos(point)
            self._scene.addItem(node)
            self._nodes[host] = node

        self._edges = edges
        self._weights = weights
        self._scene.setSceneRect(self._scene.itemsBoundingRect().adjusted(-40, -40, 40, 40))
        self._details.setText(f"{len(self._nodes)} hosts · {len(edge_list)} referrer edges")

    def show_node_info(self, host: str) -> None:
        if self._store is None:
            return
        inbound = sum(c for (a, b), c in getattr(self, "_edges", {}).items() if b == host)
        outbound = sum(c for (a, b), c in getattr(self, "_edges", {}).items() if a == host)
        weight = self._weights.get(host, 0)
        self._details.setText(
            f"<b>{host}</b> — {weight} visit(s) · {inbound} inbound links · {outbound} outbound links"
        )
