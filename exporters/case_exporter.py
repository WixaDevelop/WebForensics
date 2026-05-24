"""CASE / UCO export.

CASE (Cyber-investigation Analysis Standard Expression) is a NIST-led
ontology for representing digital forensic evidence in a way that
forensic tools can exchange. Real CASE documents are JSON-LD with full
ontology IRIs; producing a strictly-valid graph is heavy.

What we emit here is a **pragmatic CASE-compatible subset**: JSON-LD with
the canonical UCO/CASE prefixes, one ``uco-observable:URLFacet`` per history
row, ``uco-observable:HTTPCookieFacet`` per cookie, etc. The schema names
match the public CASE 1.2 vocabulary so Autopsy / X-Ways / FTK that have
CASE import will accept the file.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from data.models import ARTIFACT_KINDS, ProfileBundle
from exporters.base import ExporterBase


_CONTEXT = {
    "@vocab":   "https://ontology.unifiedcyberontology.org/uco/",
    "uco-core":   "https://ontology.unifiedcyberontology.org/uco/core/",
    "uco-action": "https://ontology.unifiedcyberontology.org/uco/action/",
    "uco-identity": "https://ontology.unifiedcyberontology.org/uco/identity/",
    "uco-observable": "https://ontology.unifiedcyberontology.org/uco/observable/",
    "uco-tool":  "https://ontology.unifiedcyberontology.org/uco/tool/",
    "case-investigation": "https://ontology.caseontology.org/case/investigation/",
    "xsd": "http://www.w3.org/2001/XMLSchema#",
}


def _iri() -> str:
    return f"kb:{uuid.uuid4()}"


def _ts(dt) -> dict | None:
    if not dt:
        return None
    if isinstance(dt, str):
        return {"@type": "xsd:dateTime", "@value": dt}
    if hasattr(dt, "isoformat"):
        return {"@type": "xsd:dateTime", "@value": dt.isoformat()}
    return None


class CaseExporter(ExporterBase):
    extension = ".jsonld"

    def export(
        self,
        bundles: Iterable[ProfileBundle],
        out_path: str | Path,
        kinds: Iterable[str] = ARTIFACT_KINDS,
    ) -> Path:
        kinds = list(kinds)
        bundles = list(bundles)
        target = Path(out_path)
        if target.is_dir():
            target = target / "webforensics.case.jsonld"
        if target.suffix.lower() not in (".jsonld", ".json"):
            target = target.with_suffix(".jsonld")
        target.parent.mkdir(parents=True, exist_ok=True)

        graph: list[dict] = []
        tool_iri = self._add_tool(graph)
        investigation_iri = self._add_investigation(graph, tool_iri)

        for bundle in bundles:
            profile_iri = self._add_profile(graph, bundle)
            graph.append({
                "@id": _iri(),
                "@type": "uco-core:Relationship",
                "uco-core:source": {"@id": investigation_iri},
                "uco-core:target": {"@id": profile_iri},
                "uco-core:kindOfRelationship": "Contains",
            })
            for kind in kinds:
                for item in bundle.get(kind):
                    self._add_artifact(graph, kind, item, profile_iri)

        doc = {"@context": _CONTEXT, "@graph": graph}
        target.write_text(json.dumps(doc, indent=2, default=str, ensure_ascii=False),
                          encoding="utf-8")
        return target

    # --- Builders ---------------------------------------------------------

    def _add_tool(self, graph: list[dict]) -> str:
        iri = _iri()
        graph.append({
            "@id": iri,
            "@type": "uco-tool:Tool",
            "uco-core:name": "WebForensics",
            "uco-tool:version": "1.0.0",
            "uco-tool:toolType": "Browser forensic analyser",
            "uco-tool:creator": "WixaDevelop",
        })
        return iri

    def _add_investigation(self, graph: list[dict], tool_iri: str) -> str:
        iri = _iri()
        graph.append({
            "@id": iri,
            "@type": "case-investigation:Investigation",
            "uco-core:name": "Browser-profile analysis",
            "uco-core:createdTime": _ts(datetime.now(timezone.utc)),
            "uco-core:performer": {"@id": tool_iri},
        })
        return iri

    def _add_profile(self, graph: list[dict], bundle: ProfileBundle) -> str:
        iri = _iri()
        graph.append({
            "@id": iri,
            "@type": "uco-observable:Profile",
            "uco-core:name": f"{bundle.browser} / {bundle.profile}",
            "uco-observable:profileType": bundle.browser,
            "uco-observable:profileLocation": bundle.path,
        })
        return iri

    def _add_artifact(self, graph: list[dict], kind: str, item, profile_iri: str) -> None:
        data = item.to_dict() if hasattr(item, "to_dict") else dict(item)
        builder = _BUILDERS.get(kind)
        if builder is None:
            return
        node = builder(data)
        if not node:
            return
        node["@id"] = _iri()
        node.setdefault("uco-core:hasFacet", []).append({
            "@id": profile_iri,
            "@type": "uco-observable:Profile",
        })
        graph.append(node)


# ---------------------------------------------------------------------------
# Per-artifact node builders. Keep the schemas conservative — pick the
# common, widely-supported facets so importers don't choke on novelty.
# ---------------------------------------------------------------------------


def _build_history(data: dict) -> dict:
    return {
        "@type": "uco-observable:URL",
        "uco-observable:hasFacet": [{
            "@type": "uco-observable:URLFacet",
            "uco-observable:fullValue": data.get("url", ""),
        }, {
            "@type": "uco-observable:URLHistoryFacet",
            "uco-observable:browserInformation": data.get("browser", ""),
            "uco-observable:visitCount": data.get("visit_count", 0),
            "uco-observable:firstVisit": _ts(data.get("last_visit")),
            "uco-observable:lastVisit": _ts(data.get("last_visit")),
            "uco-observable:pageTitle": data.get("title", ""),
            "uco-observable:referrerURL": data.get("from_visit_url", ""),
        }],
    }


def _build_cookie(data: dict) -> dict:
    return {
        "@type": "uco-observable:BrowserCookie",
        "uco-observable:hasFacet": [{
            "@type": "uco-observable:HTTPCookieFacet",
            "uco-observable:cookieName": data.get("name", ""),
            "uco-observable:cookieDomain": data.get("host", ""),
            "uco-observable:cookiePath": data.get("path", ""),
            "uco-observable:cookieValue": data.get("value", ""),
            "uco-observable:createdTime": _ts(data.get("created")),
            "uco-observable:expirationTime": _ts(data.get("expires")),
            "uco-observable:lastAccessedTime": _ts(data.get("last_access")),
            "uco-observable:isSecure": bool(data.get("secure")),
            "uco-observable:isHttpOnly": bool(data.get("http_only")),
        }],
    }


def _build_download(data: dict) -> dict:
    return {
        "@type": "uco-observable:File",
        "uco-observable:hasFacet": [{
            "@type": "uco-observable:FileFacet",
            "uco-observable:filePath": data.get("target_path", ""),
            "uco-observable:fileName": Path(data.get("target_path", "")).name,
            "uco-observable:sizeInBytes": data.get("total_bytes", 0),
            "uco-observable:mimeType": data.get("mime_type", ""),
            "uco-observable:observedTime": _ts(data.get("start_time")),
        }, {
            "@type": "uco-observable:URLFacet",
            "uco-observable:fullValue": data.get("url", ""),
        }],
    }


def _build_login(data: dict) -> dict:
    return {
        "@type": "uco-identity:Identity",
        "uco-observable:hasFacet": [{
            "@type": "uco-observable:AccountFacet",
            "uco-observable:identifier": data.get("username", ""),
            "uco-observable:accountIssuer": data.get("origin_url", ""),
            "uco-observable:createdTime": _ts(data.get("date_created")),
            "uco-observable:modifiedTime": _ts(data.get("date_last_used")),
        }],
    }


def _build_bookmark(data: dict) -> dict:
    return {
        "@type": "uco-observable:BrowserBookmark",
        "uco-observable:hasFacet": [{
            "@type": "uco-observable:BrowserBookmarkFacet",
            "uco-observable:bookmarkPath": data.get("folder", ""),
            "uco-observable:urlTargeted": data.get("url", ""),
            "uco-observable:name": data.get("name", ""),
            "uco-observable:createdTime": _ts(data.get("date_added")),
        }],
    }


def _build_extension(data: dict) -> dict:
    return {
        "@type": "uco-observable:SoftwareApplication",
        "uco-observable:hasFacet": [{
            "@type": "uco-observable:ApplicationFacet",
            "uco-observable:applicationIdentifier": data.get("extension_id", ""),
            "uco-observable:name": data.get("name", ""),
            "uco-observable:version": data.get("version", ""),
            "uco-observable:description": data.get("description", ""),
        }],
    }


def _build_tab(data: dict) -> dict:
    return {
        "@type": "uco-observable:URL",
        "uco-observable:hasFacet": [{
            "@type": "uco-observable:URLFacet",
            "uco-observable:fullValue": data.get("url", ""),
        }, {
            "@type": "uco-observable:WindowsTaskFacet",
            "uco-observable:name": data.get("title", ""),
        }],
    }


_BUILDERS = {
    "history":    _build_history,
    "cookies":    _build_cookie,
    "downloads":  _build_download,
    "logins":     _build_login,
    "bookmarks":  _build_bookmark,
    "extensions": _build_extension,
    "open_tabs":  _build_tab,
}
