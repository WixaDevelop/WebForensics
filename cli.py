"""Headless command-line entry point.

Usage examples (run from the project root)::

    python -m cli list
    python -m cli extract --profile "C:\\Users\\me\\AppData\\Local\\Google\\Chrome\\User Data\\Default" --out report.pdf
    python -m cli extract --image suspect.E01 --out report.html --kinds history,downloads
    python -m cli auto --out webforensics.wfs
    python -m cli diff baseline.wfs newer.wfs

Designed to be used in forensic pipelines / CI / scheduled jobs. The CLI uses
the exact same controller as the GUI, so anything that works there works
here.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from controller import ForensicsController
from data.models import ARTIFACT_KINDS, ProfileBundle
from data.session import Session
from exporters import EXPORTERS

logger = logging.getLogger(__name__)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="webforensics-cli",
        description="Forensic browser-profile analysis without the GUI.",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    sub = parser.add_subparsers(dest="cmd", required=True)

    # `list` — auto-detect and print profiles, no extraction.
    sub.add_parser("list", help="List auto-detected profiles and exit.")

    # `auto` — extract every auto-detected profile.
    auto = sub.add_parser("auto", help="Extract every auto-detected profile.")
    auto.add_argument("--out", required=True, help="Output file (.wfs / .pdf / .html / .json / folder for csv)")
    auto.add_argument("--format", choices=tuple(EXPORTERS) + ("wfs",), default="auto")
    auto.add_argument("--kinds", default=",".join(ARTIFACT_KINDS),
                      help="Comma-separated artifact kinds to include in exports.")

    # `extract` — explicit profile path *or* forensic image.
    ext = sub.add_parser("extract", help="Extract a single profile or forensic image.")
    grp = ext.add_mutually_exclusive_group(required=True)
    grp.add_argument("--profile", help="Path to a browser profile directory.")
    grp.add_argument("--image", help="Path to a forensic image (E01 / .dd / .img).")
    ext.add_argument("--out", required=True)
    ext.add_argument("--format", choices=tuple(EXPORTERS) + ("wfs",), default="auto")
    ext.add_argument("--kinds", default=",".join(ARTIFACT_KINDS))

    # `diff` — two .wfs files.
    diff_cmd = sub.add_parser("diff", help="Compare two .wfs sessions.")
    diff_cmd.add_argument("baseline", help=".wfs file to use as the baseline.")
    diff_cmd.add_argument("newer", help=".wfs file to compare against.")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )

    if args.cmd == "list":
        return _cmd_list()
    if args.cmd == "auto":
        return _cmd_auto(args)
    if args.cmd == "extract":
        return _cmd_extract(args)
    if args.cmd == "diff":
        return _cmd_diff(args)
    parser.print_help()
    return 2


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------


def _cmd_list() -> int:
    controller = ForensicsController()
    profiles = controller.discover_profiles()
    if not profiles:
        print("No browser profiles auto-detected.")
        return 1
    print(f"{len(profiles)} profile(s) found:")
    for p in profiles:
        print(f"  - [{p.browser}] {p.name}  →  {p.path}")
    return 0


def _cmd_auto(args) -> int:
    controller = ForensicsController()
    profiles = controller.discover_profiles()
    if not profiles:
        print("No browser profiles auto-detected.", file=sys.stderr)
        return 1
    bundles = [controller.extract(p, progress=_print) for p in profiles]
    return _persist(bundles, args)


def _cmd_extract(args) -> int:
    controller = ForensicsController()
    bundles: list[ProfileBundle] = []
    if args.profile:
        profile = controller.identify_profile(args.profile)
        if profile is None:
            print(f"Not a recognised browser profile: {args.profile}", file=sys.stderr)
            return 1
        bundles.append(controller.extract(profile, progress=_print))
    else:
        for bundle in controller.extract_image(args.image, progress=_print):
            bundles.append(bundle)
        if not bundles:
            print("No profiles found inside the image.", file=sys.stderr)
            return 1
    return _persist(bundles, args)


def _cmd_diff(args) -> int:
    from forensics.diff import compare_wfs
    diff = compare_wfs(Path(args.baseline), Path(args.newer))
    print(f"Diff summary: {diff.summary}")
    for table, td in diff.tables.items():
        if not td.added and not td.removed:
            continue
        print(f"\n[{table}] +{len(td.added)} added, -{len(td.removed)} removed")
        for row in td.added[:20]:
            print(f"  +  {_one_line(row)}")
        if len(td.added) > 20:
            print(f"  +  …{len(td.added) - 20} more added")
        for row in td.removed[:20]:
            print(f"  -  {_one_line(row)}")
        if len(td.removed) > 20:
            print(f"  -  …{len(td.removed) - 20} more removed")
    return 0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _persist(bundles: list[ProfileBundle], args) -> int:
    """Write *bundles* to args.out in the requested format."""
    out_path = Path(args.out)
    fmt = _infer_format(args.format, out_path)
    kinds = [k.strip() for k in args.kinds.split(",") if k.strip()]
    invalid = [k for k in kinds if k not in ARTIFACT_KINDS]
    if invalid:
        print(f"Unknown kinds: {invalid}", file=sys.stderr)
        return 1

    if fmt == "wfs":
        session = Session.new()
        try:
            for bundle in bundles:
                session.store.ingest_bundle(bundle)
            target = session.save_as(out_path)
        finally:
            session.close()
        print(f"Wrote session to {target}")
        return 0

    exporter = EXPORTERS[fmt]()
    target = exporter.export(bundles, out_path, kinds=kinds)
    print(f"Wrote {fmt.upper()} report to {target}")
    return 0


def _infer_format(explicit: str, out_path: Path) -> str:
    if explicit != "auto":
        return explicit
    suffix = out_path.suffix.lower()
    if suffix == ".wfs":
        return "wfs"
    if suffix == ".pdf":
        return "pdf"
    if suffix == ".html":
        return "html"
    if suffix == ".json":
        return "json"
    if out_path.is_dir() or suffix == "":
        return "csv"
    return "json"


def _one_line(row: dict) -> str:
    return " · ".join(f"{k}={str(v)[:60]}" for k, v in row.items() if v not in (None, "")
                      and k not in ("id", "profile_id"))[:200]


def _print(msg: str) -> None:
    print(msg, flush=True)


if __name__ == "__main__":
    sys.exit(main())
