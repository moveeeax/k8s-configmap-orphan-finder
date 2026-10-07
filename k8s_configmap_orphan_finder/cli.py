"""Command line entry point."""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional, Sequence

from . import __version__
from .audit import Options, audit
from .loader import load_cluster, load_manifests
from .model import SEVERITIES, LoadError
from .report import render_json, render_table

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_LOAD_ERROR = 2

EPILOG = """\
exit codes:
  0  nothing to clean up
  1  at least one finding
  2  inventory could not be read

examples:
  k8s-configmap-orphan-finder --namespace prod
  k8s-configmap-orphan-finder --manifests ./k8s --json | jq '.findings[] | select(.kind=="Secret")'
  k8s-configmap-orphan-finder --manifests ./k8s --ignore 'debug-*' --min-severity high
"""


def _split(values: Optional[Sequence[str]]) -> List[str]:
    out: List[str] = []
    for value in values or ():
        out.extend(part.strip() for part in value.split(",") if part.strip())
    return out


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="k8s-configmap-orphan-finder",
        description=(
            "Report ConfigMaps and Secrets that no workload references anymore, "
            "plus references that point at objects which do not exist."
        ),
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument("-n", "--namespace", help="audit this namespace in the live cluster")
    source.add_argument(
        "-A",
        "--all-namespaces",
        action="store_true",
        help="audit every namespace in the live cluster",
    )
    source.add_argument(
        "-m",
        "--manifests",
        metavar="DIR",
        help="audit a directory of YAML manifests instead of a cluster",
    )
    parser.add_argument(
        "--default-namespace",
        default="default",
        help="namespace assumed for manifests without metadata.namespace (default: default)",
    )
    parser.add_argument(
        "--ignore",
        action="append",
        metavar="GLOB",
        help="skip objects whose name matches this glob; repeatable or comma-separated",
    )
    parser.add_argument(
        "--skip-kinds",
        action="append",
        metavar="KIND",
        help="exclude a kind from the audit, e.g. Secret or CronJob; repeatable",
    )
    parser.add_argument(
        "--min-severity",
        choices=SEVERITIES,
        default="low",
        help="only report findings at this severity or above (default: low)",
    )
    parser.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.manifests and not args.namespace and not args.all_namespaces:
        parser.error("choose a source: --manifests DIR, --namespace NS or --all-namespaces")

    try:
        if args.manifests:
            inventory = load_manifests(args.manifests, args.default_namespace)
        else:
            inventory = load_cluster(args.namespace, args.all_namespaces)
    except LoadError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_LOAD_ERROR

    result = audit(
        inventory,
        Options(
            ignore=_split(args.ignore),
            skip_kinds=_split(args.skip_kinds),
            min_severity=args.min_severity,
        ),
    )

    print(render_json(result) if args.json else render_table(result))
    return EXIT_FINDINGS if result.findings else EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
