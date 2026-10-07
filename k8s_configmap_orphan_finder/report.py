"""Render an :class:`AuditResult` as a table or as JSON."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Sequence

from .audit import AuditResult
from .model import SEVERITIES, Finding

HEADERS = ("SEVERITY", "KIND", "NAMESPACE", "NAME", "FINDING", "DETAIL")


def severity_counts(findings: Sequence[Finding]) -> Dict[str, int]:
    counts = {name: 0 for name in SEVERITIES}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return counts


def to_json(result: AuditResult) -> Dict[str, Any]:
    return {
        "summary": {
            "namespaces": result.namespaces,
            "configmaps": result.configmaps,
            "secrets": result.secrets,
            "referrers": result.referrers,
            "findings": len(result.findings),
            "by_severity": severity_counts(result.findings),
        },
        "findings": [f.to_dict() for f in result.findings],
    }


def render_json(result: AuditResult) -> str:
    return json.dumps(to_json(result), indent=2, sort_keys=False)


def _table(rows: List[Sequence[str]]) -> str:
    widths = [len(h) for h in HEADERS]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))
    lines = ["  ".join(h.ljust(widths[i]) for i, h in enumerate(HEADERS)).rstrip()]
    for row in rows:
        lines.append("  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)).rstrip())
    return "\n".join(lines)


def render_table(result: AuditResult) -> str:
    scope = ", ".join(result.namespaces) or "-"
    header = (
        f"Scanned {result.configmaps} ConfigMaps, {result.secrets} Secrets and "
        f"{result.referrers} referencing objects in {scope}."
    )
    if not result.findings:
        return header + "\nNo orphans and no dangling references."

    rows = [
        (
            f.severity,
            f.kind,
            f.namespace,
            f.name,
            f.finding,
            f.detail,
        )
        for f in result.findings
    ]
    counts = severity_counts(result.findings)
    tally = " ".join(f"{name}={counts[name]}" for name in SEVERITIES if counts[name])
    return "\n".join(
        [header, "", _table(rows), "", f"{len(result.findings)} finding(s): {tally}"]
    )
