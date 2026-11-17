"""
reports/exporter.py — JSON serialization for OsintReport.

Produces a structured JSON payload designed for future API compatibility.
Schema: meta / target / summary / findings / assets / errors.
"""

from __future__ import annotations

import json
from datetime import datetime

from core.models import OsintReport, Severity


def to_json(report: OsintReport, output_path: str | None = None) -> str:
    """
    Serialize an OsintReport to a JSON string.

    Args:
        report:      The completed OSINT report from run_osint().
        output_path: If given, write the JSON to this file path.

    Returns:
        The JSON string (always, even when writing to a file).
    """
    payload = {
        "meta": {
            "tool":         "prowl",
            "version":      report.version,
            "generated_at": _fmt(report.generated_at),
        },
        "target": {
            "company_name": report.target.company_name,
            "domain":       report.target.domain,
            "siren":        report.target.siren,
            "mode":         report.target.mode,
            "french":       report.target.french,
        },
        "summary": {
            "total_findings":   len(report.findings),
            "collectors_run":   report.collectors_run,
            "duration_seconds": report.duration_seconds,
            "by_severity":      _count_by_severity(report),
            "errors":           report.errors,
        },
        "findings": [_serialize_finding(f) for f in report.findings],
        "assets":   report.assets,
        "errors":   report.errors,
    }

    output = json.dumps(payload, indent=2, ensure_ascii=False)

    if output_path:
        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(output)

    return output


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _fmt(dt: datetime) -> str:
    """Return an ISO 8601 string with milliseconds and UTC offset."""
    return dt.isoformat(timespec="milliseconds")


def _count_by_severity(report: OsintReport) -> dict[str, int]:
    counts = {s.value: 0 for s in Severity}
    for f in report.findings:
        counts[f.severity.value] += 1
    return counts


def _serialize_finding(f) -> dict:
    return {
        "id":             f.id,
        "severity":       f.severity.value,
        "category":       f.category.value,
        "title":          f.title,
        "description":    f.description,
        "affected_asset": f.affected_asset,
        "source":         f.source,
        "source_url":     f.source_url,
        "mitre_attack":   f.mitre_attack,
        "timestamp":      _fmt(f.timestamp),
        "raw_data":       f.raw_data,
    }
