"""
reports/pdf_exporter.py — PDF export via Jinja2 + WeasyPrint.

Renders reports/templates/report.html with the report data,
then converts the result to a PDF file.
"""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML

from core.models import OsintReport, Severity

# Resolve template directory relative to this file so the tool works
# regardless of the working directory it is called from.
_TEMPLATE_DIR = Path(__file__).parent / "templates"


def to_pdf(report: OsintReport, output_path: str) -> None:
    """
    Render an OsintReport to a PDF file.

    Args:
        report:      The completed OSINT report from run_osint().
        output_path: Destination file path (e.g. "report.pdf").
    """
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=True,
    )
    template = env.get_template("report.html")

    # Pre-compute severity counts for the summary boxes
    counts = {s.value: 0 for s in Severity}
    for f in report.findings:
        counts[f.severity.value] += 1

    html_str = template.render(report=report, counts=counts)

    HTML(string=html_str, base_url=str(_TEMPLATE_DIR)).write_pdf(output_path)
