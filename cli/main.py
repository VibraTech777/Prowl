# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 Cyril Tzaraeff
# https://www.linkedin.com/in/cyril-tzaraeff-513a61343/

"""
cli/main.py — Prowl CLI entry point (Typer).

Examples:
  prowl -d acme.com
  prowl -d acme.fr --french --siren 123456789 --pivot 1
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
from pathlib import Path

import click
import typer
from rich.markup import escape
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from cli.display import _DETAIL_SOURCES, console, print_banner, print_report
from core.collectors.base import CollectorSkipped
from core.models import OsintTarget
from core.runner import run_osint
from dotenv import find_dotenv, load_dotenv
load_dotenv(find_dotenv(usecwd=True))   # .env of the directory prowl is run from (or a parent)

_VERSION = "0.1.0"                      # keep in sync with pyproject.toml
_MODES = ("short", "deep")
_EXPORT_SUFFIXES = (".json", ".pdf")


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"prowl {_VERSION}")
        raise typer.Exit()


def _validate_options(pivot: int, pivot_limit: int, depth: int, output: str) -> None:
    """Reject bad values up front: before the banner and long before the scan starts."""
    if pivot < 0:
        raise typer.BadParameter("Pivot depth must be 0 or greater.", param_hint="--pivot")
    if pivot_limit < 1:
        raise typer.BadParameter("Pivot limit must be at least 1.", param_hint="--pivot-limit")
    if depth < 0:
        raise typer.BadParameter("Crawler depth must be 0 or greater.", param_hint="--depth")
    if output and Path(output).suffix.lower() not in _EXPORT_SUFFIXES:
        raise typer.BadParameter(
            f"Unknown export format '{Path(output).suffix}'. Use .json or .pdf.",
            param_hint="--output",
        )


app = typer.Typer(
    name="prowl",
    help="Open-source OSINT reconnaissance tool for pentesters.",
    add_completion=False,
)


@app.command()
def main(
    domain: str = typer.Option(..., "--domain", "-d",
        help="Target domain (e.g. example.com)"),
    company: str = typer.Option("", "--company", "-c",
        help="Company name (optional). Used in the report header, as a GitHub org "
             "candidate, and for OpenCorporates lookups."),
    siren: str = typer.Option("", "--siren", "-s",
        help="French SIREN registration number. Required for BODACC, Annuaire Entreprises "
             "and Pappers: without it these sources are skipped (a notice is shown)."),
    mode: str = typer.Option("short", "--mode", "-m", click_type=click.Choice(_MODES),
        help="Search depth: 'short' (default) or 'deep'. Currently all active collectors "
             "are Tier 1; this flag is reserved for future Tier 2+ collectors."),
    french: bool = typer.Option(False, "--french", "-F",
        help="Enable French-specific sources: BODACC, Annuaire Entreprises, Pappers "
             "(requires PAPPERS_API_KEY). Requires --siren."),
    crawl: bool = typer.Option(True, "--crawl/--no-crawl",
        help="[Semi-active] Web crawler: visit the target's HTTP pages (robots.txt respected). "
             "On by default; --no-crawl keeps the scan passive."),
    depth: int = typer.Option(1, "--depth",
        help="Link-following depth of the web crawler. Has no effect with --no-crawl."),
    pivot: int = typer.Option(0, "--pivot",
        help="Person pivot depth (0 = disabled). For each person found, runs: GitHub "
             "profile, EmailFormat, GitLeak (real email from commits), WhatsMyName "
             "(username across ~300 platforms). With --pivot 2+ and a GITHUB_TOKEN, "
             "also finds the colleagues of GitHub-confirmed persons and investigates "
             "them at the next level. Rate-limited per source. "
             "WARNING: even --pivot 1 sends each login to ~300 external sites."),
    pivot_limit: int = typer.Option(25, "--pivot-limit",
        help="Max persons to pivot on per depth level."),
    output: str = typer.Option("", "--output", "-o",
        help="Export path: report.json or report.pdf"),
    version: bool = typer.Option(False, "--version", "-V", callback=_version_callback,
        is_eager=True, help="Show the version and exit."),
) -> None:
    """Run an OSINT reconnaissance scan against a target domain."""

    _validate_options(pivot, pivot_limit, depth, output)
    _configure_logging()

    print_banner()
    _streamed.clear()
    _stream_counts.clear()
    _stream_hidden.clear()

    if crawl:
        typer.echo(
            "[WARNING] The web crawler performs semi-active recon: its HTTP requests will "
            "appear in the target's access logs (robots.txt is respected). "
            "Use --no-crawl for passive collection only.",
            err=True,
        )

    target = OsintTarget(
        company_name=company,
        domain=domain,
        siren=siren or None,
        mode=mode,
        french=french,
        crawl=crawl,
        crawl_depth=depth,
        pivot_depth=pivot,
        pivot_limit=pivot_limit,
    )

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task(
            f"Collecting intelligence on [cyan]{domain}[/cyan]…", total=None
        )
        report = asyncio.run(run_osint(target, on_result=_on_result, on_progress=_on_progress))

    print_report(report)

    if output:
        _handle_export(report, output)


def _configure_logging() -> None:
    """Keep log records out of the terminal: errors are shown once, cleanly (✗ line + Collector Errors).

    Without a handler Python prints every WARNING/ERROR record on stderr (retry traces, tracebacks, library
    URLs) in the middle of the findings. PROWL_DEBUG=1 turns them back on, for troubleshooting.
    """
    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)
    if os.environ.get("PROWL_DEBUG"):
        logging.basicConfig(level=logging.DEBUG, stream=sys.stderr,
                            format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    else:
        root.addHandler(logging.NullHandler())


_MAX_LIVE_FINDINGS = 15   # per collector, live callback only

_streamed: set[int] = set()   # findings already printed by _on_progress (by identity)
_stream_counts: dict[str, int] = {}     # INFO/LOW lines printed live, per collector
_stream_hidden: dict[str, int] = {}     # INFO/LOW findings streamed but not printed (cap)
_NOTICE_PREFIXES = ("[INFO] ", "[WARNING] ")   # core/runner.py notices (core never prints)
_LOW_SEVERITIES = {"INFO", "LOW"}       # capped like the end-of-collector listing; MEDIUM+ never

_SEVERITY_COLOR = {
    "CRITICAL": "red", "HIGH": "orange3", "MEDIUM": "yellow",
    "LOW": "blue", "INFO": "dim",
}


def _on_progress(message: str, finding=None) -> None:
    """From slow collectors, while they work: a status line, or one finding, printed at once."""
    if finding is None:
        if message.startswith(_NOTICE_PREFIXES):
            typer.echo(message, err=True)            # scan-flow notices from the runner: stderr
        else:
            console.print(escape(message), style="cyan")
        return
    _streamed.add(id(finding))                    # accounted for, printed or not
    sev = finding.severity.value.upper()
    if sev in _LOW_SEVERITIES:
        shown = _stream_counts.get(finding.source, 0)
        if shown >= _MAX_LIVE_FINDINGS:           # a crt.sh run can return thousands
            _stream_hidden[finding.source] = _stream_hidden.get(finding.source, 0) + 1
            return
        _stream_counts[finding.source] = shown + 1
    color = _SEVERITY_COLOR.get(sev, "white")
    line = Text(f"    {sev:8} ", style=color)
    line.append(f"{finding.source:<16}  ", style="dim")
    line.append(finding.title)
    if finding.source_url and finding.source in _DETAIL_SOURCES:   # profile URLs, not API queries
        line.append("  ")
        line.append(finding.source_url, style=f"underline bright_blue link {finding.source_url}")
    console.print(line)


def _on_result(name, findings, error) -> None:
    """Live per-collector progress, printed as each collector finishes."""
    key = name.split(" → ")[0]                    # "GitHub → Jane Doe" streams as "GitHub"
    hidden = _stream_hidden.pop(key, 0)
    _stream_counts.pop(key, None)                 # the cap applies per collector (and per person)
    if isinstance(error, CollectorSkipped):
        console.print(f"  [yellow]⚠ {escape(name)}: skipped — {escape(str(error))}[/]")
    elif error:
        console.print(f"  [red]✗ {escape(name)}:[/] {escape(str(error))}")
    elif findings and all(id(f) in _streamed for f in findings):
        # everything was already printed one by one while the collector ran
        console.print(f"  [green]✓ {escape(name)}:[/] {len(findings)} findings [dim](listed above)[/dim]")
        if hidden:
            console.print(f"  [dim]… and {hidden} more INFO findings not listed live "
                          f"(see the final table)[/dim]")
    elif findings:
        findings = [f for f in findings if id(f) not in _streamed]     # no duplicates
        console.print(f"  [green]✓ {escape(name)}:[/] {len(findings)} findings")
        for f in findings[:_MAX_LIVE_FINDINGS]:
            sev = f.severity.value.upper()
            color = _SEVERITY_COLOR.get(sev, "white")
            console.print(f"    [{color}]{sev:8}[/] {escape(f.title)}")
        if len(findings) > _MAX_LIVE_FINDINGS:
            # live view only — the final table still lists every finding
            console.print(f"  [dim]… and {len(findings) - _MAX_LIVE_FINDINGS} more[/dim]")
    else:
        console.print(f"  [dim]✓ {escape(name)}: 0 findings[/dim]")


def _handle_export(report, output: str) -> None:
    path = Path(output)

    if path.suffix.lower() == ".json":
        from reports.exporter import to_json
        to_json(report, str(path))
        console.print(f"[green]✓[/green] Saved to [cyan]{path}[/cyan]")

    elif path.suffix.lower() == ".pdf":
        from reports.pdf_exporter import to_pdf   # imported here: WeasyPrint is slow to load
        to_pdf(report, str(path))
        console.print(f"[green]✓[/green] PDF saved to [cyan]{path}[/cyan]")

    else:
        console.print(
            f"[red]Unknown format '[/red]{path.suffix}[red]'.[/red] "
            "Use .json or .pdf"
        )
