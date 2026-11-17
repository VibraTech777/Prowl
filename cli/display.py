"""
cli/display.py — Rich terminal renderer for Prowl OSINT reports.

Colour-coded severity table with OSC 8 clickable source URLs.
Supported by most modern terminal emulators (Kitty, iTerm2, GNOME Terminal).
"""

from __future__ import annotations

import re

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from core.models import Finding, OsintPerson, OsintReport, Severity

console = Console()

_SEVERITY_STYLE: dict[str, str] = {
    Severity.CRITICAL: "bold bright_red",
    Severity.HIGH:     "bold red",
    Severity.MEDIUM:   "bold yellow",
    Severity.LOW:      "cyan",
    Severity.INFO:     "dim white",
}

_BANNER = """\
[bold cyan]
██████╗ ██████╗  ██████╗ ██╗    ██╗██╗
██╔══██╗██╔══██╗██╔═══██╗██║    ██║██║
██████╔╝██████╔╝██║   ██║██║ █╗ ██║██║
██╔═══╝ ██╔══██╗██║   ██║██║███╗██║██║
██║     ██║  ██║╚██████╔╝╚███╔███╔╝███████╗
╚═╝     ╚═╝  ╚═╝ ╚═════╝  ╚══╝╚══╝ ╚══════╝
[/bold cyan][dim]Open-source OSINT reconnaissance — v0.1.0[/dim]
"""


def _clickable(label: str, url: str) -> Text:
    """OSC 8 hyperlink: clickable in supported terminals."""
    t = Text(label, style="underline bright_blue")
    t.stylize(f"link {url}")
    return t


_URL_RE = re.compile(r"https?://[^\s)\]>\"']+")

# Findings about people: their description (profile URL, guessed address, pattern…)
# is printed under the title. Other collectors stay one line (crt.sh can return thousands).
_DETAIL_SOURCES = {"GitHub", "GitHub Org", "EmailFormat", "GitLeak", "WhatsMyName"}


def _linkified(text: str, style: str = "dim") -> Text:
    """Text whose URLs are OSC 8 hyperlinks (a Text, so no markup escaping issue)."""
    t = Text(text, style=style)
    for m in _URL_RE.finditer(text):
        url = m.group(0).rstrip(".,;:")
        t.stylize(f"link {url} underline bright_blue", m.start(), m.start() + len(url))
    return t


def _finding_cell(f: Finding) -> Text:
    """Title, plus the description underneath for person-related findings."""
    cell = Text(f.title)
    if f.source in _DETAIL_SOURCES and f.description:
        cell.append("\n")
        cell.append_text(_linkified(f.description))
    return cell


def _github_cell(person: OsintPerson) -> Text:
    if not person.github_login:
        return Text("—", style="dim")
    url = f"https://github.com/{person.github_login}"
    t = Text(f"github.com/{person.github_login}", style="underline bright_blue")
    t.stylize(f"link {url}")
    return t


def _email_cell(person: OsintPerson) -> Text:
    if person.email:
        return Text(person.email)
    if person.email_guess:                      # never mixed with a verified address
        t = Text(person.email_guess)
        t.append(" (guess)", style="dim yellow")
        return t
    return Text("—", style="dim")


def print_persons(report: OsintReport) -> None:
    """Recap of every person identified during the run: Name | Role | Email | GitHub."""
    if not report.persons:
        return
    table = Table(box=box.ROUNDED, header_style="bold cyan", title="Persons identified",
                  title_style="bold cyan", title_justify="left")
    table.add_column("Name", overflow="fold")
    table.add_column("Role", overflow="fold")
    table.add_column("Email", overflow="fold")
    table.add_column("GitHub", overflow="fold")
    for p in report.persons:
        table.add_row(Text(p.full_name), Text(p.role or "—"), _email_cell(p), _github_cell(p))
    console.print(table)


def _badge(severity: Severity) -> Text:
    style = _SEVERITY_STYLE.get(severity, "white")
    return Text(f" {severity.value.upper()} ", style=f"{style} reverse")


def print_banner() -> None:
    console.print(_BANNER)


def print_report(report: OsintReport) -> None:
    """Render the full OSINT report to the terminal."""

    target = report.target

    # -- Header panel --------------------------------------------------------
    # All attempted collectors: successful ones first, failed ones marked (✗)
    sources = list(report.collectors_run) + [
        f"[red]{name} (✗)[/red]" for name in report.errors
        if not name.endswith(" (pivot)")          # pivot failures are shown below, aggregated
    ]
    for name, st in report.pivot_stats.items():   # person pivot collectors
        calls, failed = st["calls"], st["errors"]
        if not failed:
            sources.append(name)
        elif failed >= calls:
            sources.append(f"[red]{name} (✗)[/red]")
        else:
            sources.append(f"[yellow]{name} (✗ {failed}/{calls})[/yellow]")
    sources += [f"[dim]{name} (no key)[/dim]" for name in report.collectors_skipped]
    sources += [f"[yellow]{name} (skipped)[/yellow]" for name in report.skipped_reasons]
    header = "\n".join([
        f"[bold]Target[/bold]  : {target.company_name or '—'} / [cyan]{target.domain}[/cyan]",
        f"[bold]Mode[/bold]    : {target.mode}"
            + ("  [yellow]+french[/yellow]" if target.french else ""),
        f"[bold]Sources[/bold] : {', '.join(sources) or 'none'}",
        f"[bold]Duration[/bold]: {report.duration_seconds}s",
    ])
    console.print(Panel(header, title="[bold cyan]Prowl Report[/bold cyan]", expand=False))

    # -- Findings table ------------------------------------------------------
    # On a narrow terminal (80 columns, or piped output) the fixed columns used to squeeze
    # the Finding column down to nothing: drop Category and MITRE there.
    narrow = console.width < 110
    table = Table(box=box.ROUNDED, header_style="bold cyan", expand=True)
    table.add_column("#",        style="dim",  width=4 if narrow else 5,  no_wrap=True)
    table.add_column("Severity",              width=8 if narrow else 10, no_wrap=True)
    if not narrow:
        table.add_column("Category", style="dim", width=14, no_wrap=True)
    table.add_column("Asset",                 width=20 if narrow else 26, overflow="fold")
    table.add_column("Finding",  ratio=1, min_width=20, overflow="fold")
    if not narrow:
        table.add_column("MITRE", style="dim", width=12, no_wrap=True)
    table.add_column("Source",               width=11 if narrow else 12, no_wrap=True)

    for f in report.findings:
        cells = [f.id, _badge(f.severity)]
        if not narrow:
            cells.append(f.category.value)
        cells += [f.affected_asset, _finding_cell(f)]
        if not narrow:
            cells.append(f.mitre_attack or "—")
        cells.append(_clickable(f.source, f.source_url))
        table.add_row(*cells)

    console.print(table if report.findings else "[dim]No findings.[/dim]")

    # -- Persons recap ---------------------------------------------------------
    print_persons(report)

    # -- Errors panel --------------------------------------------------------
    if report.errors:
        lines = [f"[red]{n}[/red]: {m}" for n, m in report.errors.items()]
        console.print(Panel(
            "\n".join(lines),
            title="[bold red]Collector Errors[/bold red]",
            expand=False,
        ))

    # -- Summary footer ------------------------------------------------------
    sev_order = list(Severity)
    counts = {}
    for f in report.findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    parts = "  ".join(
        f"[{_SEVERITY_STYLE[s]}]{counts[s]} {s.value.upper()}[/]"
        for s in sev_order
        if s in counts
    )
    console.print(f"\n  [bold]{len(report.findings)}[/bold] findings total  {parts}\n")
