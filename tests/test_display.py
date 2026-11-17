from rich.console import Console

import cli.display as display
from tests.conftest import make_report


def _render(report) -> str:
    rec = Console(record=True, width=160)
    original = display.console
    display.console = rec
    try:
        display.print_report(report)
    finally:
        display.console = original
    return rec.export_text()


def _sources_line(text: str) -> str:
    return next(line for line in text.splitlines() if "Sources" in line)


def test_sources_lists_successful_collectors():
    line = _sources_line(_render(make_report(collectors_run=["DNS", "WHOIS"])))
    assert "DNS, WHOIS" in line and "✗" not in line


def test_sources_marks_failed_collectors():
    report = make_report(
        collectors_run=["DNS", "WHOIS", "BODACC"],
        errors={"crt.sh": "RuntimeError: unreachable"},
    )
    line = _sources_line(_render(report))
    assert "DNS, WHOIS, BODACC, crt.sh (✗)" in line


def test_errors_panel_still_shown():
    text = _render(make_report(errors={"crt.sh": "RuntimeError: down"}))
    assert "Collector Errors" in text and "RuntimeError: down" in text


def test_sources_pivot_partial_failure_shows_ratio():
    report = make_report(collectors_run=["DNS"],
                         errors={"GitHub (pivot)": "3/10 persons failed — RuntimeError: x"},
                         pivot_stats={"GitHub": {"calls": 10, "errors": 3}})
    text = _render(report)
    assert "GitHub (✗ 3/10)" in _sources_line(text)
    assert "GitHub (pivot)" in text and "3/10 persons failed" in text      # detail kept in errors panel


def test_sources_pivot_complete_failure_has_no_ratio():
    report = make_report(collectors_run=["DNS"],
                         errors={"GitHub (pivot)": "4/4 persons failed"},
                         pivot_stats={"GitHub": {"calls": 4, "errors": 4}})
    line = _sources_line(_render(report))
    assert "GitHub (✗)" in line and "4/4" not in line


def test_sources_pivot_success_listed_plainly():
    report = make_report(collectors_run=["DNS"], pivot_stats={"GitHub": {"calls": 5, "errors": 0}})
    line = _sources_line(_render(report))
    assert "DNS, GitHub" in line and "✗" not in line


def test_pivot_error_key_is_not_listed_as_a_phase_1_failure():
    report = make_report(collectors_run=["DNS"],
                         errors={"GitHub (pivot)": "1/2 persons failed", "crt.sh": "RuntimeError: down"},
                         pivot_stats={"GitHub": {"calls": 2, "errors": 1}})
    line = _sources_line(_render(report))
    assert "crt.sh (✗)" in line
    assert "GitHub (pivot) (✗)" not in line


def test_sources_shows_skipped_collectors_after_active_ones():
    report = make_report(collectors_run=["DNS", "WHOIS"], collectors_skipped=["Hunter.io"])
    assert "DNS, WHOIS, Hunter.io (no key)" in _sources_line(_render(report))


def test_sources_orders_active_failed_then_skipped():
    report = make_report(collectors_run=["DNS"], errors={"crt.sh": "RuntimeError: down"},
                         collectors_skipped=["Hunter.io", "Pappers.fr"])
    assert "DNS, crt.sh (✗), Hunter.io (no key), Pappers.fr (no key)" in _sources_line(_render(report))


def test_sources_without_skipped_is_unchanged():
    line = _sources_line(_render(make_report(collectors_run=["DNS"])))
    assert "no key" not in line


def test_sources_shows_collectors_skipped_for_missing_input():
    report = make_report(collectors_run=["DNS"], collectors_skipped=["Hunter.io"],
                         skipped_reasons={"BODACC": "provide --company or --siren"})
    line = _sources_line(_render(report))
    assert "DNS, Hunter.io (no key), BODACC (skipped)" in line


# ── persons recap and detail lines ───────────────────────────────────────────

from core.models import OsintPerson  # noqa: E402
from tests.conftest import make_finding  # noqa: E402


def _persons_report(**kw):
    return make_report(persons=[
        OsintPerson("Jane Doe", role="employee", source="GitHub Org", github_login="jdoe"),
        OsintPerson("John Smith", role="CEO", source="Hunter", email="john@acme.fr"),
        OsintPerson("Ann Lee", source="Annuaire", email_guess="a.lee@acme.fr"),
        OsintPerson("No Data"),
    ], **kw)


def test_persons_recap_columns_and_values():
    text = _render(_persons_report())
    assert "Persons identified" in text
    header = next(l for l in text.splitlines() if "Name" in l and "Role" in l)
    assert "Email" in header and "GitHub" in header
    assert "Jane Doe" in text and "github.com/jdoe" in text            # full name + GitHub
    assert "John Smith" in text and "john@acme.fr" in text             # exact email
    assert "a.lee@acme.fr (guess)" in text                             # guess is marked
    row = next(l for l in text.splitlines() if "No Data" in l)
    assert row.count("—") == 3                                         # role, email, github


def test_persons_recap_absent_without_persons():
    assert "Persons identified" not in _render(make_report())


def test_github_login_is_a_hyperlink():
    rec = Console(record=True, width=160, force_terminal=True)
    original, display.console = display.console, rec
    try:
        display.print_report(_persons_report())
    finally:
        display.console = original
    assert "\x1b]8;" in rec.export_text(styles=True) or "https://github.com/jdoe" in rec.export_text(styles=True)
    assert display._github_cell(OsintPerson("A B", github_login="jdoe")).spans[0].style \
        == "link https://github.com/jdoe"
    assert display._github_cell(OsintPerson("A B")).plain == "—"


def test_person_markup_in_names_is_not_interpreted():
    text = _render(make_report(persons=[OsintPerson("[bold]Evil[/bold] Name", role="[red]x")]))
    assert "[bold]Evil[/bold] Name" in text


def test_person_findings_show_their_description_with_url():
    f = make_finding(title="GitHub org member: Jane Doe (@jdoe)", source="GitHub Org",
                     description="jdoe is a public member of GitHub org acme. "
                                 "URL: https://github.com/jdoe.", asset="Jane Doe")
    text = _render(make_report(findings=[f]))
    assert "GitHub org member: Jane Doe (@jdoe)" in text
    assert "URL:" in text and "https://github.com/jdoe." in text          # URL never split


def test_email_finding_shows_exact_address_pattern_and_confidence():
    f = make_finding(title="Email pattern candidate", source="EmailFormat", asset="j.smith@acme.fr",
                     description="j.smith@acme.fr — pattern: {f}.{last} (confidence: 87%). Detected.")
    text = _render(make_report(findings=[f]))
    assert "j.smith@acme.fr" in text and "pattern: {f}.{last} (confidence: 87%)" in text


def test_other_sources_stay_on_one_line():
    f = make_finding(title="Subdomain: a.acme.fr", source="crt.sh", description="SECRET-DETAIL")
    assert "SECRET-DETAIL" not in _render(make_report(findings=[f]))


def test_linkified_urls_are_hyperlinks_without_trailing_punctuation():
    t = display._linkified("see https://github.com/jdoe. and (https://x.io/a)")
    links = [s.style for s in t.spans if "link" in str(s.style)]
    assert "link https://github.com/jdoe underline bright_blue" in links
    assert any(l.startswith("link https://x.io/a") for l in links)


def test_narrow_terminal_keeps_the_finding_title():
    rec = Console(record=True, width=80)
    original, display.console = display.console, rec
    try:
        display.print_report(make_report())
    finally:
        display.console = original
    text = rec.export_text()
    flat = text.replace("│", " ").replace("\n", " ")
    assert "Finding on" in flat and "dev.example" in flat          # title visible, only wrapped
    assert "Category" not in text and "MITRE" not in text      # dropped to make room
