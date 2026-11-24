import json

import pytest
from typer.testing import CliRunner

import cli.main as cli_main
from cli.main import app
from core.models import Severity
from tests.conftest import make_finding, make_report

runner = CliRunner()


@pytest.fixture
def fake_run(monkeypatch):
    """Replace run_osint so the CLI never touches the network."""
    seen = {}

    async def _fake(target, selected=None, on_result=None, on_progress=None):
        seen["target"] = target
        seen["on_result"] = on_result
        seen["on_progress"] = on_progress
        return make_report(target=target)

    monkeypatch.setattr(cli_main, "run_osint", _fake)
    return seen


def test_help_lists_all_options():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for opt in ("--domain", "--company", "--siren", "--mode", "--french", "-F", "--crawl",
                "--no-crawl", "--depth", "--pivot", "--pivot-limit", "--output",
                "--version", "-V"):
        assert opt in result.output

    text = " ".join(result.output.replace("│", " ").split())          # undo the table wrapping
    assert "Hunter" not in text and "Recursive" not in text            # stale pivot promises gone
    assert "even --pivot 1 sends each login to ~300 external sites" in text
    assert "GitLeak (real email from commits)" in text and "WhatsMyName" in text
    assert "[short|deep]" in text and "reserved for future Tier 2+ collectors" in text
    assert "Requires --siren." in text and "(requires PAPPERS_API_KEY)" in text
    assert "Used in the report header, as a GitHub org candidate, and for OpenCorporates" in text
    assert "Has no effect with --no-crawl." in text
    assert text.count("[default: 25]") == 1 and "(default: 25)" not in text   # no duplicate default


def test_domain_is_required(fake_run):
    assert runner.invoke(app, []).exit_code != 0

    # --version is eager: it answers without --domain and never starts a scan
    for flag in ("--version", "-V"):
        result = runner.invoke(app, [flag])
        assert (result.exit_code, result.output.strip()) == (0, "prowl 0.1.0")
    assert "target" not in fake_run


def test_invalid_mode_exits_with_error(fake_run):
    result = runner.invoke(app, ["-d", "example.com", "-m", "nope"])
    assert result.exit_code == 2                             # usage error, like any bad option
    assert "short" in result.output and "deep" in result.output   # valid values are listed
    assert "target" not in fake_run
    assert runner.invoke(app, ["-d", "example.com", "-m", "deep"]).exit_code == 0


def test_options_are_mapped_to_target(fake_run):
    result = runner.invoke(app, [
        "-d", "acme.fr", "-c", "Acme", "-s", "123456789", "-m", "deep", "-F",
        "--crawl", "--depth", "2",
    ])
    assert result.exit_code == 0, result.output
    t = fake_run["target"]
    assert (t.domain, t.company_name, t.siren) == ("acme.fr", "Acme", "123456789")
    assert (t.mode, t.french, t.crawl, t.crawl_depth) == ("deep", True, True, 2)

    fake_run.clear()
    bad = runner.invoke(app, ["-d", "acme.fr", "--depth", "-1"])
    assert bad.exit_code == 2 and "Crawler depth must be 0 or greater." in bad.output
    assert "target" not in fake_run                          # rejected before the scan
    assert runner.invoke(app, ["-d", "acme.fr", "--depth", "0"]).exit_code == 0   # 0 is valid


def test_crawl_is_on_by_default(fake_run):
    runner.invoke(app, ["-d", "example.com"])
    assert fake_run["target"].crawl is True                      # no flag needed


def test_no_crawl_disables_it_and_crawl_still_works(fake_run):
    runner.invoke(app, ["-d", "example.com", "--no-crawl"])
    assert fake_run["target"].crawl is False
    runner.invoke(app, ["-d", "example.com", "--crawl"])         # explicit form is still accepted
    assert fake_run["target"].crawl is True


def test_help_documents_both_crawl_flags(fake_run):
    out = " ".join(runner.invoke(app, ["--help"]).output.replace("│", " ").split())
    assert "--crawl" in out and "--no-crawl" in out
    assert "On by default" in out and "robots.txt respected" in out


def test_crawl_warning_goes_to_stderr_by_default_and_not_with_no_crawl(fake_run):
    split = CliRunner(mix_stderr=False)
    default = split.invoke(app, ["-d", "example.com"])
    assert "semi-active recon" in default.stderr and "--no-crawl" in default.stderr
    assert "semi-active recon" not in default.stdout
    passive = split.invoke(app, ["-d", "example.com", "--no-crawl"])
    assert "semi-active recon" not in passive.stderr


def test_pivot_option_is_mapped_and_listed_in_help(fake_run):
    assert "--pivot" in runner.invoke(app, ["--help"]).output
    runner.invoke(app, ["-d", "example.com"])
    assert fake_run["target"].pivot_depth == 0                       # disabled by default
    runner.invoke(app, ["-d", "example.com", "--pivot", "2"])
    assert fake_run["target"].pivot_depth == 2

    fake_run.clear()
    bad = runner.invoke(app, ["-d", "example.com", "--pivot", "-1"])
    assert bad.exit_code == 2 and "Pivot depth must be 0 or greater." in bad.output
    assert "target" not in fake_run


def test_pivot_limit_option(fake_run):
    assert "--pivot-limit" in runner.invoke(app, ["--help"]).output
    runner.invoke(app, ["-d", "example.com"])
    assert fake_run["target"].pivot_limit == 25                      # default
    runner.invoke(app, ["-d", "example.com", "--pivot", "1", "--pivot-limit", "7"])
    assert fake_run["target"].pivot_limit == 7

    for bad_value in ("0", "-5"):
        fake_run.clear()
        bad = runner.invoke(app, ["-d", "example.com", "--pivot-limit", bad_value])
        assert bad.exit_code == 2 and "Pivot limit must be at least 1." in bad.output
        assert "target" not in fake_run


def test_cli_no_longer_prints_the_pivot_warning(fake_run):
    """The warning moved to the runner: it must only appear if the pivot really runs."""
    split = CliRunner(mix_stderr=False)
    two = split.invoke(app, ["-d", "example.com", "--pivot", "2"])
    assert "performs recursive person recon" not in two.stderr


def test_live_progress_callback_output(fake_run, monkeypatch):
    """The CLI passes a callback that prints per-collector results as they land."""
    runner.invoke(app, ["-d", "example.com"])
    on_result = fake_run["on_result"]
    assert callable(on_result)

    from rich.console import Console

    rec = Console(record=True, width=120)
    monkeypatch.setattr(cli_main, "console", rec)   # restored after the test
    on_result("crt.sh", [make_finding(Severity.HIGH, title="Dépôt [x] test")], None)
    on_result("DNS", [], None)
    on_result("BODACC", [], RuntimeError("BODACC HTTP 404 for [abc]"))
    text = rec.export_text()

    assert "✓ crt.sh: 1 findings" in text
    assert "HIGH" in text and "Dépôt [x] test" in text     # brackets survive Rich markup
    assert "✓ DNS: 0 findings" in text
    assert "✗ BODACC: BODACC HTTP 404 for [abc]" in text


def test_live_output_for_a_skipped_collector(fake_run, monkeypatch):
    from rich.console import Console

    from core.collectors.base import CollectorSkipped

    runner.invoke(app, ["-d", "example.com"])
    rec = Console(record=True, width=120)
    monkeypatch.setattr(cli_main, "console", rec)
    fake_run["on_result"]("BODACC", [], CollectorSkipped("provide --company or --siren"))
    text = rec.export_text()
    assert "⚠ BODACC: skipped — provide --company or --siren" in text
    assert "0 findings" not in text and "✗" not in text


def test_live_output_is_capped_at_15_per_collector(fake_run, monkeypatch):
    runner.invoke(app, ["-d", "example.com"])
    on_result = fake_run["on_result"]

    from rich.console import Console

    rec = Console(record=True, width=120)
    monkeypatch.setattr(cli_main, "console", rec)
    findings = [make_finding(Severity.INFO, title=f"Finding number {i:02d}") for i in range(20)]
    on_result("crt.sh", findings, None)
    text = rec.export_text()

    assert "✓ crt.sh: 20 findings" in text              # header reports the true total
    assert "Finding number 14" in text                  # 15th shown
    assert "Finding number 15" not in text              # 16th hidden
    assert "… and 5 more" in text


def test_live_output_at_exactly_15_has_no_more_line(fake_run, monkeypatch):
    runner.invoke(app, ["-d", "example.com"])
    from rich.console import Console

    rec = Console(record=True, width=120)
    monkeypatch.setattr(cli_main, "console", rec)
    fake_run["on_result"]("DNS", [make_finding(title=f"F{i}") for i in range(15)], None)
    assert "more" not in rec.export_text()


def test_json_export(fake_run, tmp_path):
    out = tmp_path / "r.json"
    result = runner.invoke(app, ["-d", "example.com", "-o", str(out)])
    assert result.exit_code == 0, result.output
    assert json.loads(out.read_text())["target"]["domain"] == "example.com"
    assert "Saved to" in result.output


def test_unknown_export_format_is_rejected_before_the_scan(fake_run, tmp_path):
    result = runner.invoke(app, ["-d", "example.com", "-o", str(tmp_path / "r.txt")])
    assert result.exit_code == 2
    assert "Unknown export format '.txt'" in result.output and ".json or .pdf" in result.output
    assert "target" not in fake_run                         # nothing was scanned

    upper = tmp_path / "R.JSON"                             # the check ignores case
    ok = runner.invoke(app, ["-d", "example.com", "-o", str(upper)])
    assert ok.exit_code == 0 and upper.exists()


def _capture(monkeypatch):
    from rich.console import Console

    rec = Console(record=True, width=140)
    monkeypatch.setattr(cli_main, "console", rec)
    return rec


def test_cli_passes_on_progress_to_the_runner(fake_run):
    runner.invoke(app, ["-d", "example.com"])
    assert callable(fake_run["on_progress"])


def test_progress_header_is_printed_literally(fake_run, monkeypatch, capsys):
    runner.invoke(app, ["-d", "example.com"])
    rec = _capture(monkeypatch)
    capsys.readouterr()
    fake_run["on_progress"]("[WhatsMyName] Checking jdoe across 281 platforms — this may take a while...")
    assert "[WhatsMyName] Checking jdoe across 281 platforms — this may take a while..." in rec.export_text()

    # notices sent by core/runner.py ("[INFO] …", "[WARNING] …") are printed on stderr, not stdout
    capsys.readouterr()                                   # drop what the line above printed
    fake_run["on_progress"]("[WARNING] No GITHUB_TOKEN — GitHub pivot limited")
    fake_run["on_progress"]("[INFO] Pivot level 1: capped at 5/9 persons.")
    captured = capsys.readouterr()
    assert "[WARNING] No GITHUB_TOKEN" in captured.err and "capped at 5/9" in captured.err
    assert captured.out == "" and "GITHUB_TOKEN" not in rec.export_text()


def test_progress_prints_each_finding_immediately_with_its_url(fake_run, monkeypatch):
    runner.invoke(app, ["-d", "example.com"])
    rec = _capture(monkeypatch)
    f = make_finding(Severity.MEDIUM, title="Username 'jdoe' found on Xing", source="WhatsMyName",
                     source_url="https://www.xing.com/profile/jdoe")
    fake_run["on_progress"]("", f)
    out = rec.export_text()
    assert "MEDIUM" in out and "Username 'jdoe' found on Xing" in out
    assert "https://www.xing.com/profile/jdoe" in out


def test_streamed_findings_are_not_printed_twice(fake_run, monkeypatch):
    runner.invoke(app, ["-d", "example.com"])
    rec = _capture(monkeypatch)
    a = make_finding(title="Username 'jdoe' found on A")
    b = make_finding(title="Username 'jdoe' found on B")
    fake_run["on_progress"]("", a)
    fake_run["on_progress"]("", b)
    fake_run["on_result"]("WhatsMyName → Jane Doe", [a, b], None)
    out = rec.export_text()
    assert out.count("found on A") == 1 and out.count("found on B") == 1
    assert "WhatsMyName → Jane Doe: 2 findings (listed above)" in out


def test_partially_streamed_collector_prints_only_the_rest(fake_run, monkeypatch):
    runner.invoke(app, ["-d", "example.com"])
    rec = _capture(monkeypatch)
    a, b = make_finding(title="already shown"), make_finding(title="not yet shown")
    fake_run["on_progress"]("", a)
    fake_run["on_result"]("X", [a, b], None)
    out = rec.export_text()
    assert out.count("already shown") == 1 and "not yet shown" in out


# ── live streaming: source tag, INFO cap, no duplicates ──────────────────────


def _stream(fake_run, monkeypatch, findings, finish=None):
    runner.invoke(app, ["-d", "example.com"])
    rec = _capture(monkeypatch)
    for f in findings:
        fake_run["on_progress"]("", f)
    if finish:
        fake_run["on_result"](*finish)
    return rec.export_text()


def test_url_is_shown_only_for_people_sources(fake_run, monkeypatch):
    sub = make_finding(title="Subdomain: a.example.com", source="DNSDumpster",
                       source_url="https://api.hackertarget.com/hostsearch/?q=example.com")
    who = make_finding(title="Username 'x' found on Y", source="WhatsMyName",
                       source_url="https://y.test/x")
    out = _stream(fake_run, monkeypatch, [sub, who])
    assert "hackertarget" not in out and "https://y.test/x" in out


def test_streamed_line_shows_the_source(fake_run, monkeypatch):
    f = make_finding(title="Subdomain discovered: a.example.com", source="crt.sh")
    out = _stream(fake_run, monkeypatch, [f])
    line = next(l for l in out.splitlines() if "a.example.com" in l)
    assert "INFO" in line and "crt.sh" in line


def test_info_lines_are_capped_per_collector_but_all_are_accounted_for(fake_run, monkeypatch):
    fs = [make_finding(title=f"Subdomain discovered: h{i}.example.com", source="crt.sh")
          for i in range(40)]
    out = _stream(fake_run, monkeypatch, fs, finish=("crt.sh", fs, None))
    assert out.count("Subdomain discovered:") == 15                       # live cap, like before
    assert "crt.sh: 40 findings (listed above)" in out
    assert "and 25 more INFO findings not listed live" in out


def test_medium_and_above_are_never_capped(fake_run, monkeypatch):
    fs = [make_finding(Severity.INFO, title=f"info {i}", source="crt.sh") for i in range(20)]
    fs += [make_finding(Severity.MEDIUM, title=f"sensitive {i}", source="crt.sh") for i in range(20)]
    out = _stream(fake_run, monkeypatch, fs)
    assert out.count("sensitive") == 20 and out.count("info ") == 15


def test_cap_restarts_for_each_person_of_a_person_collector(fake_run, monkeypatch):
    runner.invoke(app, ["-d", "example.com"])
    rec = _capture(monkeypatch)
    for person in ("Ann A", "Bob B"):
        fs = [make_finding(title=f"{person} hit {i}", source="WhatsMyName") for i in range(10)]
        for f in fs:
            fake_run["on_progress"]("", f)
        fake_run["on_result"](f"WhatsMyName → {person}", fs, None)
    out = rec.export_text()
    assert out.count("Ann A hit") == 10 and out.count("Bob B hit") == 10  # 20 lines, not capped at 15
    assert "WhatsMyName → Bob B: 10 findings (listed above)" in out


def test_error_after_streaming_is_still_reported(fake_run, monkeypatch):
    f = make_finding(title="partial", source="X")
    out = _stream(fake_run, monkeypatch, [f], finish=("X", [], RuntimeError("boom")))
    assert "partial" in out and "✗ X: boom" in out


def test_log_records_never_reach_the_terminal(monkeypatch, capfd):
    """Retry traces / tracebacks / library URLs must not land in the middle of the findings."""
    import logging

    async def noisy(target, selected=None, on_result=None, on_progress=None):
        logging.getLogger("core.collectors.crtsh").warning("crt.sh attempt 1/2 failed (502 Bad Gateway)")
        logging.getLogger("core.runner").error("Collector crt.sh raised an unhandled exception")
        return make_report(target=target)

    monkeypatch.delenv("PROWL_DEBUG", raising=False)
    monkeypatch.setattr(cli_main, "run_osint", noisy)
    runner.invoke(app, ["-d", "example.com", "--no-crawl"])
    captured = capfd.readouterr()
    assert "Bad Gateway" not in captured.err + captured.out and "unhandled exception" not in captured.err + captured.out


def test_prowl_debug_brings_the_log_records_back(monkeypatch):
    import logging

    async def noisy(target, selected=None, on_result=None, on_progress=None):
        logging.getLogger("core.runner").error("Collector X raised an unhandled exception")
        return make_report(target=target)

    monkeypatch.setenv("PROWL_DEBUG", "1")
    monkeypatch.setattr(cli_main, "run_osint", noisy)
    result = runner.invoke(app, ["-d", "example.com", "--no-crawl"])
    assert "unhandled exception" in result.output


def test_source_name_never_runs_into_the_title_of_a_live_finding(fake_run, monkeypatch):
    runner.invoke(app, ["-d", "example.com"])
    rec = _capture(monkeypatch)
    fake_run["on_progress"]("", make_finding(Severity.INFO, title="Historic subdomain", source="Wayback Machine"))
    import re
    assert re.search(r"Wayback Machine {2,}Historic subdomain", rec.export_text())     # never glued together
