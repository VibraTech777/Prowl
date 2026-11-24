import pytest

from core import runner
from core.collectors.base import BaseCollector, BasePersonCollector
from core.models import CollectorResult, OsintPerson, OsintTarget
from tests.conftest import make_finding


def P(name: str) -> OsintPerson:
    return OsintPerson(full_name=name, source="test")


class _Phase1(BaseCollector):
    """A domain collector that 'discovers' persons."""
    name = "p1"

    def __init__(self, persons):
        self._persons = persons

    async def collect(self, target):
        return CollectorResult(findings=[make_finding(asset="phase1")], persons=list(self._persons))


class _PersonCollector(BasePersonCollector):
    """Scripted person collector: records who it was asked about."""
    request_delay = 0

    def __init__(self, name, script=None, fail_on=()):
        self.name = name
        self.script = script or {}          # full_name → list[OsintPerson] to "discover"
        self.fail_on = set(fail_on)
        self.calls: list[str] = []

    async def collect_person(self, person, target):
        self.calls.append(person.full_name)
        if person.full_name in self.fail_on:
            raise RuntimeError(f"{self.name} boom")
        return CollectorResult(
            findings=[make_finding(asset=f"{self.name}:{person.full_name}")],
            persons=list(self.script.get(person.full_name, [])),
        )


async def _run(target, capsys):
    """
    Run a scan and return (report, notices). The notices ("[INFO] …" / "[WARNING] …") reach the
    UI through on_progress; core/ itself must print nothing, which is asserted here.
    """
    notices: list[str] = []
    report = await runner.run_osint(
        target, on_progress=lambda message, finding=None: finding or notices.append(message))
    captured = capsys.readouterr()
    assert (captured.out, captured.err) == ("", ""), "core/ must not print"
    return report, "\n".join(notices)


def _setup(monkeypatch, phase1_persons, *person_collectors):
    monkeypatch.setattr(runner, "ALL_COLLECTORS", [_Phase1(phase1_persons)])
    monkeypatch.setattr(runner, "PERSON_COLLECTORS", list(person_collectors))


def _target(depth: int) -> OsintTarget:
    return OsintTarget(company_name="Acme", domain="example.com", pivot_depth=depth)


def _assets(report):
    return sorted(f.affected_asset for f in report.findings)


async def test_pivot_disabled(monkeypatch):
    pc = _PersonCollector("X")
    _setup(monkeypatch, [P("Alice Martin")], pc)

    async def must_not_run(*a, **k):
        raise AssertionError("_run_person_pivot must not be called when pivot_depth=0")

    monkeypatch.setattr(runner, "_run_person_pivot", must_not_run)
    report = await runner.run_osint(_target(0))

    assert pc.calls == []
    assert _assets(report) == ["phase1"]


async def test_pivot_depth_1(monkeypatch):
    pc = _PersonCollector("X", script={"Alice Martin": [P("Carol New")]})
    _setup(monkeypatch, [P("Alice Martin"), P("Bob Durand")], pc)
    report = await runner.run_osint(_target(1))

    assert pc.calls == ["Alice Martin", "Bob Durand"]       # one call per person, no recursion
    assert _assets(report) == ["X:Alice Martin", "X:Bob Durand", "phase1"]   # findings merged
    assert [f.id for f in report.findings] == ["F001", "F002", "F003"]


async def test_pivot_recursive(monkeypatch):
    pc = _PersonCollector("X", script={
        "Alice Martin": [P("Carol New")],       # found at level 1 → searched at level 2
        "Carol New": [P("Dave Deep")],          # found at level 2 → beyond depth 2, not searched
    })
    _setup(monkeypatch, [P("Alice Martin")], pc)
    report = await runner.run_osint(_target(2))

    assert pc.calls == ["Alice Martin", "Carol New"]
    assert "X:Carol New" in _assets(report)
    assert "X:Dave Deep" not in _assets(report)


async def test_pivot_depth_limits_recursion(monkeypatch):
    pc = _PersonCollector("X", script={"Alice Martin": [P("Carol New")]})
    _setup(monkeypatch, [P("Alice Martin")], pc)
    await runner.run_osint(_target(1))
    assert pc.calls == ["Alice Martin"]

    pc3 = _PersonCollector("X", script={
        "Alice Martin": [P("Carol New")], "Carol New": [P("Dave Deep")]})
    _setup(monkeypatch, [P("Alice Martin")], pc3)
    await runner.run_osint(_target(3))
    assert pc3.calls == ["Alice Martin", "Carol New", "Dave Deep"]


async def test_pivot_dedup(monkeypatch):
    x = _PersonCollector("X", script={"Alice Martin": [P("Carol New")]})
    y = _PersonCollector("Y", script={
        "Alice Martin": [P("carol new"), P("alice martin")]})     # same persons, other case
    _setup(monkeypatch, [P("Alice Martin")], x, y)
    await runner.run_osint(_target(2))

    # Carol is returned by both collectors but searched once per collector at level 2;
    # Alice (already visited) is never searched again.
    assert x.calls == ["Alice Martin", "Carol New"]
    assert y.calls == ["Alice Martin", "Carol New"]


async def test_pivot_loop_is_impossible(monkeypatch):
    """A and B 'discover' each other: the registry stops the cycle."""
    pc = _PersonCollector("X", script={
        "Alice Martin": [P("Bob Durand")], "Bob Durand": [P("Alice Martin")]})
    _setup(monkeypatch, [P("Alice Martin")], pc)
    await runner.run_osint(_target(10))
    assert pc.calls == ["Alice Martin", "Bob Durand"]


async def test_phase1_persons_are_deduplicated(monkeypatch):
    pc = _PersonCollector("X")
    _setup(monkeypatch, [P("Alice Martin"), P("ALICE MARTIN"), P("")], pc)
    await runner.run_osint(_target(1))
    assert pc.calls == ["Alice Martin"]


async def test_pivot_error_continues(monkeypatch):
    x = _PersonCollector("X", fail_on={"Alice Martin"})
    y = _PersonCollector("Y")
    _setup(monkeypatch, [P("Alice Martin"), P("Bob Durand")], x, y)
    report = await runner.run_osint(_target(1))

    # per-person errors are aggregated into ONE entry per collector
    assert report.errors == {"X (pivot)": "1/2 persons failed — RuntimeError: X boom"}
    assert report.pivot_stats == {"X": {"calls": 2, "errors": 1}, "Y": {"calls": 2, "errors": 0}}
    assert y.calls == ["Alice Martin", "Bob Durand"]         # other collector still ran
    assert x.calls == ["Alice Martin", "Bob Durand"]         # and X moved on to the next person
    assert _assets(report) == [
        "X:Bob Durand", "Y:Alice Martin", "Y:Bob Durand", "phase1"]


async def test_unavailable_person_collector_is_skipped(monkeypatch):
    monkeypatch.delenv("PROWL_PIVOT_KEY", raising=False)
    keyed = _PersonCollector("Keyed")
    keyed.requires_api_key, keyed.api_key_env = True, "PROWL_PIVOT_KEY"
    free = _PersonCollector("Free")
    _setup(monkeypatch, [P("Alice Martin")], keyed, free)
    await runner.run_osint(_target(1))
    assert keyed.calls == [] and free.calls == ["Alice Martin"]


async def test_new_persons_get_their_pivot_level(monkeypatch):
    carol = P("Carol New")
    pc = _PersonCollector("X", script={"Alice Martin": [carol]})
    _setup(monkeypatch, [P("Alice Martin")], pc)
    await runner.run_osint(_target(2))
    assert carol.depth_found == 2


async def test_pivot_progress_callback(monkeypatch):
    x = _PersonCollector("X", fail_on={"Bob Durand"})
    _setup(monkeypatch, [P("Alice Martin"), P("Bob Durand")], x)
    calls = []
    await runner.run_osint(
        _target(1), on_result=lambda name, findings, error: calls.append((name, len(findings), error)))

    pivot_calls = [c for c in calls if "→" in c[0]]
    assert pivot_calls[0] == ("X → Alice Martin", 1, None)
    assert pivot_calls[1][0] == "X → Bob Durand" and isinstance(pivot_calls[1][2], RuntimeError)


async def test_pivot_runs_after_phase_1_and_failed_phase1_collector_gives_no_persons(monkeypatch):
    class _Broken(BaseCollector):
        name = "broken"

        async def collect(self, target):
            raise RuntimeError("down")

    pc = _PersonCollector("X")
    monkeypatch.setattr(runner, "ALL_COLLECTORS", [_Broken()])
    monkeypatch.setattr(runner, "PERSON_COLLECTORS", [pc])
    report = await runner.run_osint(_target(1))
    assert pc.calls == [] and "broken" in report.errors


async def test_failing_callback_does_not_break_pivot(monkeypatch):
    pc = _PersonCollector("X")
    _setup(monkeypatch, [P("Alice Martin")], pc)

    def broken(name, findings, error):
        raise ValueError("ui exploded")

    report = await runner.run_osint(_target(1), on_result=broken)
    assert report.errors == {} and "X:Alice Martin" in _assets(report)


# ── FIX 5: aggregated pivot errors ───────────────────────────────────────────


async def test_all_calls_failing_gives_one_aggregated_entry(monkeypatch):
    x = _PersonCollector("X", fail_on={"Alice Martin", "Bob Durand", "Carol New"})
    _setup(monkeypatch, [P("Alice Martin"), P("Bob Durand"), P("Carol New")], x)
    report = await runner.run_osint(_target(1))

    assert list(report.errors) == ["X (pivot)"]              # not one entry per person
    assert report.errors["X (pivot)"].startswith("3/3 persons failed")
    assert report.pivot_stats == {"X": {"calls": 3, "errors": 3}}


async def test_no_failure_means_no_pivot_error_entry(monkeypatch):
    x = _PersonCollector("X")
    _setup(monkeypatch, [P("Alice Martin"), P("Bob Durand")], x)
    report = await runner.run_osint(_target(1))
    assert report.errors == {}
    assert report.pivot_stats == {"X": {"calls": 2, "errors": 0}}


async def test_stats_are_aggregated_across_levels(monkeypatch):
    x = _PersonCollector("X", script={"Alice Martin": [P("Carol New")]},
                         fail_on={"Carol New"})
    _setup(monkeypatch, [P("Alice Martin")], x)
    report = await runner.run_osint(_target(2))
    assert report.pivot_stats == {"X": {"calls": 2, "errors": 1}}
    assert report.errors == {"X (pivot)": "1/2 persons failed — RuntimeError: X boom"}


async def test_phase1_errors_are_untouched_by_aggregation(monkeypatch):
    class _Broken(BaseCollector):
        name = "broken"

        async def collect(self, target):
            raise RuntimeError("down")

    x = _PersonCollector("X", fail_on={"Alice Martin"})
    monkeypatch.setattr(runner, "ALL_COLLECTORS", [_Broken(), _Phase1([P("Alice Martin")])])
    monkeypatch.setattr(runner, "PERSON_COLLECTORS", [x])
    report = await runner.run_osint(_target(1))
    assert set(report.errors) == {"broken", "X (pivot)"}


# ── FIX 4: --pivot-limit ─────────────────────────────────────────────────────


def _limit_target(depth: int, limit: int) -> OsintTarget:
    return OsintTarget(company_name="Acme", domain="example.com",
                       pivot_depth=depth, pivot_limit=limit)


async def test_pivot_is_capped_per_level_and_announced(monkeypatch, capsys):
    pc = _PersonCollector("X")
    _setup(monkeypatch, [P(f"Person {i:02d}") for i in range(30)], pc)
    _, err = await _run(_limit_target(1, 25), capsys)

    assert pc.calls == [f"Person {i:02d}" for i in range(25)]        # first 25, in order
    assert "[INFO] Pivot level 1: capped at 25/30 persons." in err


async def test_no_cap_message_when_under_the_limit(monkeypatch, capsys):
    pc = _PersonCollector("X")
    _setup(monkeypatch, [P("Alice Martin"), P("Bob Durand")], pc)
    _, err = await _run(_limit_target(1, 25), capsys)
    assert "capped" not in err
    assert len(pc.calls) == 2


async def test_limit_is_inclusive(monkeypatch, capsys):
    pc = _PersonCollector("X")
    _setup(monkeypatch, [P(f"Person {i}") for i in range(5)], pc)
    _, err = await _run(_limit_target(1, 5), capsys)
    assert len(pc.calls) == 5 and "capped" not in err


async def test_cap_applies_to_each_level(monkeypatch, capsys):
    pc = _PersonCollector("X", script={"Alice Martin": [P(f"Child {i}") for i in range(10)]})
    _setup(monkeypatch, [P("Alice Martin")], pc)
    _, err = await _run(_limit_target(2, 4), capsys)

    assert pc.calls == ["Alice Martin"] + [f"Child {i}" for i in range(4)]
    assert "Pivot level 2: capped at 4/10 persons." in err


async def test_default_pivot_limit_is_25():
    assert OsintTarget(company_name="A", domain="a.com").pivot_limit == 25


# ── FIX 1: Hunter (phase 1) feeds the pivot ──────────────────────────────────


async def test_hunter_persons_feed_the_pivot(monkeypatch, respx_mock):
    from core.collectors.hunter_io import HunterCollector

    monkeypatch.setenv("HUNTER_API_KEY", "k")
    respx_mock.get(url__regex=r"https://api\.hunter\.io/v2/domain-search.*").respond(json={
        "data": {"emails": [
            {"value": "a@example.com", "first_name": "Alice", "last_name": "Martin",
             "position": "CEO", "confidence": 90},
            {"value": "b@example.com", "first_name": "Bob", "last_name": "Durand",
             "position": "CTO", "confidence": 60},
        ]}})
    pc = _PersonCollector("X")
    monkeypatch.setattr(runner, "ALL_COLLECTORS", [HunterCollector()])
    monkeypatch.setattr(runner, "PERSON_COLLECTORS", [pc])

    # default mode "short": Hunter must still run (tier 1) — and work for any domain, not just French
    report = await runner.run_osint(_target(1))

    assert report.collectors_run == ["Hunter.io"]
    assert pc.calls == ["Alice Martin", "Bob Durand"]


# ── GITHUB_TOKEN warning ─────────────────────────────────────────────────────

WARNING = "[WARNING] No GITHUB_TOKEN — GitHub pivot limited to name search"


def _github_setup(monkeypatch):
    from core.collectors.github_person import GitHubPersonCollector

    async def no_request(self, person, target):                          # never hit the network
        return CollectorResult(findings=[])

    monkeypatch.setattr(GitHubPersonCollector, "collect_person", no_request)
    monkeypatch.setattr(GitHubPersonCollector, "request_delay", 0)
    monkeypatch.setattr(runner, "ALL_COLLECTORS", [_Phase1([P("Alice Martin")])])
    monkeypatch.setattr(runner, "PERSON_COLLECTORS", [GitHubPersonCollector()])


async def test_warns_when_pivot_without_github_token(monkeypatch, capsys):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    _github_setup(monkeypatch)
    _, err = await _run(_target(1), capsys)
    assert WARNING in err
    assert "(~5 persons/hr). Set GITHUB_TOKEN in .env for full coverage." in err


async def test_blank_token_still_warns(monkeypatch, capsys):
    monkeypatch.setenv("GITHUB_TOKEN", "   ")
    _github_setup(monkeypatch)
    _, err = await _run(_target(1), capsys)
    assert WARNING in err


async def test_no_warning_with_token(monkeypatch, capsys):
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_x")
    _github_setup(monkeypatch)
    _, err = await _run(_target(1), capsys)
    assert "GITHUB_TOKEN" not in err


async def test_no_warning_when_pivot_disabled(monkeypatch, capsys):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    _github_setup(monkeypatch)
    _, err = await _run(_target(0), capsys)
    assert "GITHUB_TOKEN" not in err


async def test_no_warning_without_a_github_collector(monkeypatch, capsys):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    _setup(monkeypatch, [], _PersonCollector("X"))
    _, err = await _run(_target(1), capsys)
    assert "GITHUB_TOKEN" not in err


async def test_phase2_findings_not_deduplicated_against_phase1(monkeypatch):
    """Same (title, asset) in phase 1 and in the pivot: both kept (different source/context)."""
    class _P1(BaseCollector):
        name = "p1"

        async def collect(self, target):
            return CollectorResult(
                findings=[make_finding(title="GitHub: Alice", asset="example.com", source="GitHub Org")],
                persons=[P("Alice Martin")])

    class _Pivot(BasePersonCollector):
        name = "GitHub"
        request_delay = 0

        async def collect_person(self, person, target):
            return CollectorResult(findings=[
                make_finding(title="GitHub: Alice", asset="example.com", source="GitHub")])

    monkeypatch.setattr(runner, "ALL_COLLECTORS", [_P1()])
    monkeypatch.setattr(runner, "PERSON_COLLECTORS", [_Pivot()])
    report = await runner.run_osint(_target(1))

    assert sorted(f.source for f in report.findings) == ["GitHub", "GitHub Org"]


# ── pivot warnings only when the pivot really runs ───────────────────────────

RECURSIVE = "persons discovered at one level are investigated at the next"
SKIPPED = "[INFO] --pivot enabled but no persons found in Phase 1 — pivot skipped."


async def test_recursive_warning_printed_when_pivot_2_runs(monkeypatch, capsys):
    _setup(monkeypatch, [P("Alice Martin")], _PersonCollector("X"))
    _, err = await _run(_target(2), capsys)
    assert f"[INFO] --pivot 2: {RECURSIVE}" in err and "[WARNING] --pivot" not in err
    assert SKIPPED not in err


async def test_no_recursive_warning_for_pivot_1(monkeypatch, capsys):
    _setup(monkeypatch, [P("Alice Martin")], _PersonCollector("X"))
    _, err = await _run(_target(1), capsys)
    assert RECURSIVE not in err


async def test_pivot_skipped_with_info_when_no_persons(monkeypatch, capsys, caplog):
    pc = _PersonCollector("X")
    _setup(monkeypatch, [], pc)                       # e.g. GitHub Org failed: no persons
    report, err = await _run(_target(2), capsys)
    assert SKIPPED in err and RECURSIVE not in err
    assert pc.calls == [] and report.pivot_stats == {}

    # without a callback a library user gets the notice from the logging module; still no print
    with caplog.at_level("INFO", logger="core.runner"):
        await runner.run_osint(_target(2))
    assert capsys.readouterr() == ("", "")
    assert "--pivot enabled but no persons found in Phase 1 — pivot skipped." in caplog.text


async def test_pivot_skipped_with_info_when_no_person_collector_available(monkeypatch, capsys):
    class _Keyed(_PersonCollector):
        requires_api_key = True
        api_key_env = "PROWL_NO_KEY"

    monkeypatch.delenv("PROWL_NO_KEY", raising=False)
    pc = _Keyed("K")
    _setup(monkeypatch, [P("Alice Martin")], pc)
    _, err = await _run(_target(2), capsys)
    assert SKIPPED in err and RECURSIVE not in err and pc.calls == []


async def test_token_warning_not_printed_when_pivot_is_skipped(monkeypatch, capsys):
    """No persons in Phase 1 → no GitHub request → no point warning about the token."""
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    _github_setup(monkeypatch)
    monkeypatch.setattr(runner, "ALL_COLLECTORS", [_Phase1([])])
    _, err = await _run(_target(1), capsys)
    assert "GITHUB_TOKEN" not in err and SKIPPED in err


async def test_token_warning_comes_after_phase_1(monkeypatch, capsys):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    _github_setup(monkeypatch)
    notices: list[str] = []
    seen: list[list[str]] = []

    class _Marker(_Phase1):
        async def collect(self, target):
            seen.append(list(notices))                    # notices received so far, in Phase 1
            return await super().collect(target)

    monkeypatch.setattr(runner, "ALL_COLLECTORS", [_Marker([P("Alice Martin")])])
    await runner.run_osint(_target(1), on_progress=lambda m, f=None: f or notices.append(m))
    assert capsys.readouterr() == ("", "")
    assert not any("GITHUB_TOKEN" in n for n in seen[0])    # not at startup
    assert any(WARNING in n for n in notices)               # sent once Phase 1 is done


# ── persons exported in the report ───────────────────────────────────────────


async def test_report_lists_persons_deduplicated_with_pivot_discoveries(monkeypatch):
    pc = _PersonCollector("X", script={"Alice Martin": [P("Carol New"), P("alice martin")]})
    _setup(monkeypatch, [P("Alice Martin"), P("Bob Durand"), P("bob  durand".replace("  ", " "))], pc)
    report = await runner.run_osint(_target(2))
    assert [p.full_name for p in report.persons] == ["Alice Martin", "Bob Durand", "Carol New"]


async def test_report_lists_phase_1_persons_even_without_pivot(monkeypatch):
    _setup(monkeypatch, [P("Alice Martin")], _PersonCollector("X"))
    report = await runner.run_osint(_target(0))
    assert [p.full_name for p in report.persons] == ["Alice Martin"]


# ── progress hook: attached for the run, detached afterwards ─────────────────


async def test_on_progress_is_attached_during_the_run_and_cleared_after(monkeypatch):
    seen = {}

    class _Slow(_PersonCollector):
        async def collect_person(self, person, target):
            seen["during"] = self.on_progress
            self._progress("working…")
            return await super().collect_person(person, target)

    pc = _Slow("X")
    _setup(monkeypatch, [P("Alice Martin")], pc)
    got = []
    await runner.run_osint(_target(1), on_progress=lambda m, f=None: got.append(m))

    assert callable(seen["during"]) and got == ["working…"]
    assert pc.on_progress is None                       # cleared: no leak into the next run


async def test_on_progress_is_cleared_even_if_the_run_fails(monkeypatch):
    pc = _PersonCollector("X")
    _setup(monkeypatch, [P("Alice Martin")], pc)

    async def boom(*a, **k):
        raise RuntimeError("boom")

    monkeypatch.setattr(runner, "_run_person_pivot", boom)
    with pytest.raises(RuntimeError):
        await runner.run_osint(_target(1), on_progress=lambda m, f=None: None)
    assert pc.on_progress is None


# ── collectors that choose their persons (applies_to) and discover colleagues ────────────────────


class _Selective(_PersonCollector):
    """Only for persons with a confirmed login; discovers 'colleagues' like GitHub Colleagues does."""

    def applies_to(self, person, target):
        return bool(person.github_login) and person.depth_found < target.pivot_depth


async def test_a_collector_that_does_not_apply_is_skipped_silently(monkeypatch, capsys):
    plain, selective = _PersonCollector("plain"), _Selective("sel")
    _setup(monkeypatch, [P("Alice Martin")], plain, selective)
    notified = []
    report = await runner.run_osint(_target(2), on_result=lambda n, f, e: notified.append(n))
    capsys.readouterr()
    assert plain.calls == ["Alice Martin"] and selective.calls == []
    assert not any(n.startswith("sel") for n in notified)               # no "0 findings" line either
    assert "sel" not in report.errors


async def test_colleagues_found_at_level_1_are_investigated_at_level_2(monkeypatch, capsys):
    alice = OsintPerson(full_name="Alice Martin", source="t", github_login="alice", depth_found=1)
    bob = OsintPerson(full_name="Bob Durand", source="t", github_login="bob", depth_found=2)
    sel = _Selective("sel", script={"Alice Martin": [bob]})
    other = _PersonCollector("other")
    _setup(monkeypatch, [alice], sel, other)
    report, _ = await _run(_target(2), capsys)
    assert sel.calls == ["Alice Martin"]            # Bob is level 2 = the last: nothing left to discover for
    assert other.calls == ["Alice Martin", "Bob Durand"]
    assert {p.full_name for p in report.persons} == {"Alice Martin", "Bob Durand"}


async def test_with_pivot_1_colleagues_are_not_searched_for(monkeypatch, capsys):
    alice = OsintPerson(full_name="Alice Martin", source="t", github_login="alice", depth_found=1)
    sel = _Selective("sel")
    _setup(monkeypatch, [alice], sel)
    await _run(_target(1), capsys)
    assert sel.calls == []                           # its results could not be pivoted on


async def test_the_runner_tells_collectors_who_is_already_known(monkeypatch, capsys):
    seen = {}

    class _Probe(_PersonCollector):
        async def collect_person(self, person, target):
            seen[person.full_name] = (self.is_known("Alice Martin"), self.is_known("Zed Nobody"))
            return await super().collect_person(person, target)

    _setup(monkeypatch, [P("Alice Martin")], _Probe("probe"))
    await _run(_target(1), capsys)
    assert seen == {"Alice Martin": (True, False)}
