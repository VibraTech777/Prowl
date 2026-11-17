import pytest

from core import runner
from core.collectors.base import BaseCollector
from core.models import Category, CollectorResult, OsintTarget, Severity
from tests.conftest import make_finding


def _collector(cname, findings=None, *, tier=1, french=False, crawl=False,
               raises: Exception | None = None, key_env: str = ""):
    class _C(BaseCollector):
        name = cname
        french_only = french
        requires_crawl = crawl
        requires_api_key = bool(key_env)
        api_key_env = key_env

        async def collect(self, target):
            if raises:
                raise raises
            return CollectorResult(findings=list(findings or []))

    _C.tier = tier
    return _C()


@pytest.fixture
def target():
    return OsintTarget(company_name="Acme", domain="example.com")


async def test_sorts_by_severity_and_assigns_sequential_ids(monkeypatch, target):
    monkeypatch.setattr(runner, "ALL_COLLECTORS", [
        _collector("a", [make_finding(Severity.INFO, asset="i1"),
                         make_finding(Severity.CRITICAL, asset="c1")]),
        _collector("b", [make_finding(Severity.HIGH, asset="h1"),
                         make_finding(Severity.INFO, asset="i2")]),
    ])
    report = await runner.run_osint(target)

    assert [f.severity for f in report.findings] == [
        Severity.CRITICAL, Severity.HIGH, Severity.INFO, Severity.INFO]
    assert [f.id for f in report.findings] == ["F001", "F002", "F003", "F004"]
    # stable: equal severities keep collector order
    assert [f.affected_asset for f in report.findings][2:] == ["i1", "i2"]
    assert report.collectors_run == ["a", "b"]
    assert report.duration_seconds >= 0


async def test_failed_collector_goes_to_errors_not_collectors_run(monkeypatch, target):
    monkeypatch.setattr(runner, "ALL_COLLECTORS", [
        _collector("ok", [make_finding()]),
        _collector("bad", raises=RuntimeError("boom")),
    ])
    report = await runner.run_osint(target)

    assert report.collectors_run == ["ok"]
    assert report.errors == {"bad": "RuntimeError: boom"}
    assert not set(report.collectors_run) & set(report.errors)
    assert len(report.findings) == 1


async def test_on_result_called_per_collector_in_completion_order(monkeypatch, target):
    import asyncio

    class _Slow(BaseCollector):
        name = "slow"

        async def collect(self, t):
            await asyncio.sleep(0.05)
            return CollectorResult(findings=[make_finding(asset="s")])

    monkeypatch.setattr(runner, "ALL_COLLECTORS", [
        _Slow(),                                         # listed first, finishes last
        _collector("fast", [make_finding(asset="f")]),
        _collector("bad", raises=RuntimeError("boom")),
    ])
    calls = []
    report = await runner.run_osint(
        target, on_result=lambda name, findings, error: calls.append((name, len(findings), error))
    )

    assert [c[0] for c in calls][-1] == "slow"           # live: fast ones reported first
    by_name = {c[0]: c for c in calls}
    assert by_name["fast"][1:] == (1, None)
    assert isinstance(by_name["bad"][2], RuntimeError) and by_name["bad"][1] == 0
    # the final report stays deterministic: collector order, not completion order
    assert report.collectors_run == ["slow", "fast"]
    assert report.errors == {"bad": "RuntimeError: boom"}


async def test_failing_callback_does_not_fail_the_collector(monkeypatch, target):
    monkeypatch.setattr(runner, "ALL_COLLECTORS", [_collector("ok", [make_finding()])])

    def broken(name, findings, error):
        raise ValueError("ui exploded")

    report = await runner.run_osint(target, on_result=broken)
    assert report.collectors_run == ["ok"] and report.errors == {}
    assert len(report.findings) == 1


async def test_mode_and_flag_filtering(monkeypatch):
    monkeypatch.setattr(runner, "ALL_COLLECTORS", [
        _collector("t1"),
        _collector("t2", tier=2),
        _collector("fr", french=True),
        _collector("cr", crawl=True),
    ])
    base = dict(company_name="Acme", domain="example.com")

    short = await runner.run_osint(OsintTarget(**base))
    assert short.collectors_run == ["t1"]

    deep = await runner.run_osint(OsintTarget(**base, mode="deep"))
    assert deep.collectors_run == ["t1", "t2"]

    fr = await runner.run_osint(OsintTarget(**base, french=True))
    assert fr.collectors_run == ["t1", "fr"]

    cr = await runner.run_osint(OsintTarget(**base, crawl=True))
    assert cr.collectors_run == ["t1", "cr"]


async def test_selected_allowlist_and_missing_key(monkeypatch, target):
    monkeypatch.delenv("PROWL_NO_KEY", raising=False)
    monkeypatch.setattr(runner, "ALL_COLLECTORS", [
        _collector("a"), _collector("b"), _collector("keyed", key_env="PROWL_NO_KEY"),
    ])
    report = await runner.run_osint(target, selected=["b", "keyed"])
    assert report.collectors_run == ["b"]      # keyed skipped: no API key


async def test_assets_are_deduplicated_and_sorted(monkeypatch, target):
    monkeypatch.setattr(runner, "ALL_COLLECTORS", [_collector("a", [
        make_finding(category=Category.SUBDOMAIN, asset="z.example.com"),
        make_finding(category=Category.SUBDOMAIN, asset="a.example.com"),
        make_finding(category=Category.SUBDOMAIN, asset="a.example.com"),
        make_finding(category=Category.EMAIL, asset="x@example.com"),
    ])])
    report = await runner.run_osint(target)
    assert report.assets == {
        "subdomains": ["a.example.com", "z.example.com"],
        "emails": ["x@example.com"],
        "ips": [],
    }


# ── skipped collectors ("Name (no key)") ─────────────────────────────────────


async def test_collector_without_key_is_reported_as_skipped(monkeypatch, target):
    monkeypatch.delenv("PROWL_NO_KEY", raising=False)
    monkeypatch.setattr(runner, "ALL_COLLECTORS", [
        _collector("a"), _collector("keyed", key_env="PROWL_NO_KEY")])
    report = await runner.run_osint(target)
    assert report.collectors_run == ["a"]
    assert report.collectors_skipped == ["keyed"]


async def test_collector_with_key_is_not_skipped(monkeypatch, target):
    monkeypatch.setenv("PROWL_NO_KEY", "k")
    monkeypatch.setattr(runner, "ALL_COLLECTORS", [_collector("keyed", key_env="PROWL_NO_KEY")])
    report = await runner.run_osint(target)
    assert report.collectors_run == ["keyed"] and report.collectors_skipped == []


async def test_only_collectors_eligible_for_this_run_can_be_skipped(monkeypatch):
    """Excluded by --french / --crawl / --mode / selected ⇒ not 'no key', not listed."""
    monkeypatch.delenv("PROWL_NO_KEY", raising=False)
    monkeypatch.setattr(runner, "ALL_COLLECTORS", [
        _collector("fr", french=True, key_env="PROWL_NO_KEY"),
        _collector("cr", crawl=True, key_env="PROWL_NO_KEY"),
        _collector("t2", tier=2, key_env="PROWL_NO_KEY"),
        _collector("other", key_env="PROWL_NO_KEY"),
    ])
    base = dict(company_name="Acme", domain="example.com")

    assert (await runner.run_osint(OsintTarget(**base))).collectors_skipped == ["other"]
    assert (await runner.run_osint(OsintTarget(**base, french=True))).collectors_skipped == ["fr", "other"]
    assert (await runner.run_osint(OsintTarget(**base, mode="deep", crawl=True))
            ).collectors_skipped == ["cr", "t2", "other"]
    assert (await runner.run_osint(OsintTarget(**base), selected=["fr"])).collectors_skipped == []


async def test_unavailable_person_collector_is_reported_when_pivot_is_on(monkeypatch, target):
    from core.collectors.base import BasePersonCollector

    class _KeyedPerson(BasePersonCollector):
        name = "KeyedPerson"
        requires_api_key, api_key_env = True, "PROWL_NO_PKEY"

        async def collect_person(self, person, target):
            raise AssertionError("must not run without a key")

    monkeypatch.delenv("PROWL_NO_PKEY", raising=False)
    monkeypatch.setattr(runner, "ALL_COLLECTORS", [_collector("a")])
    monkeypatch.setattr(runner, "PERSON_COLLECTORS", [_KeyedPerson()])

    off = await runner.run_osint(target)                                     # pivot disabled
    on = await runner.run_osint(OsintTarget("Acme", "example.com", pivot_depth=1))
    assert off.collectors_skipped == [] and on.collectors_skipped == ["KeyedPerson"]


# ── Phase 1 deduplication ────────────────────────────────────────────────────


def _f(title, asset):
    return make_finding(title=title, asset=asset)


async def test_duplicate_findings_removed(monkeypatch, target):
    monkeypatch.setattr(runner, "ALL_COLLECTORS", [
        _collector("a", [_f("Subdomain: www.example.com", "www.example.com")]),
        _collector("b", [_f(" SUBDOMAIN: www.example.com ", "WWW.example.com")]),  # same, case/space
    ])
    report = await runner.run_osint(target)
    assert len(report.findings) == 1
    assert report.findings[0].source == "test" and report.collectors_run == ["a", "b"]


async def test_subdomain_titles_differing_between_collectors_are_deduplicated(monkeypatch, target):
    """crt.sh (real title format) vs DNSDumpster (title carries the IP): one finding, crt.sh's."""
    monkeypatch.setattr(runner, "ALL_COLLECTORS", [
        _collector("crt.sh", [make_finding(title="Subdomain discovered: api.example.com",
                                           asset="api.example.com", source="crt.sh")]),
        _collector("DNSDumpster", [make_finding(title="Subdomain: api.example.com → 1.2.3.4",
                                                asset="api.example.com", source="DNSDumpster")]),
    ])
    report = await runner.run_osint(target)
    assert [f.source for f in report.findings] == ["crt.sh"]


async def test_subdomain_dedup_never_downgrades_severity(monkeypatch, target):
    monkeypatch.setattr(runner, "ALL_COLLECTORS", [
        _collector("crt.sh", [make_finding(Severity.INFO, title="Subdomain discovered: vpn.example.com",
                                           asset="vpn.example.com", source="crt.sh")]),
        _collector("DNSDumpster", [make_finding(Severity.MEDIUM, title="Subdomain: vpn.example.com → 1.1.1.1",
                                                asset="vpn.example.com", source="DNSDumpster")]),
    ])
    report = await runner.run_osint(target)
    assert [(f.source, f.severity) for f in report.findings] == [("DNSDumpster", Severity.MEDIUM)]


async def test_summary_finding_does_not_collide_with_apex_subdomain(monkeypatch, target):
    monkeypatch.setattr(runner, "ALL_COLLECTORS", [
        _collector("crt.sh", [make_finding(title="Subdomain discovered: example.com",
                                           asset="example.com")]),
        _collector("DNSDumpster", [make_finding(title="DNSDumpster: 6 subdomains discovered for example.com",
                                                asset="example.com")]),
    ])
    assert len((await runner.run_osint(target)).findings) == 2


async def test_live_dedup_filters_on_result(monkeypatch, target):
    monkeypatch.setattr(runner, "ALL_COLLECTORS", [
        _collector("crt.sh", [make_finding(title="Subdomain discovered: api.example.com",
                                           asset="api.example.com")]),
        _collector("DNSDumpster", [
            make_finding(title="Subdomain: api.example.com → 1.2.3.4", asset="api.example.com"),
            make_finding(title="Subdomain: new.example.com → 1.2.3.5", asset="new.example.com"),
        ]),
        _collector("dup-only", [make_finding(title="Subdomain: api.example.com → 9.9.9.9",
                                             asset="api.example.com")]),
        _collector("empty"),
        _collector("broken", raises=RuntimeError("boom")),
    ])
    calls = []
    await runner.run_osint(target, on_result=lambda n, fs, error=None: calls.append((n, [f.affected_asset for f in fs], error)))

    shown = [a for _, assets, _ in calls for a in assets]
    assert shown.count("api.example.com") == 1 and shown.count("new.example.com") == 1
    by_name = {n: (assets, err) for n, assets, err in calls}
    assert "dup-only" not in by_name                       # everything it found was already shown
    assert by_name["empty"] == ([], None)                  # empty results still reported
    assert isinstance(by_name["broken"][1], RuntimeError)  # errors never swallowed


async def test_different_asset_kept(monkeypatch, target):
    monkeypatch.setattr(runner, "ALL_COLLECTORS", [
        _collector("a", [_f("Open port", "a.example.com"), _f("Open port", "b.example.com")]),
    ])
    assert len((await runner.run_osint(target)).findings) == 2


async def test_different_title_kept(monkeypatch, target):
    monkeypatch.setattr(runner, "ALL_COLLECTORS", [
        _collector("a", [_f("Title 1", "a.example.com"), _f("Title 2", "a.example.com")]),
    ])
    assert len((await runner.run_osint(target)).findings) == 2


async def test_github_org_skipped_when_pivot_zero(monkeypatch):
    from core.collectors.github_org import GitHubOrgCollector

    org = GitHubOrgCollector()
    assert org.skip_without_pivot is True
    called = []

    async def fake_collect(self, target):
        called.append(target.pivot_depth)
        return CollectorResult(findings=[])

    monkeypatch.setattr(GitHubOrgCollector, "collect", fake_collect)
    monkeypatch.setattr(runner, "ALL_COLLECTORS", [_collector("t1"), org])
    base = dict(company_name="Acme", domain="example.com")

    assert not runner._matches_mode(org, OsintTarget(**base))
    report = await runner.run_osint(OsintTarget(**base, pivot_depth=0))
    assert report.collectors_run == ["t1"] and called == []
    assert "GitHub Org" not in report.collectors_skipped       # not "no key": simply not eligible

    monkeypatch.setattr(runner, "PERSON_COLLECTORS", [])
    report = await runner.run_osint(OsintTarget(**base, pivot_depth=1))
    assert report.collectors_run == ["t1", "GitHub Org"] and called == [1]


# ── collectors skipped for lack of input ─────────────────────────────────────


async def test_collector_skipped_for_missing_input(monkeypatch, target):
    from core.collectors.base import CollectorSkipped

    monkeypatch.setattr(runner, "ALL_COLLECTORS", [
        _collector("ok", [make_finding()]),
        _collector("BODACC", raises=CollectorSkipped("provide --company or --siren")),
    ])
    calls = []
    report = await runner.run_osint(target, on_result=lambda n, fs, error=None: calls.append((n, error)))

    assert report.collectors_run == ["ok"]
    assert report.errors == {}                                      # not an error
    assert report.skipped_reasons == {"BODACC": "provide --company or --siren"}
    assert report.collectors_skipped == []                          # and not "no key"
    assert isinstance(dict(calls)["BODACC"], CollectorSkipped)      # live callback can tell


# ── progressive display shares the live deduplication (phase 1) ──────────────


def _streaming(cname, titles_assets, *, tier=1):
    class _S(BaseCollector):
        name = cname

        async def collect(self, target):
            fs = [make_finding(title=t, asset=a, source=cname) for t, a in titles_assets]
            for f in fs:
                self._progress(finding=f)
            return CollectorResult(findings=fs)

    _S.tier = tier
    return _S()


async def test_progress_findings_are_deduplicated_across_collectors(monkeypatch, target):
    monkeypatch.setattr(runner, "ALL_COLLECTORS", [
        _streaming("crt.sh", [("Subdomain discovered: api.example.com", "api.example.com")]),
        _streaming("DNSDumpster", [("Subdomain: api.example.com → 1.2.3.4", "api.example.com"),
                                   ("Subdomain: new.example.com → 1.2.3.5", "new.example.com")]),
    ])
    shown, finished = [], []
    report = await runner.run_osint(
        target,
        on_result=lambda n, fs, error=None: finished.append((n, [f.affected_asset for f in fs])),
        on_progress=lambda m, f=None: shown.append(f.affected_asset if f else m))

    assert sorted(shown) == ["api.example.com", "new.example.com"]       # api shown once
    assert dict(finished)["crt.sh"] == ["api.example.com"]
    assert dict(finished)["DNSDumpster"] == ["new.example.com"]          # only what is new
    assert len(report.findings) == 2                                     # final dedup unchanged


async def test_messages_are_never_deduplicated(monkeypatch, target):
    class _M(BaseCollector):
        name = "m"

        async def collect(self, target):
            self._progress("[m] Starting scan — this may take a while...")
            self._progress("[m] Starting scan — this may take a while...")
            return CollectorResult(findings=[])

    monkeypatch.setattr(runner, "ALL_COLLECTORS", [_M()])
    got = []
    await runner.run_osint(target, on_progress=lambda m, f=None: got.append(m))
    assert len(got) == 2


async def test_collector_whose_findings_were_all_streamed_is_still_announced(monkeypatch, target):
    monkeypatch.setattr(runner, "ALL_COLLECTORS", [_streaming("a", [("T", "x.example.com")])])
    finished = []
    await runner.run_osint(target, on_result=lambda n, fs, error=None: finished.append((n, len(fs))),
                           on_progress=lambda m, f=None: None)
    assert finished == [("a", 1)]


async def test_progress_without_callbacks_is_harmless(monkeypatch, target):
    monkeypatch.setattr(runner, "ALL_COLLECTORS", [_streaming("a", [("T", "x.example.com")])])
    assert len((await runner.run_osint(target)).findings) == 1


async def test_blocked_crawler_is_listed_as_failed_in_sources(monkeypatch):
    """End to end: a WAF on the seed → "Web Crawler (✗)", never a green entry with 0 findings."""
    import respx
    from rich.console import Console

    import cli.display as display
    from core.collectors import web_crawl
    from core.collectors.web_crawl import WebCrawlCollector

    monkeypatch.setattr(web_crawl, "_REQUEST_DELAY", 0)
    monkeypatch.setattr(runner, "ALL_COLLECTORS", [WebCrawlCollector()])
    with respx.mock() as m:
        m.route().respond(403, text="blocked", headers={"content-type": "text/html"})
        report = await runner.run_osint(OsintTarget(company_name="", domain="reverb.com",
                                                    crawl=True, crawl_depth=1))

    assert report.collectors_run == [] and "HTTP 403" in report.errors["Web Crawler"]
    rec = Console(record=True, width=200)
    monkeypatch.setattr(display, "console", rec)
    display.print_report(report)
    assert "Web Crawler (✗)" in rec.export_text()
