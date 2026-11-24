import json
from urllib.parse import urlparse

import httpx
import pytest

from core.collectors import ALL_COLLECTORS, wayback
from core.collectors.base import CollectorSkipped
from core.collectors.wayback import WaybackCollector
from core.models import Category, OsintTarget, Severity

CDX_URL = "https://web.archive.org/cdx/search/cdx"
TARGET = OsintTarget(company_name="Example", domain="example.com")


@pytest.fixture(autouse=True)
def setup(monkeypatch):
    monkeypatch.setattr(WaybackCollector, "request_delay", 0)
    monkeypatch.setattr(wayback, "_dns_state", lambda host: STATES.get(host, "alive"))


STATES: dict[str, str] = {}


@pytest.fixture(autouse=True)
def reset_states():
    STATES.clear()


def _rows(fields, *rows):
    return json.dumps([fields.split(","), *[list(r) for r in rows]])


def team_page(*people):
    cards = "".join(f'<div class="team-member"><h3>{n}</h3><p>{r}</p></div>' for n, r in people)
    return f"<html><body><section class='team'>{cards}</section></body></html>"


def _site(respx_mock, *, inventory=(), subs=(), files=(), team=(), home=(), pages=None, fail=()):
    """Fake archive.org. CDX answers by query kind; `pages` maps a snapshot timestamp → (html, headers)."""
    pages = pages or {}
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        if request.url.path.startswith("/cdx/"):
            params = request.url.params
            filters = params.get_list("filter")
            q = params["url"]
            if params.get("matchType") == "domain":
                kind = ("files" if any("pdf" in f for f in filters) else
                        "subdomains" if int(params["limit"]) < 0 else "inventory")
            else:                                                  # exact lookup: a team path or the homepage
                kind = "home" if "/" not in q else "team"
            if kind in fail:
                return httpx.Response(503, text="busy")
            rows = {"inventory": inventory, "subdomains": subs, "files": files, "team": team, "home": home}[kind]
            if kind == "team":                                     # an exact lookup answers for ONE path
                rows = [r for r in rows if urlparse(r[1]).path.rstrip("/") == "/" + q.split("/", 1)[1]]
            fields = "timestamp,original,mimetype" if kind in ("inventory", "subdomains", "files") else "timestamp,original"
            return httpx.Response(200, text=_rows(fields, *rows))
        ts = request.url.path.split("/")[2].removesuffix("id_")
        if ts in pages:
            html, headers = pages[ts]
            return httpx.Response(200, text=html, headers={"content-type": "text/html", **headers})
        return httpx.Response(404)

    respx_mock.route().mock(side_effect=handler)
    return seen


async def _run(target=TARGET):
    result = await WaybackCollector().collect(target)
    return result.findings, result.persons


def _titles(findings):
    return [f.title for f in findings]


# ── metadata ─────────────────────────────────────────────────────────────────


def test_metadata_registration_and_order():
    c = WaybackCollector()
    assert (c.name, c.tier, c.requires_api_key, c.is_available()) == ("Wayback Machine", 1, False, True)
    names = [x.name for x in ALL_COLLECTORS]
    # last: a person also found by GitHub Org / the registries keeps that richer record in the dedupe
    assert names[-1] == "Wayback Machine" and names.index("GitHub Org") < names.index("Wayback Machine")


async def test_invalid_domain_is_skipped_without_any_request(respx_mock):
    route = respx_mock.route().respond(200)
    with pytest.raises(CollectorSkipped):
        await _run(OsintTarget(company_name="", domain="exa mple.com"))
    assert route.call_count == 0


async def test_only_archive_org_is_ever_contacted(respx_mock):
    seen = _site(respx_mock, inventory=[("20190101000000", "https://old.example.com/", "text/html")],
                 team=[("20190101000000", "https://example.com/team"), ("20230101000000", "https://example.com/team")],
                 home=[("20150101000000", "https://example.com/")],
                 pages={"20190101000000": (team_page(("Jane Doe", "CTO")), {}),
                        "20230101000000": (team_page(("John Roe", "CEO")), {}),
                        "20150101000000": ("<html></html>", {})})
    await _run()
    assert seen and all(u.startswith("https://web.archive.org/") for u in seen)
    # the captured URLs are fetched THROUGH the archive (raw replay), never directly
    assert any("/web/20190101000000id_/https://example.com/team" in u for u in seen)


# ── subdomains ───────────────────────────────────────────────────────────────


async def test_subdomains_gone_or_alive(respx_mock):
    STATES.update({"old.example.com": "gone", "live.example.com": "alive", "slow.example.com": "unknown"})
    _site(respx_mock, inventory=[
        ("20150101000000", "http://old.example.com/a", "text/html"),
        ("20180101000000", "https://live.example.com/", "text/html"),
        ("20170101000000", "https://slow.example.com/", "text/html"),
        ("20190101000000", "https://www.example.com/", "text/html"), ("20190101000000", "https://example.com/", "text/html"),
        ("20190101000000", "https://evilexample.com/", "text/html"), ("20190101000000", "https://example.com.evil.org/", "text/html")])
    findings, _ = await _run()
    subs = {f.affected_asset: f for f in findings if f.category is Category.SUBDOMAIN}

    assert set(subs) == {"old.example.com", "live.example.com", "slow.example.com"}      # not apex / www / lookalikes
    assert subs["old.example.com"].title == "Historic subdomain (no longer resolves): old.example.com"
    assert "last capture 2015" in subs["old.example.com"].description
    # alive / unknown: titled "Subdomain …" so the runner de-duplicates them with crt.sh & co
    assert subs["live.example.com"].title == "Subdomain seen in Wayback Machine: live.example.com"
    assert subs["slow.example.com"].raw_data["dns"] == "unknown" and "inconclusive" in subs["slow.example.com"].description
    assert all(f.severity is Severity.INFO and f.source == "Wayback Machine" for f in subs.values())
    assert subs["old.example.com"].source_url == "https://web.archive.org/web/20150101000000/http://old.example.com/a"


# ── endpoints and files ──────────────────────────────────────────────────────


async def test_old_api_endpoints_and_sensitive_paths(respx_mock):
    _site(respx_mock,
          inventory=[("20170101000000", "https://api.example.com/api/v1/users/1", "text/html")],
          files=[("20180101000000", "https://example.com/api/v1/orders", "application/json"),
                 ("20160101000000", "https://example.com/admin/users", "text/html"),
                 ("20150101000000", "https://example.com/phpmyadmin/index.php", "text/html"),
                 ("20190101000000", "https://example.com/blog/administrating-the-administrator", "text/html")])
    findings, _ = await _run()
    by = {f.title.split(":")[0]: f for f in findings if f.category is Category.WEB_FINDING}

    api = by["Historic API endpoints in the Wayback Machine"]
    assert api.severity is Severity.INFO and "api.example.com/api/v1/ (2017)" in api.description and "example.com/api/v1/ (2018)" in api.description
    assert "NOT checked" in api.description
    sens = by["Sensitive-looking paths archived"]
    assert sens.severity is Severity.MEDIUM and sens.title.endswith(": 2")                   # admin + phpmyadmin
    assert "administrating" not in sens.description                                          # whole-segment match


async def test_archived_files(respx_mock):
    files = [("20190101000000", "https://example.com/backup/db.sql", "text/plain"),
             ("20150101000000", "https://example.com/backup/db.sql", "text/plain"),
             ("20180101000000", "https://example.com/.env", "text/plain"),
             ("20160101000000", "https://example.com/files/report.pdf", "application/pdf"),
             ("20170101000000", "https://example.com/files/q3.XLSX", "application/vnd.ms-excel")]
    _site(respx_mock, files=files)
    findings, _ = await _run()

    sens = [f for f in findings if f.category is Category.CODE_LEAK]
    assert [f.title for f in sens] == ["Archived sensitive file: example.com/.env (captured 2018)",
                                       "Archived sensitive file: example.com/backup/db.sql (captured 2019)"]   # newest capture, once
    assert all(f.severity is Severity.MEDIUM and "not checked live" in f.description for f in sens)
    assert sens[1].source_url == "https://web.archive.org/web/20190101000000/https://example.com/backup/db.sql"
    (docs,) = [f for f in findings if f.title.startswith("Archived documents")]
    assert docs.severity is Severity.INFO and docs.title == "Archived documents: 2 (xlsx 1, pdf 1)"


async def test_sensitive_files_are_capped(respx_mock):
    _site(respx_mock, files=[("20190101000000", f"https://example.com/b/{i:02d}.sql", "text/plain") for i in range(40)])
    findings, _ = await _run()
    assert len([f for f in findings if f.category is Category.CODE_LEAK]) == wayback._MAX_FILES


# ── former employees ─────────────────────────────────────────────────────────

TEAM = [("20160101000000", "https://example.com/team"), ("20190101000000", "https://example.com/team"),
        ("20230101000000", "https://example.com/team")]


async def test_former_employees_become_findings_and_persons(respx_mock):
    _site(respx_mock, team=TEAM, pages={
        "20160101000000": (team_page(("Jane Doe", "CTO"), ("Ann Old", "Designer")), {}),
        "20190101000000": (team_page(("Jane Doe", "CTO"), ("Bob Gone", "Sales Lead"), ("Cy Stays", "COO")), {}),
        "20230101000000": (team_page(("Cy Stays", "COO"), ("Jane Doe", "CTO"), ("New Hire", "Engineer")), {})})
    findings, persons = await _run()

    former = [f for f in findings if f.title.startswith("Possible former employee")]
    assert sorted(f.title for f in former) == ["Possible former employee: Ann Old", "Possible former employee: Bob Gone"]
    ann = next(f for f in former if "Ann" in f.title)
    assert ann.severity is Severity.INFO and ann.category is Category.COMPANY_INFO and ann.mitre_attack == "T1589.003"
    assert "/team in 2016 but not on the 2023 snapshot" in ann.description and ann.affected_asset == "Ann Old"
    assert ann.source_url == "https://web.archive.org/web/20160101000000/https://example.com/team"
    assert ann.raw_data["absent_from"] == "2023" and ann.raw_data["first_seen"] == "20160101000000"

    assert sorted((p.full_name, p.role, p.source) for p in persons) == [
        ("Ann Old", "Designer — possible former employee (seen 2016)", "Wayback Machine"),
        ("Bob Gone", "Sales Lead — possible former employee (seen 2019)", "Wayback Machine")]
    assert all(p.depth_found == 1 and not p.email and not p.github_login for p in persons)


async def test_nobody_is_flagged_without_something_to_compare(respx_mock):
    one = [("20190101000000", "https://example.com/team")]
    _site(respx_mock, team=one, pages={"20190101000000": (team_page(("Jane Doe", "CTO")), {})})
    assert (await _run())[1] == []                                              # a single snapshot

    js_site = "<html><body><div id='root'></div></body></html>"                 # newest page lists no names
    _site(respx_mock, team=TEAM, pages={"20160101000000": (team_page(("Jane Doe", "CTO")), {}),
                                        "20190101000000": (team_page(("Jane Doe", "CTO")), {}),
                                        "20230101000000": (js_site, {})})
    findings, persons = await _run()
    assert persons == [] and not [f for f in findings if f.title.startswith("Possible former")]


async def test_a_name_still_listed_on_another_team_page_is_not_former(respx_mock):
    about = [("20180101000000", "https://example.com/about"), ("20230101000000", "https://example.com/about")]
    _site(respx_mock, team=[("20160101000000", "https://example.com/team"), ("20230101000000", "https://example.com/team")] + about,
          pages={"20160101000000": (team_page(("Jane Doe", "CTO"), ("Bob Gone", "Sales")), {}),
                 "20180101000000": (team_page(("Jane Doe", "CTO")), {}),
                 "20230101000000": (team_page(("Jane Doe", "CTO"), ("Bob Gone", "Sales")), {})})
    assert (await _run())[1] == []


async def test_former_staff_are_capped(respx_mock):
    old = tuple((f"Person{chr(65 + i // 26)}{chr(65 + i % 26)} Nameson", "Staff") for i in range(45))
    _site(respx_mock, team=TEAM[::2], pages={"20160101000000": (team_page(*old), {}),
                                             "20230101000000": (team_page(("Jane Doe", "CTO")), {})})
    assert len((await _run())[1]) == wayback._MAX_PERSONS


# ── technology history ───────────────────────────────────────────────────────


async def test_technology_history(respx_mock):
    _site(respx_mock,
          home=[("20120101000000", "http://example.com/"), ("20180101000000", "https://www.example.com/"),
                ("20240101000000", "https://example.com/")],
          pages={"20120101000000": ("<html><body><script src='jquery-1.7.2.js'></script></body></html>",
                                    {"x-archive-orig-server": "Apache/2.2.22", "x-archive-orig-x-powered-by": "PHP/5.3.10"}),
                 "20180101000000": ("<html><link href='/wp-content/x.css'></html>", {"x-archive-orig-server": "nginx/1.10"}),
                 "20240101000000": ("<html><body><div data-reactroot></div></body></html>", {"x-archive-orig-server": "cloudflare"})})
    findings, _ = await _run()
    (f,) = [f for f in findings if f.title.startswith("Technology history")]

    assert f.title == "Technology history (Wayback Machine): 2012 → 2024" and f.category is Category.TECH_EXPOSURE
    assert f.severity is Severity.INFO
    assert "2012: server: Apache/2.2.22; x-powered-by: PHP/5.3.10; jQuery 1.7.2" in f.description
    assert "2018: server: nginx/1.10; WordPress" in f.description and "2024: server: cloudflare; React" in f.description
    assert f.raw_data["history"]["2012"][0] == "server: Apache/2.2.22"


# ── failures ─────────────────────────────────────────────────────────────────


async def test_everything_failing_is_a_collector_failure(respx_mock):
    _site(respx_mock, fail=("inventory", "subdomains", "files", "team", "home"))
    with pytest.raises(RuntimeError, match=r"Wayback Machine unavailable \(.*HTTP 503"):
        await _run()


async def _run_with_notices():
    c = WaybackCollector()
    notices: list[str] = []
    c.on_progress = lambda message, finding=None: notices.append(message) if finding is None else None
    result = await c.collect(TARGET)
    return result, [n for n in notices if "Partial results" in n]


async def test_a_partial_failure_keeps_the_rest_and_says_so_on_a_status_line(respx_mock):
    _site(respx_mock, fail=("team",), files=[("20190101000000", "https://example.com/db.sql", "text/plain")])
    result, notices = await _run_with_notices()
    assert [f for f in result.findings if f.category is Category.CODE_LEAK] and result.persons == []
    assert len(notices) == 1 and "team pages: HTTP 503" in notices[0]
    # archive.org's trouble is not a finding about the target: it must not land in the report
    assert not [f for f in result.findings if "incomplete" in f.title.lower()]


async def test_unreadable_snapshots_are_reported_not_fatal(respx_mock):
    _site(respx_mock, team=TEAM, home=[("20150101000000", "https://example.com/")], pages={})   # every page 404
    result, notices = await _run_with_notices()
    assert len(notices) == 1 and "team pages: 3/3" in notices[0] and "homepages: 1/1" in notices[0]
    assert result.persons == [] and not [f for f in result.findings if "incomplete" in f.title.lower()]


async def test_network_error_message_has_the_type_only(respx_mock):
    respx_mock.route().mock(side_effect=httpx.ConnectError("boom"))
    with pytest.raises(RuntimeError, match="unreachable .ConnectError"):
        await _run()


# ── progressive display ──────────────────────────────────────────────────────


async def test_findings_are_streamed_as_they_are_built(respx_mock):
    _site(respx_mock, files=[("20190101000000", "https://example.com/db.sql", "text/plain")])
    c = WaybackCollector()
    events = []
    c.on_progress = lambda message, finding=None: events.append(finding or message)
    result = await c.collect(TARGET)
    assert events[0].startswith("[Wayback Machine] Starting scan")
    assert [e for e in events if not isinstance(e, str)] == result.findings          # each one, once


async def test_each_branch_shows_its_results_without_waiting_for_the_slowest_query(respx_mock):
    """The heavy "files and APIs" query can take minutes: subdomains and the team must not wait for it."""
    import asyncio
    release = asyncio.Event()
    shown_before_release: list[str] = []

    async def slow_handler(request: httpx.Request) -> httpx.Response:
        params = request.url.params
        if request.url.path.startswith("/cdx/"):
            filters = params.get_list("filter")
            if any("pdf" in f for f in filters):                       # the heavy query
                await release.wait()
                return httpx.Response(200, text=_rows("timestamp,original,mimetype",
                                                      ("20190101000000", "https://example.com/db.sql", "text/plain")))
            if params.get("matchType") == "domain" and int(params["limit"]) < 0:
                return httpx.Response(200, text=_rows("timestamp,original,mimetype",
                                                      ("20180101000000", "https://admin.example.com/", "text/html")))
            return httpx.Response(200, text="[]")
        return httpx.Response(404)

    respx_mock.route().mock(side_effect=slow_handler)
    c = WaybackCollector()

    def on_progress(message, finding=None):
        if finding is not None:
            shown_before_release.append(finding.title)
            if not release.is_set():
                asyncio.get_running_loop().call_later(0, release.set)  # let the slow query finish afterwards

    c.on_progress = on_progress
    result = await c.collect(TARGET)
    assert shown_before_release[0] == "Subdomain seen in Wayback Machine: admin.example.com"   # first, alone
    assert "Archived sensitive file: example.com/db.sql (captured 2019)" in _titles(result.findings)


# ── query shapes (learned from the real archive.org) ─────────────────────────


async def test_subdomains_come_from_the_tail_query(respx_mock):
    # CDX keys sort the apex first: a head-only query never reaches the subdomains of a big site
    _site(respx_mock, inventory=[("20190101000000", "https://example.com/p", "text/html")],
          subs=[("20180101000000", "https://admin.example.com/login", "text/html")])
    findings, _ = await _run()
    assert [f.affected_asset for f in findings if f.category is Category.SUBDOMAIN] == ["admin.example.com"]


async def test_a_5xx_is_retried_once(respx_mock):
    import asyncio
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        return httpx.Response(503) if calls["n"] == 1 else httpx.Response(200, text="[]")

    respx_mock.route().mock(side_effect=handler)
    async with httpx.AsyncClient() as client:
        assert await WaybackCollector()._cdx(client, asyncio.Semaphore(1), [("url", "example.com")]) == []
    assert calls["n"] == 2


async def test_team_variants_of_one_path_are_one_history(respx_mock):
    _site(respx_mock, team=[("20160101000000", "http://www.example.com/team/"), ("20230101000000", "https://example.com/team")],
          pages={"20160101000000": (team_page(("Ann Old", "Designer"), ("Jane Doe", "CTO")), {}),
                 "20230101000000": (team_page(("Jane Doe", "CTO")), {})})
    _, persons = await _run()
    assert [p.full_name for p in persons] == ["Ann Old"]
