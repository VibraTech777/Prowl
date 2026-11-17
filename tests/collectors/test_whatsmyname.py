import asyncio

import httpx
import pytest

from core.collectors import PERSON_COLLECTORS
from core.collectors.whatsmyname import (
    WMN_URL, WhatsMyNameCollector, select_sites,
)
from core.models import Category, OsintPerson, OsintTarget, Severity


@pytest.fixture(autouse=True)
def fast(monkeypatch):
    monkeypatch.setattr(WhatsMyNameCollector, "request_delay", 0)


@pytest.fixture
def target():
    return OsintTarget(company_name="Acme", domain="acme.fr")


@pytest.fixture
def person():
    return OsintPerson(full_name="Jane Doe", source="GitHub Org", github_login="jdoe")


def _site(name, host=None, cat="social", **kw):
    host = host or f"{name.lower()}.test"
    return {"name": name, "uri_check": f"https://{host}/u/{{account}}", "e_code": 200,
            "e_string": "", "m_string": "", "m_code": 404, "known": ["x"], "cat": cat, **kw}


def _wmn(respx_mock, *sites):
    return respx_mock.get(WMN_URL).respond(json={"license": [], "authors": [], "sites": list(sites)})


# ── the 5 requested tests ────────────────────────────────────────────────────


async def test_wmn_skips_no_login(respx_mock, target):
    route = respx_mock.route().respond(200, json={"sites": []})
    for login in ("", "   "):
        p = OsintPerson(full_name="Jane Doe", github_login=login)
        assert (await WhatsMyNameCollector().collect_person(p, target)).findings == []
    assert route.call_count == 0                                # not even the list is downloaded


async def test_wmn_finds_profile(respx_mock, person, target):
    _wmn(respx_mock, _site("Alpha", e_string="profile-ok"), _site("Beta"))
    respx_mock.get("https://alpha.test/u/jdoe").respond(200, text="<div>profile-ok</div>")
    respx_mock.get("https://beta.test/u/jdoe").respond(404)

    result = await WhatsMyNameCollector().collect_person(person, target)

    assert len(result.findings) == 1 and result.persons == []
    f = result.findings[0]
    assert f.severity is Severity.INFO
    assert f.title == "Username 'jdoe' found on Alpha"
    assert f.description.startswith("https://alpha.test/u/jdoe")
    assert "may be a different person" in f.description
    assert f.source == "WhatsMyName" and f.source_url == "https://alpha.test/u/jdoe"
    assert f.affected_asset == "Jane Doe" and f.category is Category.COMPANY_INFO
    assert f.mitre_attack == "T1593.001"


async def test_wmn_professional_is_medium(respx_mock, person, target):
    _wmn(respx_mock, _site("Pro", cat="professional"), _site("Biz", cat="business"),
         _site("Soc", cat="social"), _site("Cod", cat="coding"), _site("Tec", cat="tech"))
    respx_mock.route().respond(200, text="ok")
    result = await WhatsMyNameCollector().collect_person(person, target)
    sev = {f.raw_data["site"]: f.severity for f in result.findings}
    assert sev == {"Pro": Severity.MEDIUM, "Biz": Severity.MEDIUM,      # business = professional
                   "Soc": Severity.INFO, "Cod": Severity.INFO, "Tec": Severity.INFO}


async def test_wmn_missing_string_skipped(respx_mock, person, target):
    _wmn(respx_mock, _site("Alpha", m_string="User not found"))
    respx_mock.get("https://alpha.test/u/jdoe").respond(200, text="<p>User not found</p>")
    assert (await WhatsMyNameCollector().collect_person(person, target)).findings == []


async def test_wmn_timeout_ignored(respx_mock, person, target):
    _wmn(respx_mock, _site("Slow"), _site("Dead"), _site("Fine"))
    respx_mock.get("https://slow.test/u/jdoe").mock(side_effect=httpx.ReadTimeout("slow"))
    respx_mock.get("https://dead.test/u/jdoe").mock(side_effect=httpx.ConnectError("down"))
    respx_mock.get("https://fine.test/u/jdoe").respond(200, text="ok")

    result = await WhatsMyNameCollector().collect_person(person, target)     # no crash
    assert [f.raw_data["site"] for f in result.findings] == ["Fine"]          # the others continue


# ── site selection ───────────────────────────────────────────────────────────


def test_category_filter_and_exclusions():
    data = {"sites": [
        _site("Soc", cat="social"), _site("Cod", cat="coding"), _site("Tec", cat="tech"),
        _site("Pro", cat="professional"),
        _site("Game", cat="gaming"), _site("Adult", cat="xx NSFW xx"), _site("Biz", cat="business"),
        _site("GitHub (User)", cat="coding"), _site("GitHub (Gists)", cat="coding"),
        _site("Invalid", cat="social", valid=False),
        _site("Post", cat="social", post_body="u={account}"),
        {"name": "NoPlaceholder", "uri_check": "https://x.test/me", "cat": "social"},
        {"name": "Ftp", "uri_check": "ftp://x.test/{account}", "cat": "social"},
    ]}
    assert [s["name"] for s in select_sites(data)] == [
        "Soc", "Cod", "Tec", "Pro", "Biz", "GitHub (Gists)"]     # GitHub (User) duplicates GitHubPerson


def test_legacy_field_names_are_supported():
    legacy = {"name": "Old", "check_uri": "https://old.test/{account}", "category": "coding",
              "valid": True, "account_existence_code": "200", "account_missing_string": "nope"}
    assert [s["name"] for s in select_sites({"sites": [legacy]})] == ["Old"]


async def test_legacy_schema_check(respx_mock, person, target):
    legacy = {"name": "Old", "check_uri": "https://old.test/{account}", "category": "professional",
              "valid": True, "account_existence_code": 200, "account_missing_string": "nope"}
    _wmn(respx_mock, legacy)
    respx_mock.get("https://old.test/jdoe").respond(200, text="welcome")
    f = (await WhatsMyNameCollector().collect_person(person, target)).findings
    assert [(x.raw_data["site"], x.severity) for x in f] == [("Old", Severity.MEDIUM)]


# ── per-site rules ───────────────────────────────────────────────────────────


async def test_existence_string_is_required_when_given(respx_mock, person, target):
    _wmn(respx_mock, _site("Alpha", e_string="profile-ok"))
    respx_mock.get("https://alpha.test/u/jdoe").respond(200, text="generic 200 page")
    assert (await WhatsMyNameCollector().collect_person(person, target)).findings == []


async def test_other_status_codes_are_not_a_match(respx_mock, person, target):
    _wmn(respx_mock, _site("A"), _site("B"), _site("C", e_code=403))
    respx_mock.get("https://a.test/u/jdoe").respond(301, headers={"location": "https://a.test/"})
    respx_mock.get("https://b.test/u/jdoe").respond(500)
    respx_mock.get("https://c.test/u/jdoe").respond(403, text="ok")          # expected 403 here
    result = await WhatsMyNameCollector().collect_person(person, target)
    assert [f.raw_data["site"] for f in result.findings] == ["C"]            # redirects not followed


async def test_username_is_url_quoted_and_custom_headers_sent(respx_mock, target):
    weird = OsintPerson(full_name="X Y", github_login="a b/c")
    _wmn(respx_mock, _site("Alpha", headers={"X-Api": "1"}))
    route = respx_mock.get("https://alpha.test/u/a%20b%2Fc").respond(200, text="ok")
    await WhatsMyNameCollector().collect_person(weird, target)
    assert route.call_count == 1
    assert route.calls[0].request.headers["x-api"] == "1"


async def test_uri_pretty_is_used_for_the_displayed_url(respx_mock, person, target):
    _wmn(respx_mock, _site("Alpha", uri_pretty="https://alpha.test/@{account}"))
    respx_mock.get("https://alpha.test/u/jdoe").respond(200, text="ok")
    f = (await WhatsMyNameCollector().collect_person(person, target)).findings[0]
    assert f.source_url == "https://alpha.test/@jdoe"


async def test_at_most_five_concurrent_requests(respx_mock, person, target):
    _wmn(respx_mock, *[_site(f"S{i}") for i in range(20)])
    state = {"now": 0, "max": 0}

    async def handler(request):
        state["now"] += 1
        state["max"] = max(state["max"], state["now"])
        await asyncio.sleep(0.01)
        state["now"] -= 1
        return httpx.Response(404)

    respx_mock.get(url__regex=r"https://s\d+\.test/.*").mock(side_effect=handler)
    await WhatsMyNameCollector().collect_person(person, target)
    assert 1 < state["max"] <= 5


async def test_response_body_is_capped(respx_mock, person, target):
    _wmn(respx_mock, _site("Big", m_string="late-marker"))
    big = "x" * (300 * 1024) + "late-marker"             # marker beyond the 256 KB read limit
    respx_mock.get("https://big.test/u/jdoe").respond(200, text=big)
    assert len((await WhatsMyNameCollector().collect_person(person, target)).findings) == 1


# ── the platform list ────────────────────────────────────────────────────────


async def test_list_is_downloaded_once_for_all_persons(respx_mock, target):
    route = _wmn(respx_mock, _site("Alpha"))
    respx_mock.get("https://alpha.test/u/jdoe").respond(404)
    respx_mock.get("https://alpha.test/u/ann").respond(404)
    c = WhatsMyNameCollector()
    for login in ("jdoe", "ann", "jdoe"):
        await c.collect_person(OsintPerson(full_name="A B", github_login=login), target)
    assert route.call_count == 1


@pytest.mark.parametrize("effect, message", [
    (httpx.Response(500), "WhatsMyName list HTTP 500"),
    (httpx.Response(200, text="<html>not json"), "not valid JSON"),
    (httpx.ConnectError("down"), "WhatsMyName list unreachable: ConnectError"),
])
async def test_list_failure_raises_and_is_not_retried_per_person(respx_mock, person, target,
                                                                 effect, message):
    route = respx_mock.get(WMN_URL)
    route.mock(return_value=effect) if isinstance(effect, httpx.Response) else route.mock(side_effect=effect)
    c = WhatsMyNameCollector()
    for _ in range(2):
        with pytest.raises(RuntimeError, match=message):
            await c.collect_person(person, target)
    assert route.call_count == 1                                # failure cached, no hammering


def test_metadata_and_registration(monkeypatch):
    monkeypatch.undo()
    c = WhatsMyNameCollector()
    assert (c.name, c.tier, c.requires_api_key, c.request_delay) == ("WhatsMyName", 1, False, 0.3)
    assert c.skip_without_pivot is True and c.is_available() is True
    assert [p.name for p in PERSON_COLLECTORS][-2:] == ["GitLeak", "WhatsMyName"]


# ── progressive output ───────────────────────────────────────────────────────


async def test_header_is_reported_before_any_site_is_requested(respx_mock, person, target):
    _wmn(respx_mock, _site("Alpha"), _site("Beta"))
    events = []

    def on_site_request(request):
        events.append("request")
        return httpx.Response(404)

    respx_mock.get(url__regex=r"https://(alpha|beta)\.test/.*").mock(side_effect=on_site_request)
    c = WhatsMyNameCollector()
    c.on_progress = lambda message, finding=None: events.append(("progress", message, finding))
    await c.collect_person(person, target)

    assert events[0] == ("progress",
        "[WhatsMyName] Checking jdoe across 2 platforms — this may take a while...", None)
    assert events[1:] == ["request", "request"]


async def test_each_profile_is_reported_the_moment_it_is_confirmed(respx_mock, person, target):
    """A fast hit is reported while a slow site is still being checked."""
    _wmn(respx_mock, _site("Slow"), _site("Fast"))
    log = []

    async def slow(request):
        await asyncio.sleep(0.2)
        log.append("slow site answered")
        return httpx.Response(200, text="ok")

    respx_mock.get("https://slow.test/u/jdoe").mock(side_effect=slow)
    respx_mock.get("https://fast.test/u/jdoe").respond(200, text="ok")
    c = WhatsMyNameCollector()
    c.on_progress = lambda message, finding=None: log.append(
        f"reported {finding.raw_data['site']}" if finding else "header")
    result = await c.collect_person(person, target)

    assert log == ["header", "reported Fast", "slow site answered", "reported Slow"]
    # the CollectorResult keeps the list's order, whatever the arrival order
    assert [f.raw_data["site"] for f in result.findings] == ["Slow", "Fast"]


async def test_streamed_findings_are_the_ones_returned(respx_mock, person, target):
    _wmn(respx_mock, _site("Alpha"))
    respx_mock.get("https://alpha.test/u/jdoe").respond(200, text="ok")
    seen = []
    c = WhatsMyNameCollector()
    c.on_progress = lambda message, finding=None: finding and seen.append(finding)
    result = await c.collect_person(person, target)
    assert seen == result.findings and seen[0] is result.findings[0]     # same objects (no dupes)


async def test_failing_progress_callback_does_not_break_the_collector(respx_mock, person, target):
    _wmn(respx_mock, _site("Alpha"))
    respx_mock.get("https://alpha.test/u/jdoe").respond(200, text="ok")
    c = WhatsMyNameCollector()

    def boom(message, finding=None):
        raise ValueError("display bug")

    c.on_progress = boom
    assert len((await c.collect_person(person, target)).findings) == 1


async def test_concurrency_limit_is_still_five():
    from core.collectors import whatsmyname
    assert whatsmyname._CONCURRENCY == 5


async def test_no_callback_no_output(respx_mock, person, target):
    _wmn(respx_mock, _site("Alpha"))
    respx_mock.get("https://alpha.test/u/jdoe").respond(200, text="ok")
    c = WhatsMyNameCollector()
    assert c.on_progress is None
    assert len((await c.collect_person(person, target)).findings) == 1
