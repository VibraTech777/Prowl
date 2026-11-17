"""Progressive display: slow collectors report while they work (timing only, same findings)."""

import re

import httpx
import pytest

from core.collectors import crtsh, web_crawl
from core.collectors.crtsh import CrtshCollector
from core.collectors.dnsdumpster import DnsDumpsterCollector
from core.collectors.email_format import EmailFormatCollector
from core.collectors.github_gitleak import GitLeakCollector
from core.collectors.github_org import GitHubOrgCollector
from core.collectors.github_person import GitHubPersonCollector
from core.collectors.opencorporates import OpenCorporatesCollector
from core.collectors.web_crawl import WebCrawlCollector
from core.models import Finding, OsintPerson, OsintTarget, Severity


@pytest.fixture(autouse=True)
def fast(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.setenv("OPENCORPORATES_API_TOKEN", "tok")
    monkeypatch.setattr(crtsh, "_RETRY_DELAY", 0)
    monkeypatch.setattr(web_crawl, "_REQUEST_DELAY", 0)
    for cls in (GitHubOrgCollector, OpenCorporatesCollector, GitLeakCollector,
                DnsDumpsterCollector, EmailFormatCollector):
        monkeypatch.setattr(cls, "request_delay", 0)


def _record(collector):
    """Attach a recorder: events are message strings or Finding objects, in arrival order."""
    events: list = []
    collector.on_progress = lambda message, finding=None: events.append(finding or message)
    return events


def _messages(events):
    return [e for e in events if isinstance(e, str)]


def _findings(events):
    return [e for e in events if isinstance(e, Finding)]


def _same_objects(events, result):
    streamed = _findings(events)
    assert len(streamed) == len(result.findings)
    assert {id(f) for f in streamed} == {id(f) for f in result.findings}      # no copies, no dupes


@pytest.fixture
def target():
    return OsintTarget(company_name="Zed Industries", domain="zed.dev")


# ── crt.sh ───────────────────────────────────────────────────────────────────


async def test_crtsh_streams_every_subdomain_after_the_start_message(respx_mock, target):
    respx_mock.get(url__regex=r"https://crt\.sh/.*").respond(json=[
        {"name_value": "a.zed.dev\ndev.zed.dev\nb.zed.dev"}])
    c = CrtshCollector()
    events = _record(c)
    result = await c.collect(target)

    assert events[0] == "[crt.sh] Starting scan — this may take a while..."
    assert [f.affected_asset for f in _findings(events)] == ["a.zed.dev", "dev.zed.dev", "b.zed.dev"]
    _same_objects(events, result)
    assert [f.severity for f in result.findings] == [Severity.INFO, Severity.MEDIUM, Severity.INFO]


async def test_crtsh_reports_each_failed_attempt_before_retrying(respx_mock, target):
    route = respx_mock.get(url__regex=r"https://crt\.sh/.*")
    route.side_effect = [httpx.Response(502), httpx.Response(200, json=[{"name_value": "a.zed.dev"}])]
    c = CrtshCollector()
    events = _record(c)
    result = await c.collect(target)

    msgs = _messages(events)
    assert msgs[0].startswith("[crt.sh] Starting scan")
    assert msgs[1].startswith("[crt.sh] Attempt 1/2 failed (HTTPStatusError) — retrying in")
    assert len(result.findings) == 1 and len(_findings(events)) == 1


async def test_crtsh_failure_still_raises_and_streams_nothing(respx_mock, target):
    respx_mock.get(url__regex=r"https://crt\.sh/.*").respond(502)
    c = CrtshCollector()
    events = _record(c)
    with pytest.raises(RuntimeError, match="unreachable after 2 attempts"):
        await c.collect(target)
    assert _findings(events) == []


# ── DNSDumpster ──────────────────────────────────────────────────────────────


async def test_dnsdumpster_streams_subdomains_and_the_summary(respx_mock, target):
    respx_mock.get(url__regex=r"https://api\.hackertarget\.com/.*").respond(
        text="".join(f"h{i}.zed.dev,1.1.1.{i}\n" for i in range(6)))
    c = DnsDumpsterCollector()
    events = _record(c)
    result = await c.collect(target)

    assert events[0] == "[DNSDumpster] Starting scan — this may take a while..."
    assert len(result.findings) == 7                                # 6 subdomains + summary
    _same_objects(events, result)
    assert _findings(events)[-1].title.startswith("DNSDumpster: 6 subdomains")


# ── OpenCorporates ───────────────────────────────────────────────────────────


async def test_opencorporates_streams_company_then_officers(respx_mock, target):
    def handler(request):
        if request.url.path.endswith("/search"):
            return httpx.Response(200, json={"results": {"companies": [{"company": {
                "name": "ZED INDUSTRIES", "company_number": "1", "jurisdiction_code": "us_de"}}]}})
        return httpx.Response(200, json={"results": {"officers": [
            {"officer": {"name": "ALICE A", "position": "director"}},
            {"officer": {"name": "BOB B", "position": "ceo"}}]}})

    respx_mock.route().mock(side_effect=handler)
    c = OpenCorporatesCollector()
    events = _record(c)
    result = await c.collect(target)

    assert events[0] == "[OpenCorporates] Starting scan — this may take a while..."
    assert [f.title for f in _findings(events)] == [
        "OpenCorporates: ZED INDUSTRIES (us_de)", "Officer: Alice A (director)", "Officer: Bob B (ceo)"]
    _same_objects(events, result)


# ── GitHub Org: members arrive one by one ────────────────────────────────────


def _github(respx_mock, members, order):
    def handler(request):
        path = request.url.path
        order.append(path)
        if path == "/orgs/zed":
            return httpx.Response(200, json={"login": "zed", "public_repos": 3, "blog": "https://zed.dev"})
        if path == "/orgs/zed/public_members":
            return httpx.Response(200, json=[{"login": m, "type": "User"} for m in members])
        if m := re.fullmatch(r"/users/([^/]+)", path):
            return httpx.Response(200, json={"login": m[1], "name": m[1].title()})
        return httpx.Response(404)

    respx_mock.route().mock(side_effect=handler)


async def test_github_org_streams_each_member_as_its_profile_is_fetched(respx_mock, target):
    order: list[str] = []
    _github(respx_mock, ["alice", "bob"], order)
    c = GitHubOrgCollector()
    arrival: list[str] = []
    c.on_progress = lambda message, finding=None: arrival.append(
        f"finding:{finding.title}" if finding else f"msg:{message}")
    # interleave HTTP calls and progress events to prove the order of arrival
    orig = c._member

    def spy(*a, **k):
        arrival.append(f"fetched:{a[2]}")
        return orig(*a, **k)

    c._member = spy
    result = await c.collect(target)

    assert arrival[0] == "msg:[GitHub Org] Starting scan — this may take a while..."
    assert arrival[1:5] == ["fetched:alice", "finding:GitHub org member: Alice (@alice)",
                            "fetched:bob", "finding:GitHub org member: Bob (@bob)"]
    assert arrival[5].startswith("finding:GitHub org: zed —")              # org needs the count
    assert result.findings[0].title.startswith("GitHub org: zed —")        # returned order unchanged
    assert [p.full_name for p in result.persons] == ["Alice", "Bob"]


async def test_github_org_unconfirmed_streams_only_the_org_finding(respx_mock, target):
    respx_mock.route().mock(side_effect=lambda r: httpx.Response(
        200, json={"login": "zed", "public_repos": 1, "blog": ""}) if r.url.path == "/orgs/zed"
        else httpx.Response(404))
    c = GitHubOrgCollector()
    events = _record(c)
    result = await c.collect(target)
    assert [f.title for f in _findings(events)] == [result.findings[0].title] and len(result.findings) == 1


# ── person collectors ────────────────────────────────────────────────────────


@pytest.fixture
def jane():
    return OsintPerson(full_name="Jane Doe", source="GitHub Org", github_login="jdoe")


async def test_github_person_streams_profile_stack_and_repos(respx_mock, jane, target, monkeypatch):
    def handler(request):
        path = request.url.path
        if path == "/users/jdoe/repos":
            return httpx.Response(200, json=[{"name": "prod-credentials", "language": "Go"}])
        if path == "/users/jdoe":
            return httpx.Response(200, json={"login": "jdoe", "html_url": "https://github.com/jdoe",
                                             "public_repos": 1, "followers": 2})
        return httpx.Response(404)

    respx_mock.route().mock(side_effect=handler)
    monkeypatch.setenv("GITHUB_TOKEN", "x")            # 1.5 s delay is only applied by the runner
    c = GitHubPersonCollector()
    events = _record(c)
    result = await c.collect_person(jane, target)

    assert events[0] == "[GitHub] Starting scan of Jane Doe — this may take a while..."
    assert [f.title.split(":")[0] for f in _findings(events)] == [
        "GitHub profile", "GitHub tech stack for jdoe", "Suspicious repo name on GitHub"]
    _same_objects(events, result)


async def test_email_format_announces_once_per_domain_and_streams_the_guess(respx_mock, target):
    page = ("<div class='format_score_container'><div class='format fl'>first_name . last_name</div>"
            "<div class='confidence_value fl'>80%</div></div>")
    route = respx_mock.get("https://www.email-format.com/d/zed.dev/").respond(text=page)
    c = EmailFormatCollector()
    events = _record(c)
    first = await c.collect_person(OsintPerson(full_name="Jane Doe"), target)
    second = await c.collect_person(OsintPerson(full_name="John Smith"), target)

    assert _messages(events) == ["[EmailFormat] Starting scan — this may take a while..."]  # once
    assert route.call_count == 1
    assert [f.affected_asset for f in _findings(events)] == ["jane.doe@zed.dev", "john.smith@zed.dev"]
    assert first.findings[0] is _findings(events)[0] and second.findings[0] is _findings(events)[1]


async def test_gitleak_streams_the_email_finding(respx_mock, jane, target):
    def handler(request):
        if request.url.path == "/users/jdoe/repos":
            return httpx.Response(200, json=[{"name": "r1"}])
        return httpx.Response(200, json=[{"html_url": "u", "commit": {"author": {"email": "jane@zed.dev"}}}])

    respx_mock.route().mock(side_effect=handler)
    c = GitLeakCollector()
    events = _record(c)
    result = await c.collect_person(jane, target)
    assert events[0] == "[GitLeak] Starting scan of Jane Doe — this may take a while..."
    _same_objects(events, result)
    assert _findings(events)[0].severity is Severity.MEDIUM


async def test_gitleak_without_login_stays_silent(respx_mock, target):
    c = GitLeakCollector()
    events = _record(c)
    await c.collect_person(OsintPerson(full_name="Jane Doe"), target)
    assert events == []                                       # nothing to wait for: no message


# ── web crawler ──────────────────────────────────────────────────────────────


async def test_web_crawler_announces_and_streams_its_findings(respx_mock):
    html = {"content-type": "text/html"}
    respx_mock.route().mock(side_effect=lambda r: httpx.Response(
        200, text="<html><title>t</title>Contact: hi@example.com</html>", headers=html)
        if r.url.path == "/" else httpx.Response(404, text="nf", headers=html))
    c = WebCrawlCollector()
    events = _record(c)
    result = await c.collect(OsintTarget(company_name="", domain="example.com",
                                         crawl=True, crawl_depth=0))
    assert events[0] == "[Web Crawler] Starting scan — this may take a while..."
    assert result.findings and _same_objects(events, result) is None


# ── no callback: nothing changes ─────────────────────────────────────────────


async def test_collectors_work_without_a_callback(respx_mock, target):
    respx_mock.get(url__regex=r"https://crt\.sh/.*").respond(json=[{"name_value": "a.zed.dev"}])
    c = CrtshCollector()
    assert c.on_progress is None
    assert len((await c.collect(target)).findings) == 1
