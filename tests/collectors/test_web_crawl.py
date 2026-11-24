import httpx
import pytest

from core.collectors import web_crawl
from core.collectors.web_crawl import WebCrawlCollector
from core.models import Category, OsintTarget, Severity

HOME = """<html><head><title>Home</title>
<meta name="generator" content="TestCMS 1.0"></head><body>
<a href="/about">About</a> <a href="/admin">Admin</a> <a href="/login">Login</a>
<a href="https://other.org/x">External</a>
Contact: contact@example.com, someone@other.org
</body></html>"""

LOGIN = """<html><head><title>Login</title></head><body>
<form action="/session" method="post">
<input name="user"><input name="pw" type="password"></form></body></html>"""

ABOUT = "<html><head><title>About</title></head><body>about</body></html>"


@pytest.fixture(autouse=True)
def no_delay(monkeypatch):
    monkeypatch.setattr(web_crawl, "_REQUEST_DELAY", 0)


@pytest.fixture
def site(respx_mock):
    """A fake site. Returns the list of requested paths."""
    requested: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        requested.append(path)
        html = {"content-type": "text/html", "server": "nginx"}
        if path == "/":
            return httpx.Response(200, text=HOME, headers=html)
        if path == "/about":
            return httpx.Response(200, text=ABOUT, headers=html)
        if path == "/login":
            return httpx.Response(200, text=LOGIN, headers=html)
        if path == "/admin":
            return httpx.Response(404, text="nope", headers=html)   # soft 404
        if path == "/.env":
            return httpx.Response(200, text="SECRET=1",
                                  headers={"content-type": "text/plain"})
        return httpx.Response(404, text="nf", headers=html)

    respx_mock.route().mock(side_effect=handler)
    return requested


def _target(depth: int) -> OsintTarget:
    return OsintTarget(company_name="", domain="example.com", crawl=True, crawl_depth=depth)


def test_collector_flags():
    c = WebCrawlCollector()
    assert c.requires_crawl is True
    assert c.french_only is False


async def test_depth_one_findings(site):
    findings = (await WebCrawlCollector().collect(_target(1))).findings
    titles = [f.title for f in findings]

    # exposed .env found via probe → CRITICAL
    env = next(f for f in findings if "/.env" in f.title)
    assert env.severity is Severity.CRITICAL
    assert env.category is Category.WEB_FINDING

    # login page: sensitive path + login form
    assert any(t == "Sensitive path accessible: /login" for t in titles)
    assert any(t == "Login form discovered: /login" for t in titles)

    # 404 /admin is NOT reported as a sensitive path
    assert not any("/admin" in t for t in titles)

    # only in-scope emails
    emails = [f.affected_asset for f in findings if f.category is Category.EMAIL]
    assert emails == ["contact@example.com"]

    # tech findings are deduplicated per distinct fingerprint, not per page:
    # the homepage (nginx + generator meta) differs from the plain nginx pages
    tech = [f for f in findings if f.category is Category.TECH_EXPOSURE]
    assert len(tech) == 2
    by_fp = {f.raw_data["fingerprint"]: f for f in tech}
    assert set(by_fp) == {"server: nginx", "meta generator: TestCMS 1.0 | server: nginx"}
    assert "Observed on 1 page(s)" in by_fp["meta generator: TestCMS 1.0 | server: nginx"].description
    assert "Observed on 3 page(s)" in by_fp["server: nginx"].description

    # out-of-scope link never requested
    assert "/x" not in site


async def test_depth_zero_does_not_follow_links(site):
    await WebCrawlCollector().collect(_target(0))
    assert "/about" not in site and "/login" not in site
    # seed + probe paths only
    for probe in ("/.git/HEAD", "/.env", "/.htpasswd", "/robots.txt", "/sitemap.xml"):
        assert probe in site


async def test_unreachable_seed_raises(respx_mock):
    respx_mock.route().mock(side_effect=httpx.ConnectError("down"))
    with pytest.raises(RuntimeError, match="seed URL unreachable"):
        await WebCrawlCollector().collect(_target(1))


async def test_redirect_final_url_is_recorded(respx_mock):
    respx_mock.get("https://example.com/").respond(
        301, headers={"location": "https://www.example.com/"})
    respx_mock.get("https://www.example.com/").respond(
        200, text=ABOUT, headers={"content-type": "text/html"})
    respx_mock.route().respond(404, text="nf", headers={"content-type": "text/html"})

    collector = WebCrawlCollector()
    async with httpx.AsyncClient(follow_redirects=True) as client:
        page = await collector._fetch_page(client, "https://example.com/", 0)
    assert page.url == "https://www.example.com/"
    assert page.title == "About"


def test_in_scope():
    f = WebCrawlCollector._in_scope
    assert f("https://example.com/a", "example.com")
    assert f("https://sub.example.com:8443/a", "example.com")
    assert not f("https://example.com.evil.org/", "example.com")
    assert not f("https://notexample.com/", "example.com")


@pytest.mark.parametrize("status", [401, 403, 404, 429, 500, 503])
async def test_seed_http_error_raises_instead_of_reporting_zero_findings(respx_mock, status):
    """A WAF answering 403/503 for the home page used to look like a successful empty crawl."""
    respx_mock.route().respond(status, text="blocked", headers={"content-type": "text/html"})
    with pytest.raises(RuntimeError, match=f"seed https://example.com answered HTTP {status}"):
        await WebCrawlCollector().collect(_target(1))


async def test_seed_error_message_names_the_server(respx_mock):
    respx_mock.route().respond(403, text="Attention Required",
                               headers={"content-type": "text/html", "server": "cloudflare"})
    with pytest.raises(RuntimeError, match=r"HTTP 403 \(Server: cloudflare\) — blocked or down"):
        await WebCrawlCollector().collect(_target(0))


async def test_seed_redirected_then_blocked_is_also_an_error(respx_mock):
    respx_mock.get("https://example.com/robots.txt").respond(404)
    respx_mock.get("https://example.com/").respond(
        301, headers={"location": "https://www.example.com/"})
    respx_mock.get("https://www.example.com/").respond(403, text="no", headers={"content-type": "text/html"})
    with pytest.raises(RuntimeError, match="HTTP 403"):
        await WebCrawlCollector().collect(_target(1))


async def test_healthy_site_with_nothing_found_is_still_a_success(respx_mock):
    html = {"content-type": "text/html"}
    respx_mock.route().mock(side_effect=lambda r: httpx.Response(
        200, text="<html><title>Quiet</title></html>", headers=html)
        if r.url.path == "/" else httpx.Response(404, text="nf", headers=html))
    result = await WebCrawlCollector().collect(_target(1))
    assert result.findings == []                      # 0 findings, but it really ran


# ── robots.txt ───────────────────────────────────────────────────────────────

from core.collectors.base import CollectorSkipped  # noqa: E402


def _robots_site(respx_mock, robots, *, robots_status=200):
    """The fake site of the `site` fixture, plus a configurable robots.txt."""
    requested: list[str] = []
    html = {"content-type": "text/html", "server": "nginx"}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        requested.append(path)
        if path == "/robots.txt":
            return httpx.Response(robots_status, text=robots, headers={"content-type": "text/plain"})
        pages = {"/": HOME, "/about": ABOUT, "/login": LOGIN}
        if path in pages:
            return httpx.Response(200, text=pages[path], headers=html)
        if path == "/.env":
            return httpx.Response(200, text="SECRET=1", headers={"content-type": "text/plain"})
        return httpx.Response(404, text="nf", headers=html)

    respx_mock.route().mock(side_effect=handler)
    return requested


async def test_disallowed_urls_are_never_requested(respx_mock):
    requested = _robots_site(respx_mock, "User-agent: *\nDisallow: /login\nDisallow: /.env\n")
    result = await WebCrawlCollector().collect(_target(1))

    assert "/about" in requested                          # allowed pages are still crawled
    assert "/login" not in requested                      # linked, but disallowed
    assert "/.env" not in requested                       # sensitive probe, disallowed
    assert not any("Login form" in f.title for f in result.findings)
    assert not any(f.title.startswith("Sensitive path accessible") for f in result.findings)
    # ...but the rules themselves are reported (information only, nothing was requested)
    robots_finding = next(f for f in result.findings if f.title.startswith("robots.txt discloses"))
    assert robots_finding.severity is Severity.MEDIUM
    assert robots_finding.raw_data["disallow"] == ["/login", "/.env"]


async def test_rules_for_our_own_user_agent_apply(respx_mock):
    requested = _robots_site(
        respx_mock, "User-agent: Googlebot\nDisallow: /\n\nUser-agent: Prowl\nDisallow: /about\n")
    await WebCrawlCollector().collect(_target(1))
    assert "/about" not in requested and "/login" in requested   # only Prowl's group matters


async def test_whole_site_disallowed_is_reported_as_skipped(respx_mock):
    requested = _robots_site(respx_mock, "User-agent: *\nDisallow: /\n")
    with pytest.raises(CollectorSkipped, match="robots.txt disallows crawling this site"):
        await WebCrawlCollector().collect(_target(1))
    assert requested == ["/robots.txt"]                   # not even the home page


@pytest.mark.parametrize("status", [404, 403, 401, 410])
async def test_missing_robots_txt_means_everything_is_allowed(respx_mock, status):
    requested = _robots_site(respx_mock, "", robots_status=status)
    await WebCrawlCollector().collect(_target(1))
    assert "/login" in requested and "/.env" in requested


@pytest.mark.parametrize("status", [500, 503])
async def test_server_error_on_robots_stops_the_crawl_visibly(respx_mock, status):
    requested = _robots_site(respx_mock, "oops", robots_status=status)
    with pytest.raises(RuntimeError, match=f"answered HTTP {status}.*robots.txt unavailable"):
        await WebCrawlCollector().collect(_target(1))
    assert requested == ["/robots.txt"]


async def test_garbage_robots_txt_allows_everything(respx_mock):
    requested = _robots_site(respx_mock, "<html><body>Not found</body></html>")
    await WebCrawlCollector().collect(_target(1))
    assert "/login" in requested


async def test_crawl_delay_is_honoured_but_capped(respx_mock, monkeypatch):
    sleeps: list[float] = []

    async def fake_sleep(seconds):
        sleeps.append(seconds)

    monkeypatch.setattr(web_crawl.asyncio, "sleep", fake_sleep)
    _robots_site(respx_mock, "User-agent: *\nCrawl-delay: 2\n")
    await WebCrawlCollector().collect(_target(1))
    assert sleeps and set(sleeps) == {2.0}

    sleeps.clear()
    _robots_site(respx_mock, "User-agent: *\nCrawl-delay: 3600\n")
    await WebCrawlCollector().collect(_target(0))
    assert set(sleeps) == {web_crawl._MAX_CRAWL_DELAY}    # one hour would stall the scan


async def test_skipped_urls_are_announced(respx_mock):
    _robots_site(respx_mock, "User-agent: *\nDisallow: /login\n")
    c = WebCrawlCollector()
    got = []
    c.on_progress = lambda message, finding=None: got.append(message)
    await c.collect(_target(1))
    assert any("robots.txt respected" in m and "not crawled" in m for m in got if m)


async def test_robots_txt_is_fetched_before_anything_else(respx_mock):
    requested = _robots_site(respx_mock, "")
    await WebCrawlCollector().collect(_target(0))
    assert requested[0] == "/robots.txt"


async def test_unreachable_site_is_reported_as_unreachable_seed(respx_mock):
    respx_mock.route().mock(side_effect=httpx.ConnectError("down"))
    with pytest.raises(RuntimeError, match=r"seed URL unreachable: https://example.com \(robots.txt: ConnectError\)"):
        await WebCrawlCollector().collect(_target(1))


# ── robots.txt is downloaded once ────────────────────────────────────────────


def _count(requested, path="/robots.txt"):
    return requested.count(path)


@pytest.mark.parametrize("status", [200, 404, 403])
async def test_robots_txt_is_requested_exactly_once(respx_mock, status):
    requested = _robots_site(respx_mock, "User-agent: *\nDisallow: /login\n", robots_status=status)
    await WebCrawlCollector().collect(_target(1))
    assert _count(requested) == 1                         # rules + probe share one request
    assert "/.env" in requested and "/sitemap.xml" in requested     # other probes still sent


async def test_robots_txt_is_requested_once_without_any_rule(respx_mock, site):
    await WebCrawlCollector().collect(_target(1))
    assert _count(site) == 1


async def test_the_reused_robots_response_is_still_analysed_for_findings(respx_mock):
    body = "User-agent: *\nDisallow: /private\n# security contact: sec@example.com\n"
    requested = _robots_site(respx_mock, body)
    result = await WebCrawlCollector().collect(_target(0))

    emails = [f for f in result.findings if f.title == "Email found in page source: sec@example.com"]
    assert len(emails) == 1                               # same finding as the old second request
    assert emails[0].source_url == "https://example.com/robots.txt"
    assert _count(requested) == 1


async def test_missing_robots_txt_adds_no_page_and_no_request(respx_mock):
    requested = _robots_site(respx_mock, "", robots_status=404)
    result = await WebCrawlCollector().collect(_target(0))
    assert _count(requested) == 1
    assert not any("robots.txt" in f.source_url for f in result.findings)


async def test_robots_txt_stays_readable_even_if_it_lists_itself(respx_mock):
    """The parser (like RFC 9309) never treats /robots.txt as disallowed: still one request."""
    body = "User-agent: *\nDisallow: /robots.txt\n# sec@example.com\n"
    requested = _robots_site(respx_mock, body)
    result = await WebCrawlCollector().collect(_target(0))
    assert _count(requested) == 1
    assert any(f.title == "Email found in page source: sec@example.com" for f in result.findings)


def test_analyze_parses_a_response_without_any_request():
    resp = httpx.Response(200, text="contact: a@example.com", headers={"content-type": "text/plain"},
                          request=httpx.Request("GET", "https://example.com/robots.txt"))
    page = WebCrawlCollector()._analyze(resp, "https://example.com/robots.txt", 0)
    assert (page.url, page.status_code, page.emails) == (
        "https://example.com/robots.txt", 200, ["a@example.com"])


# ── robots.txt content as a finding ──────────────────────────────────────────

from core.collectors.web_crawl import parse_robots_rules  # noqa: E402


def _robots_findings(result):
    return [f for f in result.findings if f.title.startswith("robots.txt discloses")]


def test_parse_robots_rules():
    text = """
# comment line
User-agent: *
Disallow: /admin/        # trailing comment
Disallow: /private
DISALLOW: /*.sql$
Disallow:
Disallow: /
Disallow: /private
Allow: /public

User-agent: BadBot
Disallow: /api/v2
Sitemap: https://example.com/sitemap.xml
sitemap: https://example.com/sitemap.xml
Sitemap: https://example.com/news.xml
"""
    disallowed, sitemaps = parse_robots_rules(text)
    assert disallowed == ["/admin/", "/private", "/*.sql$", "/api/v2"]   # deduped, "" and "/" ignored
    assert sitemaps == ["https://example.com/sitemap.xml", "https://example.com/news.xml"]
    assert parse_robots_rules("") == ([], []) and parse_robots_rules("<html>Not found</html>") == ([], [])


async def test_sensitive_disallow_makes_one_medium_finding(respx_mock):
    requested = _robots_site(respx_mock, (
        "User-agent: *\nDisallow: /search\nDisallow: /admin/\nDisallow: /backup\n"
        "Disallow: /*.sql$\nSitemap: https://example.com/sitemap.xml\n"))
    result = await WebCrawlCollector().collect(_target(0))

    (f,) = _robots_findings(result)
    assert f.severity is Severity.MEDIUM and f.category is Category.WEB_FINDING
    assert f.title == "robots.txt discloses 4 disallowed paths — sensitive: /admin/, /backup, /*.sql$"
    assert "/search" in f.description and "Sitemaps: https://example.com/sitemap.xml" in f.description
    assert "never requests them" in f.description
    assert f.raw_data["disallow"] == ["/search", "/admin/", "/backup", "/*.sql$"]
    assert f.raw_data["sensitive"] == ["/admin/", "/backup", "/*.sql$"]
    assert f.source == "Web Crawler" and f.source_url == "https://example.com/robots.txt"
    assert f.mitre_attack == "T1594" and f.affected_asset == "example.com"
    # reporting is not requesting: no disallowed path is ever fetched, robots.txt only once
    assert not {"/admin/", "/admin", "/backup"} & set(requested) and requested.count("/robots.txt") == 1


async def test_benign_disallow_is_info(respx_mock):
    _robots_site(respx_mock, "User-agent: *\nDisallow: /search\nDisallow: /cart\nDisallow: /tmp/\n")
    (f,) = _robots_findings(await WebCrawlCollector().collect(_target(0)))
    assert f.severity is Severity.INFO
    assert f.title == "robots.txt discloses 3 disallowed paths" and f.raw_data["sensitive"] == []


async def test_single_rule_wording(respx_mock):
    _robots_site(respx_mock, "User-agent: *\nDisallow: /staging\n")       # /staging scores 40: INFO
    (f,) = _robots_findings(await WebCrawlCollector().collect(_target(0)))
    assert f.title == "robots.txt discloses 1 disallowed path" and f.severity is Severity.INFO


@pytest.mark.parametrize("robots, status", [
    ("User-agent: *\nDisallow:\n", 200),                   # empty Disallow = allow everything
    ("User-agent: *\nAllow: /\nSitemap: https://example.com/s.xml\n", 200),
    ("<html><body>Page not found</body></html>", 200),       # soft-404 served as robots.txt
    ("", 200),
    ("", 404),
])
async def test_no_disallow_rules_no_finding(respx_mock, robots, status):
    _robots_site(respx_mock, robots, robots_status=status)
    assert _robots_findings(await WebCrawlCollector().collect(_target(0))) == []


async def test_long_robots_is_capped_in_the_description_not_in_the_data(respx_mock):
    rules = "".join(f"Disallow: /dir{i}/\n" for i in range(60))
    _robots_site(respx_mock, "User-agent: *\n" + rules)
    (f,) = _robots_findings(await WebCrawlCollector().collect(_target(0)))
    assert f.title == "robots.txt discloses 60 disallowed paths"
    assert "/dir24/" in f.description and "/dir25/" not in f.description    # 25 spelled out
    assert "… and 35 more." in f.description
    assert len(f.raw_data["disallow"]) == 60


async def test_robots_finding_is_streamed_and_returned_once(respx_mock):
    _robots_site(respx_mock, "User-agent: *\nDisallow: /admin\n")
    c = WebCrawlCollector()
    streamed = []
    c.on_progress = lambda message, finding=None: streamed.append(finding) if finding else None
    result = await c.collect(_target(0))
    (f,) = _robots_findings(result)
    assert any(s is f for s in streamed)
