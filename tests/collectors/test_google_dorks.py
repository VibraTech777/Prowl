import httpx
import pytest

from core.collectors import ALL_COLLECTORS
from core.collectors.base import CollectorSkipped
from core.collectors.google_dorks import DORKS, GoogleDorksCollector
from core.models import Category, OsintTarget, Severity

KEY = "serp-secret-key-123"
API = r"https://serpapi\.com/search\.json.*"


@pytest.fixture(autouse=True)
def setup(monkeypatch):
    monkeypatch.setenv("SERPAPI_API_KEY", KEY)
    monkeypatch.setattr(GoogleDorksCollector, "request_delay", 0)


@pytest.fixture
def target():
    return OsintTarget(company_name="Acme", domain="example.com")


def _r(link, title="A page", snippet="", position=1):
    return {"position": position, "title": title, "link": link, "snippet": snippet}


def _serp(respx_mock, by_dork=None, default=()):
    """Fake SerpAPI. `by_dork` maps a Dork.key to its results; returns the queries received."""
    by_dork = by_dork or {}
    queries: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        params = dict(request.url.params)
        queries.append(params)
        for dork in DORKS:
            if params["q"] == dork.query.format(d="example.com"):
                results = by_dork.get(dork.key, default)
                if not results:
                    return httpx.Response(200, json={"error": "Google hasn't returned any results for this query."})
                return httpx.Response(200, json={"search_metadata": {"status": "Success"}, "organic_results": list(results)})
        return httpx.Response(400, json={"error": "unexpected query"})

    respx_mock.get(url__regex=API).mock(side_effect=handler)
    return queries


async def _run(target):
    return (await GoogleDorksCollector().collect(target)).findings


# ── metadata, availability, queries ──────────────────────────────────────────


def test_metadata_registration_and_availability(monkeypatch):
    c = GoogleDorksCollector()
    assert (c.name, c.tier, c.requires_api_key, c.api_key_env) == ("Google Dorks", 1, True, "SERPAPI_API_KEY")
    assert c.is_available() is True
    monkeypatch.delenv("SERPAPI_API_KEY")
    assert c.is_available() is False
    assert [x.name for x in ALL_COLLECTORS].index("Google Dorks") == 4        # right after DNSDumpster


async def test_one_request_per_dork_with_the_expected_parameters(respx_mock, target):
    queries = _serp(respx_mock)
    await _run(target)

    assert [q["q"] for q in queries] == [d.query.format(d="example.com") for d in DORKS]
    assert len(DORKS) == 10                                  # ≤ 10 searches per scan (250 free / month)
    for q in queries:
        assert (q["engine"], q["num"], q["api_key"]) == ("google", "10", KEY)
        assert "site:" in q["q"] and "example.com" in q["q"]
    texts = " ".join(q["q"] for q in queries)
    for operator in ("filetype:", "inurl:", "intitle:", "intext:", "site:*."):
        assert operator in texts


async def test_invalid_domain_is_skipped_without_any_request(respx_mock):
    route = respx_mock.get(url__regex=API)
    for bad in ('exa mple.com', 'example.com" OR 1=1', "ex@mple.com", ""):
        with pytest.raises(CollectorSkipped):
            await _run(OsintTarget(company_name="", domain=bad))
    assert route.call_count == 0


# ── results → findings ───────────────────────────────────────────────────────


async def test_documents_are_info_findings(respx_mock, target):
    _serp(respx_mock, {"documents": [
        _r("https://example.com/files/report.pdf", "Annual report", "Revenue…"),
        _r("https://example.com/files/page.html", "Not a document"),          # wrong extension
        _r("https://evilexample.com/x.pdf", "Lookalike host"),                 # not the target
        _r("https://other.org/example.com.pdf", "Another site"),
    ]})
    findings = await _run(target)

    (f,) = findings
    assert f.severity is Severity.INFO and f.category is Category.WEB_FINDING
    assert f.title == "Indexed document: /files/report.pdf"
    assert f.affected_asset == f.source_url == "https://example.com/files/report.pdf"
    assert f.source == "Google Dorks" and f.mitre_attack == "T1593.002"
    assert "Annual report — Revenue…" in f.description and "not verified" in f.description
    assert f.raw_data["dork"] == "documents" and "filetype:pdf" in f.raw_data["query"]
    assert KEY not in repr(f) and KEY not in f.description and KEY not in str(f.raw_data)


async def test_sensitive_files_are_medium_and_the_extension_is_checked(respx_mock, target):
    _serp(respx_mock, {"sensitive_files": [
        _r("https://example.com/backup/db.sql"), _r("https://example.com/.env"),
        _r("https://example.com/app.log?x=1"), _r("https://example.com/config.html"),   # dropped
    ]})
    findings = await _run(target)
    assert [(f.severity, f.category, f.title) for f in findings] == [
        (Severity.MEDIUM, Category.CODE_LEAK, "Indexed sensitive file: /backup/db.sql"),
        (Severity.MEDIUM, Category.CODE_LEAK, "Indexed sensitive file: /.env"),
        (Severity.MEDIUM, Category.CODE_LEAK, "Indexed sensitive file: /app.log"),
    ]


async def test_directory_listing_needs_index_of_in_the_title(respx_mock, target):
    _serp(respx_mock, {"directory_listing": [
        _r("https://example.com/files/", "Index of /files"), _r("https://example.com/blog", "A blog")]})
    (f,) = await _run(target)
    assert f.severity is Severity.MEDIUM and f.title == "Indexed directory listing: /files/"


async def test_admin_and_login_pages_are_info_unless_the_path_is_an_admin_one(respx_mock, target):
    _serp(respx_mock, {"admin_login": [
        _r("https://example.com/login"), _r("https://example.com/admin/users"),
        _r("https://www.example.com/blog/administrating-the-administrator")],
        "debug_backup": [_r("https://example.com/staging/home")]})
    sev = {f.title.split(": ", 1)[1]: f.severity for f in await _run(target)}
    assert sev == {"/login": Severity.INFO, "/admin/users": Severity.MEDIUM,
                   "www.example.com/blog/administrating-the-administrator": Severity.INFO,
                   "/staging/home": Severity.INFO}


async def test_error_messages_are_medium_and_api_docs_info(respx_mock, target):
    _serp(respx_mock, {"errors": [_r("https://example.com/p?id=1", "Fatal error", "Fatal error: Uncaught…")],
                       "api_docs": [_r("https://api.example.com/swagger/index.html")]})
    got = {f.raw_data["dork"]: f.severity for f in await _run(target)}
    assert got == {"errors": Severity.MEDIUM, "api_docs": Severity.INFO}


async def test_subdomains_are_reported_once_and_only_in_scope(respx_mock, target):
    _serp(respx_mock, {"subdomains": [
        _r("https://shop.example.com/cart"), _r("https://shop.example.com/about"),   # same host
        _r("https://www.example.com/"), _r("https://example.com/"),                 # not new
        _r("https://a.b.example.com/x"), _r("https://notexample.com/")]})
    findings = await _run(target)
    assert [(f.category, f.title, f.affected_asset) for f in findings] == [
        (Category.SUBDOMAIN, "Subdomain discovered (Google): shop.example.com", "shop.example.com"),
        (Category.SUBDOMAIN, "Subdomain discovered (Google): a.b.example.com", "a.b.example.com")]


async def test_third_party_mentions_must_name_the_domain(respx_mock, target):
    _serp(respx_mock, {
        "pastebin": [_r("https://pastebin.com/abc", "Dump", "admin@example.com password: hunter2"),
                     _r("https://pastebin.com/def", "Notes", "contact us at example.com"),
                     _r("https://pastebin.com/ghi", "Unrelated", "password: x but nothing about the target")]})
    got = {f.source_url: f.severity for f in await _run(target)}
    assert got == {"https://pastebin.com/abc": Severity.MEDIUM, "https://pastebin.com/def": Severity.INFO}
    assert all(f.category is Category.CODE_LEAK for f in await _run(target))        # no ghi: no mention


@pytest.mark.parametrize("snippet, path, severity", [
    # a credential SET next to the domain → MEDIUM
    ("DB_HOST=db.example.com TOKEN=abc", "/x/y/blob/main/app.py", Severity.MEDIUM),
    ('{"host": "example.com", "api_key": "k-123"}', "/x/y/blob/main/a.json", Severity.MEDIUM),
    ("-----BEGIN RSA PRIVATE KEY----- … example.com", "/x/y/blob/main/k.txt", Severity.MEDIUM),
    # the dork asks for these words, so the words alone must not raise the severity (they used to)
    ("Reset your password at example.com", "/x/y/issues/1", Severity.INFO),
    # a credential READ from somewhere, not a leaked value
    ("example.com: $password = $myCredential.GetNetworkCredential().Password", "/x/y/a.ps1", Severity.INFO),
    ("example.com token = os.getenv('API_TOKEN')", "/x/y/a.py", Severity.INFO),
    ("example.com password: ${DB_PASSWORD}", "/x/y/a.yml", Severity.INFO),
    ("example.com PASSWORD = process.env.PASSWORD", "/x/y/a.js", Severity.INFO),
    ("example.com token refresh docs: the token expires", "/x/y/issues/2", Severity.INFO),
    ("password: hunter2 " + "." * 200 + " example.com", "/x/y/issues/3", Severity.INFO),   # far apart
    # a secrets / config file mentioning the domain → MEDIUM whatever the snippet says
    ("example.com", "/x/y/blob/main/.env", Severity.MEDIUM),
    ("example.com", "/x/y/blob/main/.env.production", Severity.MEDIUM),
    ("example.com", "/x/y/blob/main/wp-config.php", Severity.MEDIUM),
    ("example.com", "/x/y/blob/main/README.md", Severity.INFO),
])
async def test_github_mentions_are_medium_only_for_a_credential_or_a_secrets_file(
        respx_mock, target, snippet, path, severity):
    _serp(respx_mock, {"github": [_r(f"https://github.com{path}", "a result", snippet)]})
    (f,) = await _run(target)
    assert f.severity is severity, (snippet, path)


async def test_a_url_found_by_two_dorks_is_reported_once(respx_mock, target):
    page = _r("https://example.com/admin/login", "Admin login")
    _serp(respx_mock, {"admin_login": [page], "debug_backup": [page], "errors": [page]})
    assert len(await _run(target)) == 1


async def test_no_results_is_not_an_error(respx_mock, target):
    _serp(respx_mock)                                            # "hasn't returned any results"
    assert await _run(target) == []

    for wording in ("Google hasn't returned any results for this query.", "No results found.",
                    "Google returned no results"):
        respx_mock.get(url__regex=API).mock(return_value=httpx.Response(200, json={"error": wording}))
        assert await _run(target) == []                          # even on the very first query


# ── failures ─────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("response, message", [
    (httpx.Response(401, json={"error": "Invalid API key. Your API key should be here: …"}), "rejected the API key"),
    (httpx.Response(200, json={"error": "Invalid API key"}), "rejected the API key"),
    (httpx.Response(429, json={"error": "Your account has run out of searches."}), "quota exhausted"),
    (httpx.Response(500, text="boom"), "SerpAPI error 500"),
])
async def test_a_first_query_failure_is_a_collector_failure(respx_mock, target, response, message):
    respx_mock.get(url__regex=API).mock(return_value=response)
    with pytest.raises(RuntimeError, match=message) as exc:
        await _run(target)
    assert KEY not in str(exc.value)


async def test_network_error_does_not_leak_the_key(respx_mock, target):
    respx_mock.get(url__regex=API).mock(side_effect=httpx.ConnectError(f"cannot reach serpapi?api_key={KEY}"))
    with pytest.raises(RuntimeError, match="SerpAPI unreachable: ConnectError") as exc:
        await _run(target)
    assert KEY not in str(exc.value) and KEY not in repr(exc.value)


async def test_quota_running_out_midway_keeps_the_partial_results_and_says_so(respx_mock, target):
    calls = []
    answers = [[_r("https://example.com/d1.pdf")], [_r("https://example.com/d2.sql")]]

    def handler(request):
        calls.append(request.url.params["q"])
        if len(calls) <= 2:
            return httpx.Response(200, json={"organic_results": answers[len(calls) - 1]})
        return httpx.Response(429, json={"error": "Your account has run out of searches."})

    respx_mock.get(url__regex=API).mock(side_effect=handler)
    findings = await _run(target)

    assert len(calls) == 3                                        # stopped at the failing query
    assert [f.title for f in findings] == [
        "Indexed document: /d1.pdf", "Indexed sensitive file: /d2.sql",
        f"Google dorks incomplete: 2/{len(DORKS)} queries run"]    # partial results are kept
    last = findings[-1]
    assert last.severity is Severity.INFO and "quota exhausted" in last.description
    assert KEY not in last.description and KEY not in str(last.raw_data)


# ── progressive display ──────────────────────────────────────────────────────


async def test_start_message_and_findings_are_streamed(respx_mock, target):
    _serp(respx_mock, {"documents": [_r("https://example.com/a.pdf")]})
    c = GoogleDorksCollector()
    events = []
    c.on_progress = lambda message, finding=None: events.append(finding or message)
    result = await c.collect(target)
    assert events[0] == f"[Google Dorks] Starting scan — {len(DORKS)} queries via SerpAPI (this may take a while...)"
    assert [e for e in events[1:]] == result.findings and events[1] is result.findings[0]
