"""Discovery files (sitemap, security.txt, .well-known…): parsers, findings, and the crawler glue."""

import json

import httpx
import pytest

from core.collectors import web_crawl
from core.collectors.web_crawl import WebCrawlCollector
from core.crawler import discovery as d
from core.models import Category, OsintTarget, Severity

TARGET = OsintTarget(company_name="", domain="example.com", crawl=True, crawl_depth=0)

URLSET = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
<url><loc>https://example.com/</loc></url>
<url><loc>https://example.com/blog/a?x=1&amp;y=2</loc></url>
<url><loc> https://example.com/blog/b </loc></url>
<url><loc><![CDATA[https://shop.example.com/cart]]></loc></url>
</urlset>"""
INDEX = """<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
<sitemap><loc>https://example.com/s1.xml</loc></sitemap><sitemap><loc>https://example.com/s2.xml</loc></sitemap>
</sitemapindex>"""
SECURITY = "Contact: mailto:security@example.com\nContact: https://example.com/report\n" \
           "Expires: 2099-01-01T00:00:00Z\nPolicy: https://example.com/policy\nEncryption: https://example.com/pgp.txt\n"


def _finding(kind, text, path):
    parsed = d.PARSERS[kind](text)
    assert parsed is not None, (kind, text[:40])
    return d.build_finding(kind, parsed, f"https://example.com{path}", TARGET, "Web Crawler")


# ── parsers: a 200 is not proof, the content must be the right file ──────────


def test_spa_index_html_is_never_mistaken_for_a_discovery_file():
    spa = "<!doctype html><html><head><title>App</title></head><body><div id='root'></div></body></html>"
    for kind, parser in d.PARSERS.items():
        assert not parser(spa), kind                      # None, [] or "" — nothing to report
    assert d.PARSERS["humans"](spa) is None and d.PARSERS["sitemap"]("") is None


def test_sitemap_urlset_and_index():
    info = d.parse_sitemap(URLSET)
    assert not info.is_index and info.locs == [
        "https://example.com/", "https://example.com/blog/a?x=1&y=2",            # &amp; unescaped
        "https://example.com/blog/b", "https://shop.example.com/cart"]            # trimmed, CDATA
    idx = d.parse_sitemap(INDEX)
    assert idx.is_index and idx.locs == ["https://example.com/s1.xml", "https://example.com/s2.xml"]


def test_sitemap_findings():
    f = _finding("sitemap", URLSET, "/sitemap.xml")
    assert f.severity is Severity.INFO and f.category is Category.WEB_FINDING and f.mitre_attack == "T1594"
    assert f.title == "Sitemap /sitemap.xml: 4 URLs"
    assert "Top sections: /blog (2)" in f.description
    assert "Other hosts referenced: shop.example.com" in f.description        # a subdomain leak
    assert f.raw_data["total"] == 4
    www_only = _finding("sitemap", URLSET.replace("https://shop.example.com", "https://www.example.com"),
                        "/sitemap.xml")
    assert "Other hosts" not in www_only.description                          # www is not a leak

    idx = _finding("sitemap", INDEX, "/sitemap_index.xml")
    assert idx.title == "Sitemap index /sitemap_index.xml: 2 child sitemaps" and idx.severity is Severity.INFO

    sens = _finding("sitemap", URLSET.replace("/blog/b", "/admin/panel"), "/sitemap.xml")
    assert sens.severity is Severity.MEDIUM and sens.title.endswith("— sensitive: /admin/panel")
    assert sens.raw_data["sensitive"] == ["https://example.com/admin/panel"]
    benign = _finding("sitemap", URLSET.replace("/blog/b", "/login"), "/sitemap.xml")   # score 50 < 70
    assert benign.severity is Severity.INFO


def test_sitemap_is_capped():
    big = "<urlset>" + "".join(f"<url><loc>https://example.com/p{i}</loc></url>" for i in range(d._MAX_LOCS + 5)) + "</urlset>"
    info = d.parse_sitemap(big)
    assert len(info.locs) == d._MAX_LOCS and info.truncated
    f = d.build_finding("sitemap", info, "https://example.com/sitemap.xml", TARGET, "Web Crawler")
    assert f.title == f"Sitemap /sitemap.xml: {d._MAX_LOCS}+ URLs" and len(f.raw_data["urls"]) == d._RAW_URLS


def test_security_txt():
    f = _finding("security", SECURITY, "/.well-known/security.txt")
    assert f.severity is Severity.INFO
    assert f.title == "security.txt published — contact: mailto:security@example.com"
    assert "Policy: https://example.com/policy" in f.description and "Expires: 2099-01-01T00:00:00Z" in f.description

    stale = _finding("security", SECURITY.replace("2099-01-01", "2020-01-01"), "/.well-known/security.txt")
    assert stale.severity is Severity.LOW and stale.title.startswith("security.txt expired (2020-01-01")

    signed = "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n" + SECURITY + "-----BEGIN PGP SIGNATURE-----\n"
    assert d.parse_security_txt(signed)["contact"][0] == "mailto:security@example.com"
    assert d.parse_security_txt("Policy: https://example.com/p\n") is None      # Contact is mandatory
    assert d.parse_security_txt("Not found\nSorry: nothing here") is None


def test_openid_configuration():
    cfg = {"issuer": "https://auth.example.com", "authorization_endpoint": "https://auth.example.com/authorize",
           "token_endpoint": "https://auth.example.com/token", "jwks_uri": "https://auth.example.com/jwks",
           "grant_types_supported": ["authorization_code"], "scopes_supported": ["openid", "email"]}
    f = _finding("openid", json.dumps(cfg), "/.well-known/openid-configuration")
    assert f.severity is Severity.INFO and f.title == "OpenID Connect configuration exposed: https://auth.example.com"
    assert "token_endpoint https://auth.example.com/token" in f.description and "2 scopes" in f.description
    assert f.raw_data["endpoints"]["jwks_uri"] == "https://auth.example.com/jwks"

    reg = _finding("openid", json.dumps({**cfg, "registration_endpoint": "https://auth.example.com/register"}), "/x")
    pwd = _finding("openid", json.dumps({**cfg, "grant_types_supported": ["password"]}), "/x")
    assert reg.severity is pwd.severity is Severity.MEDIUM
    assert "dynamic client registration is advertised" in reg.description and "the password grant is enabled" in pwd.description
    assert d.parse_openid_config("[1, 2]") is None and d.parse_openid_config("{}") is None
    assert d.parse_openid_config("not json") is None


def test_app_link_files():
    links = [{"relation": ["delegate_permission/common.handle_all_urls"],
              "target": {"namespace": "android_app", "package_name": "com.example.app",
                         "sha256_cert_fingerprints": ["AA:BB", "CC:DD"]}}]
    f = _finding("assetlinks", json.dumps(links), "/.well-known/assetlinks.json")
    assert f.title == "Android app links (assetlinks.json): com.example.app" and "2 certificate fingerprint(s)" in f.description
    assert d.parse_assetlinks("[]") is None and d.parse_assetlinks('{"a": 1}') is None

    aasa = {"applinks": {"details": [{"appID": "ABCDE12345.com.example.app", "paths": ["*"]},
                                     {"appIDs": ["ABCDE12345.com.example.beta"]}]},
            "webcredentials": {"apps": ["ABCDE12345.com.example.app"]}}
    g = _finding("aasa", json.dumps(aasa), "/.well-known/apple-app-site-association")
    assert g.raw_data["app_ids"] == ["ABCDE12345.com.example.app", "ABCDE12345.com.example.beta"]
    assert g.title.startswith("Apple app-site-association: ABCDE12345.com.example.app")
    assert d.parse_aasa('{"foo": 1}') is None
    assert d.build_finding("aasa", d.parse_aasa('{"applinks": {}}'), "https://example.com/x", TARGET, "s") is None


def test_humans_txt():
    f = _finding("humans", "/* TEAM */\nChef: Jane Doe\nContact: jane [at] example.com\n", "/humans.txt")
    assert f.severity is Severity.INFO and "Chef: Jane Doe" in f.description


def test_cross_domain_policies():
    wide = _finding("crossdomain", '<cross-domain-policy><allow-access-from domain="*" /></cross-domain-policy>', "/crossdomain.xml")
    assert wide.severity is Severity.MEDIUM and wide.title == "/crossdomain.xml allows access from any domain"
    narrow = _finding("crossdomain", "<cross-domain-policy><allow-access-from domain='a.example.com'/></cross-domain-policy>", "/crossdomain.xml")
    assert narrow.severity is Severity.INFO and "a.example.com" in narrow.description
    cap = _finding("clientaccess", '<access-policy><cross-domain-access><policy><allow-from><domain uri="*"/></allow-from></policy></cross-domain-access></access-policy>', "/clientaccesspolicy.xml")
    assert cap.severity is Severity.MEDIUM
    empty = d.parse_crossdomain("<cross-domain-policy></cross-domain-policy>")
    assert empty == [] and d.build_finding("crossdomain", empty, "https://example.com/x", TARGET, "s") is None
    assert d.parse_crossdomain("<html></html>") is None


# ── the crawler: fetching, robots.txt, redirects, failures ───────────────────


@pytest.fixture(autouse=True)
def no_delay(monkeypatch):
    monkeypatch.setattr(web_crawl, "_REQUEST_DELAY", 0)


def _site(respx_mock, files, robots=""):
    """Fake site: `files` maps path → (status, body[, content_type]); anything else is a 404."""
    requested: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        requested.append(path)
        if path == "/robots.txt":
            return httpx.Response(200 if robots else 404, text=robots, headers={"content-type": "text/plain"})
        if path in files:
            status, body, *ctype = files[path]
            return httpx.Response(status, text=body, headers={"content-type": (ctype or ["text/plain"])[0]})
        if path == "/":
            return httpx.Response(200, text="<html><title>Home</title></html>", headers={"content-type": "text/html"})
        return httpx.Response(404, text="nf", headers={"content-type": "text/html"})

    respx_mock.route().mock(side_effect=handler)
    return requested


def _by_source(result, prefix):
    return [f for f in result.findings if f.title.startswith(prefix)]


FILES = {
    "/sitemap.xml": (200, URLSET, "application/xml"),
    "/.well-known/security.txt": (200, SECURITY),
    "/.well-known/openid-configuration": (200, json.dumps({"issuer": "https://example.com"}), "application/json"),
    "/humans.txt": (200, "Team: Jane"),
    "/crossdomain.xml": (200, '<cross-domain-policy><allow-access-from domain="*"/></cross-domain-policy>', "text/xml"),
}


async def test_the_crawler_reports_every_discovery_file_it_finds(respx_mock):
    requested = _site(respx_mock, FILES)
    result = await WebCrawlCollector().collect(TARGET)
    titles = [f.title for f in result.findings]

    assert "Sitemap /sitemap.xml: 4 URLs" in titles
    assert any(t.startswith("security.txt published") for t in titles)
    assert any(t.startswith("OpenID Connect configuration exposed") for t in titles)
    assert "humans.txt published" in titles
    assert "/crossdomain.xml allows access from any domain" in titles
    assert not any("assetlinks" in t or "app-site" in t or "clientaccess" in t for t in titles)   # 404s
    # reporting is not requesting: the URLs a sitemap lists are never fetched
    assert "/blog/a" not in requested and "/cart" not in requested
    assert requested.count("/sitemap.xml") == 1                      # also no more double probe


async def test_a_catch_all_single_page_app_yields_nothing(respx_mock):
    spa = "<!doctype html><html><head><title>App</title></head><body>app</body></html>"
    respx_mock.route().respond(200, text=spa, headers={"content-type": "text/html"})
    result = await WebCrawlCollector().collect(TARGET)
    assert not any(f.mitre_attack == "T1594" for f in result.findings)


async def test_robots_txt_applies_to_every_discovery_file(respx_mock):
    robots = "User-agent: *\nDisallow: /sitemap.xml\nDisallow: /.well-known/\nDisallow: /humans.txt\n"
    requested = _site(respx_mock, FILES, robots=robots)
    result = await WebCrawlCollector().collect(TARGET)
    assert not {"/sitemap.xml", "/.well-known/security.txt", "/humans.txt"} & set(requested)
    assert not any(f.title.startswith(("Sitemap", "security.txt", "humans")) for f in result.findings)
    assert any("allows access from any domain" in f.title for f in result.findings)   # not disallowed


async def test_security_txt_first_location_wins_and_the_legacy_path_is_a_fallback(respx_mock):
    requested = _site(respx_mock, {**FILES, "/security.txt": (200, SECURITY)})
    await WebCrawlCollector().collect(TARGET)
    assert "/.well-known/security.txt" in requested and "/security.txt" not in requested

    only_legacy = {k: v for k, v in FILES.items() if k != "/.well-known/security.txt"}
    requested = _site(respx_mock, {**only_legacy, "/security.txt": (200, SECURITY)})
    result = await WebCrawlCollector().collect(TARGET)
    assert "/security.txt" in requested and _by_source(result, "security.txt published")


async def test_sitemaps_declared_in_robots_txt_are_fetched_within_scope(respx_mock):
    robots = ("User-agent: *\nSitemap: https://example.com/news-sitemap.xml\n"
              "Sitemap: https://example.com/sitemap.xml\nSitemap: https://elsewhere.org/s.xml\n"
              + "".join(f"Sitemap: https://example.com/extra{i}.xml\n" for i in range(5)))
    files = {"/news-sitemap.xml": (200, INDEX, "application/xml"),
             "/extra0.xml": (200, URLSET, "application/xml")}
    requested = _site(respx_mock, files, robots=robots)
    result = await WebCrawlCollector().collect(TARGET)
    assert "/news-sitemap.xml" in requested                        # declared, in scope
    assert requested.count("/sitemap.xml") == 1                    # the default one is not repeated
    assert "/s.xml" not in requested                               # another site: out of scope
    declared = [p for p in requested if p.startswith(("/news-", "/extra"))]
    assert len(declared) == web_crawl._MAX_DECLARED_SITEMAPS       # capped: the first 3 only
    assert _by_source(result, "Sitemap index /news-sitemap.xml: 2 child sitemaps")


async def test_a_sitemap_reached_twice_through_a_redirect_is_read_and_reported_once(respx_mock):
    """/sitemap.xml redirects to www, and robots.txt declares the www URL as well (cobalt.io, …)."""
    hits: list[str] = []

    def handler(request):
        url = str(request.url)
        hits.append(url)
        if url == "https://example.com/robots.txt":
            return httpx.Response(200, text="Sitemap: https://www.example.com/sitemap.xml\n",
                                  headers={"content-type": "text/plain"})
        if url == "https://example.com/sitemap.xml":
            return httpx.Response(301, headers={"location": "https://www.example.com/sitemap.xml"})
        if url == "https://www.example.com/sitemap.xml":
            return httpx.Response(200, text=URLSET, headers={"content-type": "application/xml"})
        if request.url.path == "/" and request.url.host == "example.com":
            return httpx.Response(200, text="<html><title>Home</title></html>", headers={"content-type": "text/html"})
        return httpx.Response(404, text="nf", headers={"content-type": "text/html"})

    respx_mock.route().mock(side_effect=handler)
    result = await WebCrawlCollector().collect(TARGET)
    assert hits.count("https://www.example.com/sitemap.xml") == 1             # fetched once
    assert len(_by_source(result, "Sitemap /sitemap.xml")) == 1               # reported once


async def test_a_failing_or_slow_file_does_not_stop_the_others(respx_mock):
    def handler(request):
        if request.url.path == "/sitemap.xml":
            raise httpx.ReadTimeout("slow")
        if request.url.path == "/humans.txt":
            return httpx.Response(200, text="Team: Jane", headers={"content-type": "text/plain"})
        return httpx.Response(404, text="nf", headers={"content-type": "text/html"}) if request.url.path != "/" \
            else httpx.Response(200, text="<html></html>", headers={"content-type": "text/html"})

    respx_mock.route().mock(side_effect=handler)
    result = await WebCrawlCollector().collect(TARGET)
    assert _by_source(result, "humans.txt published") and not _by_source(result, "Sitemap")


async def test_a_huge_sitemap_is_read_only_up_to_the_cap(respx_mock, monkeypatch):
    monkeypatch.setattr(web_crawl, "MAX_BYTES", 2000)
    big = "<urlset>" + "".join(f"<url><loc>https://example.com/p{i}</loc></url>" for i in range(2000)) + "</urlset>"
    _site(respx_mock, {"/sitemap.xml": (200, big, "application/xml")})
    (f,) = _by_source(await WebCrawlCollector().collect(TARGET), "Sitemap /sitemap.xml")
    assert f.raw_data["total"] < 100                              # only the first 2000 bytes were parsed
