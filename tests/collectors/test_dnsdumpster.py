import httpx
import pytest

from core.collectors.dnsdumpster import DnsDumpsterCollector, categorize
from core.models import OsintTarget, Severity

API = r"https://api\.hackertarget\.com/hostsearch/.*"


@pytest.fixture
def target():
    return OsintTarget(company_name="", domain="example.com")


# ── the 4 requested tests ────────────────────────────────────────────────────


async def test_subdomains_parsed(respx_mock, target):
    route = respx_mock.get(url__regex=API).respond(text=(
        "www.example.com,93.184.216.34\n"
        "shop.example.com,93.184.216.35\n"
        "blog.example.com,93.184.216.36\n"))
    result = await DnsDumpsterCollector().collect(target)

    assert len(result.findings) == 3 and result.persons == []
    assert [f.title for f in result.findings] == [
        "Subdomain: www.example.com → 93.184.216.34",
        "Subdomain: shop.example.com → 93.184.216.35",
        "Subdomain: blog.example.com → 93.184.216.36",
    ]
    f = result.findings[0]
    assert f.affected_asset == "www.example.com" and f.source == "DNSDumpster"
    assert f.mitre_attack == "T1590.005" and f.severity is Severity.INFO
    assert f.description == "Subdomain of example.com discovered via passive DNS."
    assert dict(route.calls[0].request.url.params) == {"q": "example.com"}


async def test_dev_subdomain_is_medium(respx_mock, target):
    respx_mock.get(url__regex=API).respond(text=(
        "dev.example.com,1.1.1.1\nvpn.example.com,1.1.1.2\nwww.example.com,1.1.1.3\n"))
    by_asset = {f.affected_asset: f for f in (await DnsDumpsterCollector().collect(target)).findings}
    assert by_asset["dev.example.com"].severity is Severity.MEDIUM
    assert by_asset["vpn.example.com"].severity is Severity.MEDIUM        # remote_access
    assert by_asset["www.example.com"].severity is Severity.INFO


async def test_api_error_returns_empty(respx_mock, target):
    respx_mock.get(url__regex=API).respond(text="error check your domain")
    result = await DnsDumpsterCollector().collect(target)
    assert result.findings == [] and result.persons == []


async def test_api_count_exceeded(respx_mock, target, caplog):
    respx_mock.get(url__regex=API).respond(text="API count exceeded - Increase Quota with Membership")
    with caplog.at_level("WARNING", logger="core.collectors.dnsdumpster"):
        result = await DnsDumpsterCollector().collect(target)
    assert result.findings == [] and result.persons == []
    assert "quota exceeded" in caplog.text


# ── more behaviour ───────────────────────────────────────────────────────────


@pytest.mark.parametrize("host, category", [
    ("mail.example.com", "mail"), ("smtp.example.com", "mail"), ("mx.example.com", "mail"),
    ("mx2.example.com", "mail"),
    ("vpn.example.com", "remote_access"), ("remote.example.com", "remote_access"),
    ("citrix.example.com", "remote_access"), ("vpn2.example.com", "remote_access"),
    ("dev.example.com", "dev_staging"), ("staging.example.com", "dev_staging"),
    ("test.example.com", "dev_staging"), ("beta.example.com", "dev_staging"),
    ("dev-1.example.com", "dev_staging"),
    ("api.example.com", "api"),
    ("www.example.com", "subdomain"), ("devops.example.com", "subdomain"),
    ("testimonials.example.com", "subdomain"), ("a.dev.example.com", "subdomain"),
])
def test_categorize(host, category):
    assert categorize(host) == category


async def test_apex_lookalikes_and_malformed_lines_are_skipped(respx_mock, target):
    respx_mock.get(url__regex=API).respond(text=(
        "example.com,1.1.1.1\n"              # apex — already in the DNS collector
        "evilexample.com,2.2.2.2\n"           # endswith("example.com") but NOT a subdomain
        "example.com.evil.org,3.3.3.3\n"
        "garbage line\n"
        "a,b,c\n"
        "\n"
        "ok.example.com,4.4.4.4\n"
        "OK.example.com,4.4.4.4\n"))          # duplicate, different case
    result = await DnsDumpsterCollector().collect(target)
    assert [f.affected_asset for f in result.findings] == ["ok.example.com"]


async def test_summary_finding_above_five_subdomains(respx_mock, target):
    respx_mock.get(url__regex=API).respond(
        text="".join(f"h{i}.example.com,1.1.1.{i}\n" for i in range(6)))
    result = await DnsDumpsterCollector().collect(target)

    assert len(result.findings) == 7
    summary = result.findings[-1]
    assert summary.title == "DNSDumpster: 6 subdomains discovered for example.com"
    assert summary.severity is Severity.INFO and summary.mitre_attack == "T1590"


async def test_no_summary_with_exactly_five(respx_mock, target):
    respx_mock.get(url__regex=API).respond(
        text="".join(f"h{i}.example.com,1.1.1.{i}\n" for i in range(5)))
    result = await DnsDumpsterCollector().collect(target)
    assert len(result.findings) == 5
    assert not any(f.title.startswith("DNSDumpster:") for f in result.findings)


async def test_empty_response(respx_mock, target):
    respx_mock.get(url__regex=API).respond(text="")
    assert (await DnsDumpsterCollector().collect(target)).findings == []


async def test_http_error_raises(respx_mock, target):
    respx_mock.get(url__regex=API).respond(500)
    with pytest.raises(RuntimeError, match="DNSDumpster API error 500"):
        await DnsDumpsterCollector().collect(target)


async def test_connection_error_raises(respx_mock, target):
    respx_mock.get(url__regex=API).mock(side_effect=httpx.ConnectError("down"))
    with pytest.raises(RuntimeError, match="DNSDumpster unreachable: ConnectError"):
        await DnsDumpsterCollector().collect(target)


def test_metadata_and_registration():
    from core.collectors import ALL_COLLECTORS

    c = DnsDumpsterCollector()
    assert (c.tier, c.requires_api_key, c.french_only, c.request_delay) == (1, False, False, 1.0)
    names = [x.name for x in ALL_COLLECTORS]
    assert names == ["DNS", "WHOIS", "crt.sh", "DNSDumpster", "Google Dorks", "GitHub Org", "OpenCorporates",
                     "BODACC", "Pappers.fr", "Web Crawler", "Annuaire Entreprises", "Hunter.io", "Wayback Machine"]
