import httpx
import pytest

from core.collectors.opencorporates import OpenCorporatesCollector
from core.models import OsintTarget, Severity

SEARCH_PATH = "/v0.4/companies/search"


@pytest.fixture(autouse=True)
def setup(monkeypatch):
    monkeypatch.setenv("OPENCORPORATES_API_TOKEN", "tok")
    monkeypatch.setattr(OpenCorporatesCollector, "request_delay", 0)


@pytest.fixture
def target():
    return OsintTarget(company_name="Zed Industries", domain="zed.dev")


def _company(name="ZED INDUSTRIES", number="12345", jur="us_de"):
    return {"company": {"name": name, "company_number": number, "jurisdiction_code": jur,
                        "opencorporates_url": f"https://opencorporates.com/companies/{jur}/{number}"}}


def _officer(name, position="director", end_date=None):
    return {"officer": {"name": name, "position": position, "start_date": "2020-01-01",
                        "end_date": end_date}}


def _site(respx_mock, companies, officers=None, officers_status=200):
    """Fake OpenCorporates. Returns the list of (path, params) requests received."""
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.url.path, dict(request.url.params)))
        if request.url.path == SEARCH_PATH:
            return httpx.Response(200, json={"results": {"companies": companies}})
        if request.url.path.endswith("/officers"):
            if officers_status != 200:
                return httpx.Response(officers_status)
            return httpx.Response(200, json={"results": {"officers": officers or []}})
        return httpx.Response(404)

    respx_mock.route().mock(side_effect=handler)
    return seen


# ── the 4 requested tests ────────────────────────────────────────────────────


async def test_officers_returned_as_persons(respx_mock, target):
    _site(respx_mock, [_company()],
          [_officer("NATHAN SOBO", "director"), _officer("max brunsfeld", "ceo")])
    result = await OpenCorporatesCollector().collect(target)

    assert [(p.full_name, p.role, p.email, p.source, p.depth_found) for p in result.persons] == [
        ("Nathan Sobo", "director", "", "OpenCorporates", 1),
        ("Max Brunsfeld", "ceo", "", "OpenCorporates", 1),
    ]
    titles = [f.title for f in result.findings]
    assert titles[0] == "OpenCorporates: ZED INDUSTRIES (us_de)"
    assert "Officer: Nathan Sobo (director)" in titles and "Officer: Max Brunsfeld (ceo)" in titles
    assert all(f.severity is Severity.INFO and f.mitre_attack == "T1591.001"
               and f.affected_asset == "zed.dev" and f.source == "OpenCorporates"
               for f in result.findings)
    assert result.findings[0].description == "Company number: 12345. Jurisdiction: us_de."


async def test_inactive_officer_skipped(respx_mock, target):
    _site(respx_mock, [_company()],
          [_officer("Active Person"), _officer("Former Person", end_date="2022-05-01")])
    result = await OpenCorporatesCollector().collect(target)
    assert [p.full_name for p in result.persons] == ["Active Person"]
    assert not any("Former Person" in f.title for f in result.findings)


async def test_no_match_returns_empty(respx_mock, target):
    seen = _site(respx_mock, [])
    result = await OpenCorporatesCollector().collect(target)
    assert result.findings == [] and result.persons == []
    assert [p for p, _ in seen] == [SEARCH_PATH]                 # officers never requested


async def test_rate_limit_returns_empty(respx_mock, target, caplog):
    respx_mock.route().respond(429)
    with caplog.at_level("WARNING", logger="core.collectors.opencorporates"):
        result = await OpenCorporatesCollector().collect(target)       # no exception
    assert result.findings == [] and result.persons == []
    assert "OpenCorporates rate limit hit" in caplog.text


# ── more behaviour ───────────────────────────────────────────────────────────


async def test_needs_a_token_and_is_skipped_without_it(monkeypatch):
    c = OpenCorporatesCollector()
    assert c.requires_api_key is True and c.api_key_env == "OPENCORPORATES_API_TOKEN"
    assert c.is_available() is True
    monkeypatch.delenv("OPENCORPORATES_API_TOKEN")
    assert c.is_available() is False


async def test_invalid_token_raises(respx_mock, target):
    respx_mock.route().respond(401, json={"error": {"message": "Invalid Api Token"}})
    with pytest.raises(RuntimeError, match="invalid or missing API token"):
        await OpenCorporatesCollector().collect(target)


async def test_other_http_error_raises(respx_mock, target):
    respx_mock.route().respond(500)
    with pytest.raises(RuntimeError, match="OpenCorporates API error 500"):
        await OpenCorporatesCollector().collect(target)


async def test_connection_error_raises(respx_mock, target):
    respx_mock.route().mock(side_effect=httpx.ConnectError("down"))
    with pytest.raises(RuntimeError, match="OpenCorporates unreachable: ConnectError"):
        await OpenCorporatesCollector().collect(target)


async def test_exact_name_beats_partial_match(respx_mock, target):
    _site(respx_mock, [_company("ZED INDUSTRIES HOLDING", "1"), _company("zed industries", "2")],
          [_officer("Alice")])
    result = await OpenCorporatesCollector().collect(target)
    assert result.findings[0].raw_data["company_number"] == "2"


async def test_partial_match_must_be_a_whole_word(respx_mock):
    t = OsintTarget(company_name="", domain="zed.dev")
    _site(respx_mock, [_company("ZEDDY LTD")], [_officer("Mallory")])
    assert (await OpenCorporatesCollector().collect(t)).findings == []   # not "zed"

    _site(respx_mock, [_company("THE ZED COMPANY")], [_officer("Alice")])
    assert len((await OpenCorporatesCollector().collect(t)).persons) == 1


async def test_search_term_falls_back_to_domain_label(respx_mock):
    seen = _site(respx_mock, [])
    await OpenCorporatesCollector().collect(OsintTarget(company_name="", domain="zed.dev"))
    assert seen[0][1]["q"] == "zed"                                       # TLD stripped
    assert seen[0][1]["per_page"] == "5"


async def test_company_name_is_preferred_and_token_is_sent(respx_mock, target):
    seen = _site(respx_mock, [])
    await OpenCorporatesCollector().collect(target)
    assert seen[0][1] == {"api_token": "tok", "q": "Zed Industries", "per_page": "5"}


async def test_officers_request_uses_company_path_and_page_size(respx_mock, target):
    seen = _site(respx_mock, [_company(number="AB 12/3", jur="gb")], [])
    await OpenCorporatesCollector().collect(target)
    wire = [call.request.url.raw_path for call in respx_mock.calls]

    # company_number comes from the API response: it is URL-quoted, never interpolated raw
    assert wire[1].split(b"?")[0] == b"/v0.4/companies/gb/AB%2012%2F3/officers"
    assert seen[1][1]["per_page"] == "20"


async def test_officers_404_keeps_the_company_finding(respx_mock, target):
    _site(respx_mock, [_company()], officers_status=404)
    result = await OpenCorporatesCollector().collect(target)
    assert len(result.findings) == 1 and result.persons == []


async def test_officers_without_name_or_position(respx_mock, target):
    _site(respx_mock, [_company()],
          [{"officer": {"name": "", "position": "director"}},
           {"officer": {"name": "solo person", "position": None, "end_date": None}}])
    result = await OpenCorporatesCollector().collect(target)
    assert [p.full_name for p in result.persons] == ["Solo Person"]
    assert "Officer: Solo Person (officer)" in [f.title for f in result.findings]
