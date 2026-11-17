import httpx
import pytest

from core.collectors import ALL_COLLECTORS, PERSON_COLLECTORS
from core.collectors.base import BaseCollector, BasePersonCollector
from core.collectors.hunter_io import HunterCollector
from core.models import Category, OsintTarget, Severity

API = r"https://api\.hunter\.io/v2/domain-search.*"


@pytest.fixture(autouse=True)
def key(monkeypatch):
    monkeypatch.setenv("HUNTER_API_KEY", "hk_test")


@pytest.fixture
def target():
    return OsintTarget(company_name="Acme", domain="acme.fr")


def _email(value, first, last, position, confidence):
    return {"value": value, "first_name": first, "last_name": last,
            "position": position, "confidence": confidence}


THREE = {"data": {"emails": [
    _email("ceo@acme.fr", "Alice", "Martin", "CEO", 90),
    _email("dev@acme.fr", "Bob", "Durand", "Developer", 50),
    _email("cto@acme.fr", "Carol", "Petit", "CTO", 85),
]}}


def test_is_a_phase_1_domain_collector():
    c = HunterCollector()
    assert isinstance(c, BaseCollector) and not isinstance(c, BasePersonCollector)
    assert any(isinstance(x, HunterCollector) for x in ALL_COLLECTORS)
    assert not any(isinstance(x, HunterCollector) for x in PERSON_COLLECTORS)
    assert c.tier == 1                                  # so it also runs in the default "short" mode
    assert (c.requires_api_key, c.api_key_env, c.french_only) == (True, "HUNTER_API_KEY", False)


def test_availability_depends_on_key(monkeypatch):
    assert HunterCollector().is_available() is True
    monkeypatch.delenv("HUNTER_API_KEY")
    assert HunterCollector().is_available() is False


async def test_domain_search(respx_mock, target):
    route = respx_mock.get(url__regex=API).respond(json=THREE)
    result = await HunterCollector().collect(target)

    sev = sorted(f.severity.value for f in result.findings)
    assert sev == ["info", "medium", "medium"]            # confidence 90, 85 → MEDIUM; 50 → INFO
    assert {f.title for f in result.findings} == {
        "Employee email: ceo@acme.fr (CEO)",
        "Employee email: dev@acme.fr (Developer)",
        "Employee email: cto@acme.fr (CTO)",
    }
    assert all(f.category is Category.EMAIL and f.mitre_attack == "T1589.002"
               for f in result.findings)
    assert all(f.affected_asset.endswith("@acme.fr") for f in result.findings)

    # persons are returned so that the phase 2 pivot can use them
    assert [(p.full_name, p.role, p.email, p.source) for p in result.persons] == [
        ("Alice Martin", "CEO", "ceo@acme.fr", "Hunter.io"),
        ("Bob Durand", "Developer", "dev@acme.fr", "Hunter.io"),
        ("Carol Petit", "CTO", "cto@acme.fr", "Hunter.io"),
    ]
    request = route.calls[0].request
    assert dict(request.url.params) == {"domain": "acme.fr", "limit": "100"}
    assert request.headers["authorization"] == "Bearer hk_test"


async def test_confidence_threshold_is_80_inclusive(respx_mock, target):
    respx_mock.get(url__regex=API).respond(json={"data": {"emails": [
        _email("a@acme.fr", "A", "A", "x", 80), _email("b@acme.fr", "B", "B", "x", 79),
    ]}})
    result = await HunterCollector().collect(target)
    assert [f.severity for f in result.findings] == [Severity.MEDIUM, Severity.INFO]


async def test_no_persons_without_name(respx_mock, target):
    respx_mock.get(url__regex=API).respond(json={"data": {"emails": [
        _email("info@acme.fr", "", None, None, 95),
    ]}})
    result = await HunterCollector().collect(target)
    assert len(result.findings) == 1
    assert "(unknown role)" in result.findings[0].title
    assert result.persons == []


async def test_empty_response(respx_mock, target):
    respx_mock.get(url__regex=API).respond(json={"data": {"emails": []}})
    result = await HunterCollector().collect(target)
    assert result.findings == [] and result.persons == []


async def test_no_cache_each_call_hits_the_api(respx_mock, target):
    """collect() runs once per run, so there is no cross-call cache any more."""
    route = respx_mock.get(url__regex=API).respond(json=THREE)
    collector = HunterCollector()
    first = await collector.collect(target)
    second = await collector.collect(target)
    assert route.call_count == 2
    assert len(first.findings) == len(second.findings) == 3


async def test_invalid_key(respx_mock, target):
    respx_mock.get(url__regex=API).respond(401)
    with pytest.raises(RuntimeError, match="Hunter.io: invalid API key"):
        await HunterCollector().collect(target)


async def test_rate_limit(respx_mock, target):
    respx_mock.get(url__regex=API).respond(429)
    with pytest.raises(RuntimeError, match="Hunter.io: rate limit exceeded"):
        await HunterCollector().collect(target)


async def test_other_http_error(respx_mock, target):
    respx_mock.get(url__regex=API).respond(500)
    with pytest.raises(RuntimeError, match="Hunter.io API error 500"):
        await HunterCollector().collect(target)


async def test_connection_error(respx_mock, target):
    respx_mock.get(url__regex=API).mock(side_effect=httpx.ConnectError("down"))
    with pytest.raises(RuntimeError, match="Hunter.io unreachable: ConnectError"):
        await HunterCollector().collect(target)


async def test_api_key_is_sent_in_header_never_in_url(respx_mock, target):
    route = respx_mock.get(url__regex=API).respond(json=THREE)
    await HunterCollector().collect(target)

    request = route.calls[0].request
    assert request.headers["authorization"] == "Bearer hk_test"
    assert "api_key" not in request.url.params
    assert "api_key" not in str(request.url)
    assert "hk_test" not in str(request.url)               # the secret is not in the URL at all


async def test_api_key_never_ends_up_in_findings_or_persons(respx_mock, target):
    respx_mock.get(url__regex=API).respond(json=THREE)
    result = await HunterCollector().collect(target)

    dump = repr(result.findings) + repr(result.persons)
    assert "hk_test" not in dump
    assert all("api_key" not in f.raw_data for f in result.findings)
    assert all("hk_test" not in f.source_url for f in result.findings)


async def test_error_messages_do_not_leak_the_key(respx_mock, target):
    respx_mock.get(url__regex=API).respond(500)
    with pytest.raises(RuntimeError) as exc:
        await HunterCollector().collect(target)
    assert "hk_test" not in str(exc.value)
