import httpx
import pytest

from core.collectors import crtsh
from core.collectors.crtsh import CrtshCollector
from core.models import Category, Severity

CRT_URL = r"https://crt\.sh/.*"


@pytest.fixture(autouse=True)
def no_backoff(monkeypatch):
    monkeypatch.setattr(crtsh, "_RETRY_DELAY", 0)


async def test_parses_subdomains_and_flags_sensitive(respx_mock, target):
    respx_mock.get(url__regex=CRT_URL).respond(json=[
        {"name_value": "www.example.com\ndev.example.com"},
        {"name_value": "*.example.com"},          # wildcard → example.com
        {"name_value": "www.example.com"},        # duplicate
    ])
    findings = (await CrtshCollector().collect(target)).findings
    by_asset = {f.affected_asset: f for f in findings}

    assert set(by_asset) == {"www.example.com", "dev.example.com", "example.com"}
    assert by_asset["dev.example.com"].severity is Severity.MEDIUM
    assert by_asset["www.example.com"].severity is Severity.INFO
    assert all(f.category is Category.SUBDOMAIN for f in findings)
    assert all(f.mitre_attack == "T1596.003" for f in findings)


async def test_rejects_lookalike_domains(respx_mock, target):
    respx_mock.get(url__regex=CRT_URL).respond(json=[
        {"name_value": "example.com.evil.org\nnotexample.com\nok.example.com"},
    ])
    findings = (await CrtshCollector().collect(target)).findings
    assert [f.affected_asset for f in findings] == ["ok.example.com"]


async def test_retries_then_succeeds(respx_mock, target):
    route = respx_mock.get(url__regex=CRT_URL)
    route.side_effect = [
        httpx.Response(502),
        httpx.Response(200, json=[{"name_value": "www.example.com"}]),
    ]
    findings = (await CrtshCollector().collect(target)).findings
    assert route.call_count == 2
    assert len(findings) == 1


async def test_permanent_failure_raises(respx_mock, target):
    route = respx_mock.get(url__regex=CRT_URL).respond(502)
    with pytest.raises(RuntimeError, match="unreachable after 3 attempts"):
        await CrtshCollector().collect(target)
    assert route.call_count == 3


def test_retry_budget_is_bounded():
    # worst case dead wait ≈ attempts × timeout + backoff ≈ 3×45 + 15 = 150s (phase 1 runs concurrently)
    assert crtsh._MAX_RETRIES == 3
    assert crtsh._REQUEST_TIMEOUT == 45


async def test_network_error_also_raises(respx_mock, target):
    respx_mock.get(url__regex=CRT_URL).mock(side_effect=httpx.ConnectError("down"))
    with pytest.raises(RuntimeError):
        await CrtshCollector().collect(target)


@pytest.mark.parametrize("host, expected", [
    ("dev.domain.fr", True),
    ("staging-api.domain.fr", True),          # "-" separates labels
    ("dev.preprod.domain.fr", True),          # first label only...
    ("a.b.dev.domain.fr", False),             # ...labels further right are ignored
    ("17849-fix.preprod-dev.domain.fr", False),   # review app under an environment zone
    ("x.staging.domain.fr", False),
    ("pre-prod.domain.fr", True),             # hyphenated keyword
    ("dev01.domain.fr", True),                # keyword + digits
    ("staging2.domain.fr", True),
    ("test-1.domain.fr", True),
    ("pre-prod2.domain.fr", True),            # digits after the last part of a hyphenated keyword
    ("1dev.domain.fr", False),                # digits only AFTER the keyword
    ("dev1a.domain.fr", False),
    ("device.domain.fr", False),              # substring of "dev": no longer flagged
    ("gold.domain.fr", False),                # "old"
    ("latest.domain.fr", False),              # "test"
    ("rapid.domain.fr", False),               # "api"
    ("www.domain.fr", False),
    ("domain.fr", False),                     # apex
])
def test_sensitive_keywords_match_whole_labels(host, expected):
    assert crtsh._is_sensitive(host, "domain.fr") is expected


def test_only_the_leftmost_label_is_checked_end_to_end():
    assert crtsh._is_sensitive("staging-api.example.com", "example.com") is True
    assert crtsh._is_sensitive("17849-fix.preprod-dev.example.com", "example.com") is False


def test_target_domain_labels_are_not_scanned():
    assert crtsh._is_sensitive("www.api.io", "api.io") is False
    assert crtsh._is_sensitive("dev.api.io", "api.io") is True


async def test_no_false_positive_severity_end_to_end(respx_mock, target):
    respx_mock.get(url__regex=CRT_URL).respond(json=[
        {"name_value": "device.example.com\ngold.example.com\nstaging-api.example.com"}])
    by_asset = {f.affected_asset: f.severity
                for f in (await CrtshCollector().collect(target)).findings}
    assert by_asset == {"device.example.com": Severity.INFO,
                        "gold.example.com": Severity.INFO,
                        "staging-api.example.com": Severity.MEDIUM}
