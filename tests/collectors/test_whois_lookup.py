from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from core.collectors import whois_lookup
from core.collectors.whois_lookup import WhoisCollector, _to_datetime
from core.models import Category, Severity


def _patch_whois(monkeypatch, days_until_expiry: int | None, **extra):
    now = datetime.now(timezone.utc)
    data = SimpleNamespace(
        registrar="Test Registrar",
        creation_date=now - timedelta(days=2000),
        expiration_date=(
            now + timedelta(days=days_until_expiry, hours=1)
            if days_until_expiry is not None else None
        ),
        name_servers=["NS1.Example.com", "ns2.example.com"],
    )
    for k, v in extra.items():
        setattr(data, k, v)
    monkeypatch.setattr(whois_lookup.whois, "whois", lambda domain: data)


async def test_base_info_finding_only_when_far_from_expiry(monkeypatch, target):
    _patch_whois(monkeypatch, 400)
    findings = (await WhoisCollector().collect(target)).findings
    assert len(findings) == 1
    f = findings[0]
    assert f.severity is Severity.INFO and f.category is Category.COMPANY_INFO
    assert "Test Registrar" in f.description
    assert f.raw_data["name_servers"] == ["ns1.example.com", "ns2.example.com"]


async def test_expiring_within_30_days_is_high(monkeypatch, target):
    _patch_whois(monkeypatch, 10)
    findings = (await WhoisCollector().collect(target)).findings
    issue = [f for f in findings if f.category is Category.DNS_ISSUE]
    assert len(issue) == 1 and issue[0].severity is Severity.HIGH
    assert "10 days" in issue[0].title


async def test_expiring_within_90_days_is_medium(monkeypatch, target):
    _patch_whois(monkeypatch, 60)
    findings = (await WhoisCollector().collect(target)).findings
    issue = [f for f in findings if f.category is Category.DNS_ISSUE]
    assert len(issue) == 1 and issue[0].severity is Severity.MEDIUM


async def test_unknown_expiry_does_not_crash(monkeypatch, target):
    _patch_whois(monkeypatch, None)
    findings = (await WhoisCollector().collect(target)).findings
    assert len(findings) == 1
    assert "Expires: unknown" in findings[0].description


async def test_lookup_failure_returns_empty(monkeypatch, target):
    def boom(domain):
        raise OSError("whois server down")

    monkeypatch.setattr(whois_lookup.whois, "whois", boom)
    assert (await WhoisCollector().collect(target)).findings == []


def test_to_datetime_normalises_inputs():
    naive = datetime(2030, 1, 1)
    assert _to_datetime(naive).tzinfo is timezone.utc
    assert _to_datetime([naive]).year == 2030
    assert _to_datetime(None) is None
    assert _to_datetime("2030-01-01") is None
