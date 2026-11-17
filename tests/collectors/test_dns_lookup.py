from core.collectors import dns_lookup
from core.collectors.dns_lookup import DnsCollector
from core.models import Category, Severity


def _fake_resolver(records: dict[tuple[str, str], list[str]]):
    return lambda domain, rtype: records.get((domain, rtype), [])


async def test_emits_record_findings_and_no_issues_when_secure(monkeypatch, target):
    monkeypatch.setattr(dns_lookup, "_resolve", _fake_resolver({
        ("example.com", "A"): ["1.2.3.4"],
        ("example.com", "AAAA"): ["::1"],
        ("example.com", "MX"): ["10 mail.example.com."],
        ("example.com", "NS"): ["ns1.example.com."],
        ("example.com", "TXT"): ['"v=spf1 -all"'],
        ("_dmarc.example.com", "TXT"): ['"v=DMARC1; p=reject"'],
    }))
    findings = (await DnsCollector().collect(target)).findings
    titles = [f.title for f in findings]

    assert len(findings) == 3
    assert any("IP addresses" in t for t in titles)
    assert any("Mail servers" in t for t in titles)
    assert any("Name servers" in t for t in titles)
    assert not any(f.category is Category.DNS_ISSUE for f in findings)


async def test_missing_spf_and_dmarc_are_high(monkeypatch, target):
    monkeypatch.setattr(dns_lookup, "_resolve", _fake_resolver({}))
    findings = (await DnsCollector().collect(target)).findings

    assert len(findings) == 2
    assert all(f.severity is Severity.HIGH for f in findings)
    assert {f.title for f in findings} == {
        "Missing SPF record on example.com",
        "Missing DMARC record on example.com",
    }
    dmarc = next(f for f in findings if "DMARC" in f.title)
    assert dmarc.affected_asset == "_dmarc.example.com"


async def test_spf_present_but_dmarc_missing(monkeypatch, target):
    monkeypatch.setattr(dns_lookup, "_resolve", _fake_resolver({
        ("example.com", "TXT"): ['"v=spf1 include:_spf.google.com ~all"'],
    }))
    findings = (await DnsCollector().collect(target)).findings
    assert [f.title for f in findings] == ["Missing DMARC record on example.com"]


def test_resolve_swallows_dns_errors(monkeypatch):
    import dns.resolver

    def boom(*a, **k):
        raise dns.resolver.NXDOMAIN()

    monkeypatch.setattr(dns_lookup.dns.resolver, "resolve", boom)
    assert dns_lookup._resolve("nope.invalid", "A") == []
