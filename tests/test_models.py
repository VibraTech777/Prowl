from core.models import (
    SEVERITY_ORDER, Category, Finding, OsintReport, OsintTarget, Severity,
)
from tests.conftest import make_finding, make_report


def test_severity_order_is_most_critical_first():
    ordered = sorted(Severity, key=lambda s: SEVERITY_ORDER[s])
    assert [s.value for s in ordered] == ["critical", "high", "medium", "low", "info"]
    assert SEVERITY_ORDER[Severity.CRITICAL] == 0


def test_finding_defaults_and_timezone_aware_timestamp():
    f = make_finding()
    assert f.raw_data == {}
    assert f.mitre_attack == ""
    assert f.timestamp.tzinfo is not None


def test_finding_default_dicts_are_not_shared():
    a, b = make_finding(), make_finding()
    a.raw_data["x"] = 1
    assert b.raw_data == {}


def test_osint_target_defaults():
    t = OsintTarget(company_name="Acme", domain="acme.com")
    assert t.siren is None
    assert t.mode == "short"
    assert t.french is False and t.crawl is False
    assert t.crawl_depth == 1


def test_report_defaults():
    r = make_report()
    assert r.version == "0.1.0"
    assert r.generated_at.tzinfo is not None
    assert isinstance(r, OsintReport) and isinstance(r.findings[0], Finding)
    assert Category.SUBDOMAIN.value == "subdomain"


def test_osint_person_defaults():
    from core.models import OsintPerson

    p = OsintPerson(full_name="Alice Martin")
    assert (p.role, p.email, p.source, p.depth_found) == ("", "", "", 1)


def test_collector_result_defaults_and_independent_lists():
    from core.models import CollectorResult, OsintPerson

    a, b = CollectorResult(findings=[]), CollectorResult(findings=[])
    a.persons.append(OsintPerson("X"))
    assert b.persons == []


def test_pivot_depth_defaults_to_disabled():
    assert OsintTarget(company_name="A", domain="a.com").pivot_depth == 0


def test_pivot_limit_and_stats_defaults():
    assert OsintTarget(company_name="A", domain="a.com").pivot_limit == 25
    assert make_report().pivot_stats == {}
