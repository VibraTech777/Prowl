"""Shared fixtures and helpers for the Prowl test suite. No network access."""

from __future__ import annotations

import pytest

from core.models import (
    Category, Finding, OsintReport, OsintTarget, Severity,
)


def make_finding(
    severity: Severity = Severity.INFO,
    category: Category = Category.SUBDOMAIN,
    asset: str = "a.example.com",
    **kw,
) -> Finding:
    return Finding(
        id=kw.pop("id", ""),
        severity=severity,
        category=category,
        title=kw.pop("title", f"Finding on {asset}"),
        description=kw.pop("description", "desc"),
        affected_asset=asset,
        source=kw.pop("source", "test"),
        source_url=kw.pop("source_url", "https://example.com"),
        **kw,
    )


def make_report(findings: list[Finding] | None = None, **kw) -> OsintReport:
    findings = findings if findings is not None else [
        make_finding(Severity.MEDIUM, asset="dev.example.com", id="F001",
                     mitre_attack="T1596.003"),
        make_finding(Severity.INFO, asset="www.example.com", id="F002"),
    ]
    return OsintReport(
        target=kw.pop("target", OsintTarget(company_name="Acme", domain="example.com")),
        findings=findings,
        assets=kw.pop("assets", {"subdomains": ["dev.example.com", "www.example.com"],
                                 "emails": [], "ips": []}),
        errors=kw.pop("errors", {}),
        collectors_run=kw.pop("collectors_run", ["DNS", "crt.sh"]),
        duration_seconds=kw.pop("duration_seconds", 1.5),
        **kw,
    )


@pytest.fixture
def target() -> OsintTarget:
    return OsintTarget(company_name="Acme", domain="example.com")
