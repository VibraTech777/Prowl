"""
core/models.py — Core data models for Prowl.

All business logic lives here. cli/ and reports/ do not define
their own data structures — they import from this module.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class Severity(str, Enum):
    """Finding severity, ordered from most to least critical."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# Ordering map used for sorting findings in the report output
SEVERITY_ORDER: dict[str, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


class Category(str, Enum):
    """The type of intelligence a Finding represents."""
    BREACH_DATA    = "breach_data"
    EXPOSED_PORT   = "exposed_port"
    SUBDOMAIN      = "subdomain"
    EMAIL          = "email"
    CREDENTIALS    = "credentials"
    TECH_EXPOSURE  = "tech_exposure"
    DNS_ISSUE      = "dns_issue"
    WEB_FINDING    = "web_finding"
    COMPANY_INFO   = "company_info"
    CODE_LEAK      = "code_leak"


# ---------------------------------------------------------------------------
# Core dataclasses
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    """
    A single piece of OSINT intelligence.

    Every collector produces a list[Finding].
    The id field uses the format F001, F002, … assigned at report time.
    """
    id:             str            # e.g. "F001" — set by the exporter
    severity:       Severity
    category:       Category
    title:          str            # Short one-line description
    description:    str            # Full human-readable explanation
    affected_asset: str            # domain, IP, email address, etc.
    source:         str            # Collector name, e.g. "crt.sh"
    source_url:     str            # Clickable link the analyst can verify

    raw_data:       dict           = field(default_factory=dict)
    mitre_attack:   str            = ""   # e.g. "T1596.001"
    timestamp:      datetime       = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class OsintTarget:
    """
    Everything Prowl knows about the target before collection begins.

    Passed verbatim to every collector — collectors must not mutate it.
    """
    company_name:  str
    domain:        str
    siren:         str | None = None   # French company registration number
    mode:          str         = "short"  # "short" | "deep"
    french:        bool        = False    # Enables French-specific sources
    crawl:         bool        = False    # visit discovered HTTP pages (the CLI turns it on by default)
    crawl_depth:   int         = 1
    crawl_port:    int | None  = None     # web crawler port (None = the scheme's default)
    pivot_depth:   int         = 0        # person pivot: 0 = disabled
    pivot_limit:   int         = 25       # max persons pivoted on per depth level


@dataclass
class OsintReport:
    """
    The final aggregated result returned by core/runner.py.

    Consumed by cli/display.py (terminal table),
    reports/exporter.py (JSON), and reports/pdf_exporter.py (PDF).
    """
    target:            OsintTarget
    findings:          list[Finding]
    assets:            dict               # {emails: [], subdomains: [], ips: []}
    errors:            dict[str, str]     # {collector_name: error_message}
    collectors_run:    list[str]
    duration_seconds:  float
    generated_at:      datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    version:           str      = "0.1.0"
    # person pivot: {collector: {"calls": n, "errors": m}}
    pivot_stats:       dict[str, dict[str, int]] = field(default_factory=dict)
    # eligible collectors that were skipped because their API key is missing
    collectors_skipped: list[str] = field(default_factory=list)
    # every person identified during the run (phase 1 + pivot), deduplicated
    persons:            list[OsintPerson] = field(default_factory=list)
    # collectors that ran but had nothing to search for: {name: reason}
    # (e.g. BODACC without --company/--siren). Not errors, not "no key".
    skipped_reasons:    dict[str, str] = field(default_factory=dict)


@dataclass
class OsintPerson:
    """A person discovered during collection; input for the person pivot."""
    full_name:   str
    role:        str = ""      # "Président", "CEO", "employee"
    email:       str = ""      # if known
    source:      str = ""      # which collector found this person
    depth_found: int = 1       # pivot level at which found
    github_login: str = ""     # GitHub login when known to be this person (org member)
    github_org:   str = ""     # login of the target's GitHub org that login is a member of
    # Address GUESSED from the company's email format (EmailFormat). Display only:
    # it is never put in `email`, so it can never feed a search of the pivot chain.
    email_guess:  str = ""


@dataclass
class CollectorResult:
    """What every collector returns: findings plus any persons discovered."""
    findings: list[Finding]
    persons:  list[OsintPerson] = field(default_factory=list)
