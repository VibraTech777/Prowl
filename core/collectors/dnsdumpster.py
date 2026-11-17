"""
core/collectors/dnsdumpster.py — passive subdomain discovery via HackerTarget (phase 1).

Uses the free HackerTarget host-search API (https://api.hackertarget.com/hostsearch/),
the data source behind DNSDumpster. No API key; free tier ≈ 100 queries/day per IP.
"""

from __future__ import annotations

import logging
import re

import httpx

from core.collectors.base import BaseCollector
from core.models import Category, CollectorResult, Finding, OsintTarget, Severity

logger = logging.getLogger(__name__)

_API = "https://api.hackertarget.com/hostsearch/"
_TIMEOUT = 15
_SUMMARY_THRESHOLD = 5

# category → first-label keywords. A label matches when it is the keyword itself
# or the keyword followed by digits ("vpn", "vpn2", "dev-1") — not "devops".
_CATEGORIES: dict[str, tuple[str, ...]] = {
    "mail": ("mail", "smtp", "mx"),
    "remote_access": ("vpn", "remote", "citrix"),
    "dev_staging": ("dev", "staging", "test", "beta"),
    "api": ("api",),
}
_MEDIUM_CATEGORIES = {"remote_access", "dev_staging"}


def categorize(hostname: str) -> str:
    label = hostname.split(".")[0].lower()
    for category, keywords in _CATEGORIES.items():
        if any(re.fullmatch(rf"{kw}[-_]?\d*", label) for kw in keywords):
            return category
    return "subdomain"


class DnsDumpsterCollector(BaseCollector):
    name = "DNSDumpster"
    tier = 1
    requires_api_key = False
    french_only = False
    request_delay = 1.0

    async def collect(self, target: OsintTarget) -> CollectorResult:
        domain = target.domain.lower()
        self._progress("[DNSDumpster] Starting scan — this may take a while...")
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(_API, params={"q": target.domain})
        except httpx.HTTPError as exc:
            raise RuntimeError(f"DNSDumpster unreachable: {type(exc).__name__}: {exc}") from exc
        if resp.status_code >= 400:
            raise RuntimeError(f"DNSDumpster API error {resp.status_code}")

        text = resp.text.strip()
        lowered = text.lower()
        if lowered.startswith("api count exceeded"):
            logger.warning("DNSDumpster (HackerTarget): daily API quota exceeded")
            return CollectorResult(findings=[], persons=[])
        if lowered.startswith("error"):
            logger.info("DNSDumpster (HackerTarget) error: %s", text[:100])
            return CollectorResult(findings=[], persons=[])

        findings: list[Finding] = []
        seen: set[str] = set()
        for line in text.splitlines():
            parts = line.strip().split(",")
            if len(parts) != 2:
                continue
            hostname, ip = parts[0].strip().lower(), parts[1].strip()
            # real subdomain of the target ("evilexample.com" must not pass)
            if not hostname.endswith("." + domain):
                continue                    # also drops the apex (already in the DNS collector)
            if hostname in seen:
                continue
            seen.add(hostname)

            category = categorize(hostname)
            findings.append(Finding(
                id="",
                severity=Severity.MEDIUM if category in _MEDIUM_CATEGORIES else Severity.INFO,
                category=Category.SUBDOMAIN,
                title=f"Subdomain: {hostname} → {ip}",
                description=f"Subdomain of {target.domain} discovered via passive DNS.",
                affected_asset=hostname,
                source=self.name,
                source_url=f"{_API}?q={target.domain}",
                mitre_attack="T1590.005",
                raw_data={"ip": ip, "category": category},
            ))
            self._progress(finding=findings[-1])

        if len(findings) > _SUMMARY_THRESHOLD:
            findings.append(Finding(
                id="",
                severity=Severity.INFO,
                category=Category.SUBDOMAIN,
                title=f"DNSDumpster: {len(findings)} subdomains discovered for {target.domain}",
                description="Passive DNS enumeration summary.",
                affected_asset=target.domain,
                source=self.name,
                source_url=f"{_API}?q={target.domain}",
                mitre_attack="T1590",
                raw_data={"count": len(findings)},
            ))
            self._progress(finding=findings[-1])

        logger.info("DNSDumpster: %d subdomains for %s", len(seen), target.domain)
        return CollectorResult(findings=findings, persons=[])
