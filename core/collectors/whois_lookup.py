"""
core/collectors/whois_lookup.py — WHOIS registration data collector.

Retrieves domain registration details: registrar, creation/expiry dates,
and name servers. Flags domains expiring soon. Tier 1, no API key.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

import whois

from core.collectors.base import BaseCollector
from core.models import Category, CollectorResult, Finding, OsintTarget, Severity

logger = logging.getLogger(__name__)


def _to_datetime(value: object) -> datetime | None:
    """Normalize WHOIS date fields — they can be a datetime, a list, or None."""
    if isinstance(value, list):
        value = value[0]
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value
    return None


class WhoisCollector(BaseCollector):
    name = "WHOIS"
    tier = 1
    requires_api_key = False

    async def collect(self, target: OsintTarget) -> CollectorResult:
        try:
            w = await asyncio.to_thread(whois.whois, target.domain)
        except Exception as exc:
            logger.warning(
                "WHOIS failed for %s (%s: %s)",
                target.domain, type(exc).__name__, exc,
            )
            return CollectorResult(findings=[])

        findings: list[Finding] = []
        now = datetime.now(timezone.utc)

        registrar = w.registrar or "unknown"
        creation = _to_datetime(w.creation_date)
        expiration = _to_datetime(w.expiration_date)
        name_servers = [ns.lower() for ns in (w.name_servers or [])]

        # Always emit a base info finding with registration details
        findings.append(
            Finding(
                id="",
                severity=Severity.INFO,
                category=Category.COMPANY_INFO,
                title=f"Domain registration info: {target.domain}",
                description=(
                    f"Registrar: {registrar}. "
                    f"Created: {creation.date() if creation else 'unknown'}. "
                    f"Expires: {expiration.date() if expiration else 'unknown'}. "
                    f"Name servers: {', '.join(name_servers) or 'none found'}."
                ),
                affected_asset=target.domain,
                source=self.name,
                source_url=f"https://lookup.icann.org/lookup?name={target.domain}",
                mitre_attack="T1596.002",  # Search WHOIS
                raw_data={
                    "registrar": registrar,
                    "creation_date": str(creation),
                    "expiration_date": str(expiration),
                    "name_servers": name_servers,
                },
            )
        )

        # Flag expiring domains
        if expiration:
            days_left = (expiration - now).days
            if days_left < 30:
                findings.append(
                    Finding(
                        id="",
                        severity=Severity.HIGH,
                        category=Category.DNS_ISSUE,
                        title=f"Domain expires in {days_left} days",
                        description=(
                            f"{target.domain} expires on {expiration.date()}. "
                            "An expired domain can be snatched by attackers "
                            "for phishing or malware distribution."
                        ),
                        affected_asset=target.domain,
                        source=self.name,
                        source_url=f"https://lookup.icann.org/lookup?name={target.domain}",
                        mitre_attack="T1584.001",
                        raw_data={"days_left": days_left},
                    )
                )
            elif days_left < 90:
                findings.append(
                    Finding(
                        id="",
                        severity=Severity.MEDIUM,
                        category=Category.DNS_ISSUE,
                        title=f"Domain expires in {days_left} days",
                        description=(
                            f"{target.domain} expires on {expiration.date()}. "
                            "Consider renewing to avoid accidental expiry."
                        ),
                        affected_asset=target.domain,
                        source=self.name,
                        source_url=f"https://lookup.icann.org/lookup?name={target.domain}",
                        mitre_attack="T1584.001",
                        raw_data={"days_left": days_left},
                    )
                )

        logger.info("WHOIS: %d findings for %s", len(findings), target.domain)
        return CollectorResult(findings=findings)
