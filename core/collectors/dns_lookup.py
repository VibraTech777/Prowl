"""
core/collectors/dns_lookup.py — DNS record collector.

Resolves A, AAAA, MX, TXT, NS records and checks for missing
email security configurations (SPF, DMARC). Tier 1, no API key.
"""

from __future__ import annotations

import logging

import dns.exception
import dns.resolver

from core.collectors.base import BaseCollector
from core.models import Category, CollectorResult, Finding, OsintTarget, Severity

logger = logging.getLogger(__name__)


def _resolve(domain: str, rtype: str) -> list[str]:
    """Return DNS records as strings, empty list on any error."""
    try:
        return [r.to_text() for r in dns.resolver.resolve(domain, rtype)]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.exception.Timeout):
        return []
    except Exception as exc:
        logger.debug("DNS %s lookup failed for %s: %s", rtype, domain, exc)
        return []


class DnsCollector(BaseCollector):
    name = "DNS"
    tier = 1
    requires_api_key = False

    async def collect(self, target: OsintTarget) -> CollectorResult:
        domain = target.domain
        findings: list[Finding] = []

        # -- A / AAAA records (IP resolution) --------------------------------
        a_records = _resolve(domain, "A")
        aaaa_records = _resolve(domain, "AAAA")
        all_ips = a_records + aaaa_records
        if all_ips:
            findings.append(
                Finding(
                    id="",
                    severity=Severity.INFO,
                    category=Category.COMPANY_INFO,
                    title=f"IP addresses for {domain}",
                    description=f"Resolved IPs: {', '.join(all_ips)}",
                    affected_asset=domain,
                    source=self.name,
                    source_url=f"https://dnschecker.org/#A/{domain}",
                    mitre_attack="T1590.005",  # IP Addresses
                    raw_data={"a": a_records, "aaaa": aaaa_records},
                )
            )

        # -- MX records (mail servers) ----------------------------------------
        mx_records = _resolve(domain, "MX")
        if mx_records:
            findings.append(
                Finding(
                    id="",
                    severity=Severity.INFO,
                    category=Category.COMPANY_INFO,
                    title=f"Mail servers for {domain}",
                    description=f"MX records: {', '.join(mx_records)}",
                    affected_asset=domain,
                    source=self.name,
                    source_url=f"https://dnschecker.org/#MX/{domain}",
                    mitre_attack="T1590",
                    raw_data={"mx": mx_records},
                )
            )

        # -- NS records (name servers) ----------------------------------------
        ns_records = _resolve(domain, "NS")
        if ns_records:
            findings.append(
                Finding(
                    id="",
                    severity=Severity.INFO,
                    category=Category.COMPANY_INFO,
                    title=f"Name servers for {domain}",
                    description=f"NS records: {', '.join(ns_records)}",
                    affected_asset=domain,
                    source=self.name,
                    source_url=f"https://dnschecker.org/#NS/{domain}",
                    mitre_attack="T1590",
                    raw_data={"ns": ns_records},
                )
            )

        # -- TXT records → check SPF and DMARC --------------------------------
        txt_records = _resolve(domain, "TXT")
        spf_found = any("v=spf1" in r for r in txt_records)
        if not spf_found:
            findings.append(
                Finding(
                    id="",
                    severity=Severity.HIGH,
                    category=Category.DNS_ISSUE,
                    title=f"Missing SPF record on {domain}",
                    description=(
                        "No SPF (Sender Policy Framework) TXT record found. "
                        "Attackers can send spoofed emails that appear to come "
                        "from this domain."
                    ),
                    affected_asset=domain,
                    source=self.name,
                    source_url=f"https://dnschecker.org/#TXT/{domain}",
                    mitre_attack="T1566.002",  # Phishing
                    raw_data={"txt_records": txt_records},
                )
            )

        dmarc_records = _resolve(f"_dmarc.{domain}", "TXT")
        dmarc_found = any("v=DMARC1" in r for r in dmarc_records)
        if not dmarc_found:
            findings.append(
                Finding(
                    id="",
                    severity=Severity.HIGH,
                    category=Category.DNS_ISSUE,
                    title=f"Missing DMARC record on {domain}",
                    description=(
                        "No DMARC (Domain-based Message Authentication) record found "
                        "at _dmarc." + domain + ". Without DMARC, spoofed emails from "
                        "this domain cannot be blocked or reported by receiving servers."
                    ),
                    affected_asset=f"_dmarc.{domain}",
                    source=self.name,
                    source_url=f"https://dmarcian.com/dmarc-inspector/?domain={domain}",
                    mitre_attack="T1566.002",
                    raw_data={"dmarc_records": dmarc_records},
                )
            )

        logger.info("DNS: %d findings for %s", len(findings), domain)
        return CollectorResult(findings=findings)
