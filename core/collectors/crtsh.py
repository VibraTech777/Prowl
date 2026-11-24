"""
core/collectors/crtsh.py — Certificate Transparency log collector.

Queries crt.sh to discover subdomains via SSL/TLS certificate logs.
No API key required. Tier 1.
"""

from __future__ import annotations

import asyncio
import logging
import re

import httpx

from core.collectors.base import BaseCollector
from core.models import Category, CollectorResult, Finding, OsintTarget, Severity

logger = logging.getLogger(__name__)

_MAX_RETRIES = 3
_RETRY_DELAY = 5  # seconds; the wait grows linearly: 5 s after attempt 1, 10 s after attempt 2, …
# crt.sh answers a fresh query in 5-30+ s (then in <1 s, from its cache) and returns passing 502s: a
# short timeout or backoff fails exactly the request that would have succeeded. Phase 1 runs
# concurrently, so the wait is hidden behind the slower collectors.
_REQUEST_TIMEOUT = 45  # seconds per attempt

# Subdomains containing these keywords are escalated to MEDIUM severity
# because they often expose dev/staging environments or admin interfaces.
_SENSITIVE_KEYWORDS = {
    "admin", "dev", "staging", "test", "preprod", "pre-prod",
    "internal", "intranet", "vpn", "api", "portal", "dashboard",
    "backup", "old", "legacy", "beta",
}

def _is_sensitive(host: str, domain: str) -> bool:
    """
    True if the FIRST (leftmost) label of `host` contains a sensitive keyword.

    Only that label counts: "dev.x.fr" is MEDIUM, but "17849-fix.preprod-dev.x.fr" is not
    (thousands of review apps hang under one environment zone; the zone is not repeated
    as a finding per host). The label is split on "-" and compared by whole parts, never
    as substrings: a part matches ^keyword\\d*$ (keyword optionally followed by digits), so
    "dev", "dev01" and "staging-api" match; "device" and "gold" do not.
    The target domain's own labels are excluded ("api.io" must not flag every host), and
    so is the apex. A hyphenated keyword ("pre-prod") matches as consecutive parts.
    """
    host, domain = host.lower(), domain.lower()
    prefix = host[: -len(domain)] if host.endswith(domain) else host
    first_label = prefix.lstrip(".").split(".")[0]
    labels = [x for x in first_label.split("-") if x]
    for keyword in _SENSITIVE_KEYWORDS:
        parts = keyword.split("-")
        n = len(parts)
        last = re.compile(re.escape(parts[-1]) + r"\d*")        # keyword + optional digits
        if any(
            labels[i:i + n - 1] == parts[:-1] and last.fullmatch(labels[i + n - 1])
            for i in range(len(labels) - n + 1)
        ):
            return True
    return False


_CRT_URL = "https://crt.sh/?q=%.{domain}&output=json"


class CrtshCollector(BaseCollector):
    name = "crt.sh"
    tier = 1
    requires_api_key = False

    async def collect(self, target: OsintTarget) -> CollectorResult:
        data: list = []
        self._progress("[crt.sh] Starting scan — this may take a while...")
        for attempt in range(_MAX_RETRIES):
            try:
                async with httpx.AsyncClient(timeout=_REQUEST_TIMEOUT) as client:
                    resp = await client.get(
                        _CRT_URL.format(domain=target.domain),
                        headers={"Accept": "application/json"},
                        follow_redirects=True,
                    )
                    resp.raise_for_status()
                    data = resp.json()
                break  # success — exit retry loop
            except Exception as exc:
                logger.warning(
                    "crt.sh attempt %d/%d failed for %s (%s: %s)",
                    attempt + 1, _MAX_RETRIES,
                    target.domain, type(exc).__name__, exc,
                )
                if attempt < _MAX_RETRIES - 1:
                    self._progress(
                        f"[crt.sh] Attempt {attempt + 1}/{_MAX_RETRIES} failed "
                        f"({type(exc).__name__}) — retrying in {_RETRY_DELAY * (attempt + 1)}s...")
                    await asyncio.sleep(_RETRY_DELAY * (attempt + 1))
        else:
            raise RuntimeError(
                f"crt.sh unreachable after {_MAX_RETRIES} attempts for {target.domain}"
            )

        # Collect unique, clean subdomain names
        seen: set[str] = set()
        subdomains: list[str] = []
        for entry in data:
            for name in entry.get("name_value", "").splitlines():
                name = name.strip().lstrip("*.")
                if (
                    name
                    and (name == target.domain or name.endswith("." + target.domain))
                    and name not in seen
                ):
                    seen.add(name)
                    subdomains.append(name)

        findings: list[Finding] = []
        for sub in subdomains:
            sensitive = _is_sensitive(sub, target.domain)
            findings.append(
                Finding(
                    id="",  # assigned by exporter
                    severity=Severity.MEDIUM if sensitive else Severity.INFO,
                    category=Category.SUBDOMAIN,
                    title=f"Subdomain discovered: {sub}",
                    description=(
                        "Found in Certificate Transparency logs. "
                        + (
                            "Keyword suggests a non-production environment that may "
                            "have weaker security controls."
                            if sensitive
                            else "Passive discovery — no active probing performed."
                        )
                    ),
                    affected_asset=sub,
                    source=self.name,
                    source_url=f"https://crt.sh/?q={sub}",
                    mitre_attack="T1596.003",  # Search Open Websites — Certificate Transparency
                    raw_data={"name_value": sub},
                )
            )
            self._progress(finding=findings[-1])      # shown as soon as it is built

        logger.info("crt.sh: found %d subdomains for %s", len(findings), target.domain)
        return CollectorResult(findings=findings)
