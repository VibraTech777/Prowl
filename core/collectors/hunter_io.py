"""
core/collectors/hunter_io.py — Hunter.io employee e-mail collector (phase 1).

Hunter's domain search is per-domain, so this is a regular domain collector.
Every e-mail with a name also yields an OsintPerson, which feeds the phase 2
person pivot (--pivot). Requires HUNTER_API_KEY.
"""

from __future__ import annotations

import logging
import os

import httpx

from core.collectors.base import BaseCollector
from core.models import (
    Category, CollectorResult, Finding, OsintPerson, OsintTarget, Severity,
)

logger = logging.getLogger(__name__)

_API = "https://api.hunter.io/v2/domain-search"
_TIMEOUT = 15
_HIGH_CONFIDENCE = 80


class HunterCollector(BaseCollector):
    name = "Hunter.io"
    tier = 1                      # key-gated; tier 1 so it also runs in the default "short" mode
    requires_api_key = True
    api_key_env = "HUNTER_API_KEY"

    async def collect(self, target: OsintTarget) -> CollectorResult:
        key = os.getenv(self.api_key_env, "").strip()
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                # Key in the Authorization header, never in the URL (URLs end up in logs)
                resp = await client.get(
                    _API,
                    params={"domain": target.domain, "limit": 100},
                    headers={"Authorization": f"Bearer {key}"},
                )
        except httpx.HTTPError as exc:
            raise RuntimeError(f"Hunter.io unreachable: {type(exc).__name__}: {exc}") from exc

        if resp.status_code == 401:
            raise RuntimeError("Hunter.io: invalid API key")
        if resp.status_code == 429:
            raise RuntimeError("Hunter.io: rate limit exceeded")
        if resp.status_code >= 400:
            raise RuntimeError(f"Hunter.io API error {resp.status_code}")

        emails = (resp.json().get("data") or {}).get("emails") or []

        findings: list[Finding] = []
        persons: list[OsintPerson] = []

        for e in emails:
            email = e.get("value") or ""
            if not email:
                continue
            position = e.get("position") or ""
            confidence = e.get("confidence") or 0
            findings.append(Finding(
                id="",
                severity=Severity.MEDIUM if confidence >= _HIGH_CONFIDENCE else Severity.INFO,
                category=Category.EMAIL,
                title=f"Employee email: {email} ({position or 'unknown role'})",
                description=(
                    f"Email found by Hunter.io for {target.domain} "
                    f"(confidence {confidence}/100)."
                ),
                affected_asset=email,
                source=self.name,
                source_url=f"https://hunter.io/search/{target.domain}",
                mitre_attack="T1589.002",
                raw_data=e,
            ))

            full_name = f"{e.get('first_name') or ''} {e.get('last_name') or ''}".strip()
            if full_name:
                persons.append(OsintPerson(
                    full_name=full_name, role=position, email=email, source=self.name,
                ))

        logger.info("Hunter.io: %d emails, %d persons for %s",
                    len(findings), len(persons), target.domain)
        return CollectorResult(findings=findings, persons=persons)
