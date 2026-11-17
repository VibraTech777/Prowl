"""
core/collectors/opencorporates.py — OpenCorporates company officers (phase 1).

Finds the company in the OpenCorporates registry, then lists its ACTIVE officers.
Each officer becomes an OsintPerson that feeds the person pivot (--pivot).

NOTE: the API now answers HTTP 401 ("Invalid Api Token") without a token, so
this collector needs OPENCORPORATES_API_TOKEN and is skipped ("no key") without it.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
from urllib.parse import quote

import httpx

from core.collectors.base import BaseCollector
from core.models import (
    Category, CollectorResult, Finding, OsintPerson, OsintTarget, Severity,
)

logger = logging.getLogger(__name__)

_API = "https://api.opencorporates.com/v0.4"
_USER_AGENT = "Prowl OSINT / github.com/prowl"
_TIMEOUT = 10
_PER_PAGE_SEARCH = 5
_PER_PAGE_OFFICERS = 20


class OpenCorporatesCollector(BaseCollector):
    name = "OpenCorporates"
    tier = 1
    requires_api_key = True              # the API refuses unauthenticated calls (401)
    api_key_env = "OPENCORPORATES_API_TOKEN"
    french_only = False
    request_delay = 2.0                  # rate limit ~10 req/min

    async def collect(self, target: OsintTarget) -> CollectorResult:
        term = (target.company_name or "").strip() or target.domain.split(".")[0]
        token = os.getenv(self.api_key_env, "").strip()
        base_params = {"api_token": token} if token else {}
        self._progress("[OpenCorporates] Starting scan — this may take a while...")

        try:
            async with httpx.AsyncClient(
                headers={"User-Agent": _USER_AGENT}, timeout=_TIMEOUT
            ) as client:
                # STEP 1 — find the company
                resp = await client.get(
                    f"{_API}/companies/search",
                    params={**base_params, "q": term, "per_page": _PER_PAGE_SEARCH},
                )
                if self._is_soft_stop(resp):
                    return CollectorResult(findings=[])
                companies = [
                    c.get("company", c)
                    for c in (resp.json().get("results") or {}).get("companies") or []
                ]
                company = self._best_match(term, companies)
                if company is None:
                    return CollectorResult(findings=[])

                jurisdiction = company.get("jurisdiction_code") or ""
                number = str(company.get("company_number") or "")
                company_name = company.get("name") or term

                # STEP 2 — its officers (rate limited)
                await asyncio.sleep(self.request_delay)
                resp = await client.get(
                    f"{_API}/companies/{quote(jurisdiction, safe='')}/{quote(number, safe='')}/officers",
                    params={**base_params, "per_page": _PER_PAGE_OFFICERS},
                )
                officers: list[dict] = []
                if resp.status_code != 404:
                    if self._is_soft_stop(resp):
                        return CollectorResult(findings=[])
                    officers = [
                        o.get("officer", o)
                        for o in (resp.json().get("results") or {}).get("officers") or []
                    ]
        except httpx.HTTPError as exc:
            raise RuntimeError(
                f"OpenCorporates unreachable: {type(exc).__name__}: {exc}"
            ) from exc

        # STEP 3 — findings and persons
        url = company.get("opencorporates_url") or (
            f"https://opencorporates.com/companies/{jurisdiction}/{number}")
        findings: list[Finding] = [self._finding(
            target, f"OpenCorporates: {company_name} ({jurisdiction})",
            f"Company number: {number}. Jurisdiction: {jurisdiction}.", url,
            {"company_number": number, "jurisdiction_code": jurisdiction},
        )]
        self._progress(finding=findings[0])
        persons: list[OsintPerson] = []

        for o in officers:
            if o.get("end_date"):                       # no longer active
                continue
            raw_name = (o.get("name") or "").strip()
            if not raw_name:
                continue
            name = raw_name.title()
            position = (o.get("position") or "").strip()
            persons.append(OsintPerson(
                full_name=name, role=position, email="", source=self.name, depth_found=1,
            ))
            findings.append(self._finding(
                target, f"Officer: {name} ({position or 'officer'})",
                f"{name} is listed as {position or 'officer'} at {company_name} on OpenCorporates.",
                url, {"officer": o},
            ))
            self._progress(finding=findings[-1])

        logger.info("OpenCorporates: %d officers for %s", len(persons), company_name)
        return CollectorResult(findings=findings, persons=persons)

    # ── helpers ─────────────────────────────────────────────────────────────

    def _is_soft_stop(self, resp: httpx.Response) -> bool:
        """True → stop quietly with an empty result; raises on real errors."""
        if resp.status_code == 429:
            logger.warning("OpenCorporates rate limit hit")
            return True
        if resp.status_code == 404:
            return True
        if resp.status_code in (401, 403):
            raise RuntimeError(
                f"OpenCorporates: invalid or missing API token (HTTP {resp.status_code})")
        if resp.status_code >= 400:
            raise RuntimeError(f"OpenCorporates API error {resp.status_code}")
        return False

    @staticmethod
    def _score(term: str, name: str) -> float:
        """Exact name = 1.0; term as a whole word inside the name = 0.5; else 0."""
        t, n = term.casefold().strip(), (name or "").casefold().strip()
        if not t or not n:
            return 0.0
        if t == n:
            return 1.0
        # whole word, not a substring of a longer word ("zed" must not match "zeddy")
        if re.search(rf"(?<![a-z0-9]){re.escape(t)}(?![a-z0-9])", n):
            return 0.5
        return 0.0

    def _best_match(self, term: str, companies: list[dict]) -> dict | None:
        best, best_score = None, 0.0
        for c in companies:
            score = self._score(term, c.get("name", ""))
            if score > best_score:
                best, best_score = c, score
        return best

    def _finding(self, target: OsintTarget, title: str, description: str,
                 url: str, raw: dict) -> Finding:
        return Finding(
            id="",
            severity=Severity.INFO,
            category=Category.COMPANY_INFO,
            title=title,
            description=description,
            affected_asset=target.domain,
            source=self.name,
            source_url=url,
            mitre_attack="T1591.001",
            raw_data=raw,
        )
