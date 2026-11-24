"""
core/collectors/github_colleagues.py — Colleagues of a GitHub-confirmed person (person pivot, level 2+).

From a person whose GitHub account is CONFIRMED (org member found by GitHub Org, or a profile whose
company field names the target), finds the people who work with them:

  • the public members of the target's GitHub organisation(s) — a domain-confirmed org the person
    belongs to (same rule as GitHub Org: the org's blog / email must be the target's domain);
  • the contributors of that organisation's recent repositories whose profile company field
    names the target (a community contributor without it is NOT a colleague).

Every colleague has a real name, a confirmed GitHub login and becomes an OsintPerson for the NEXT
pivot level; people another source already found are skipped. A name-search hit that is not
confirmed never starts an expansion (it would multiply homonyms).

Runs only when its results can be pivoted (person.depth_found < --pivot) and needs GITHUB_TOKEN
(about 25 requests per person; 60 req/h unauthenticated would be unusable).
"""

from __future__ import annotations

import asyncio
import logging
import os
import time

import httpx

from core.collectors.base import BasePersonCollector
from core.collectors.github_org import GitHubOrgCollector
from core.collectors.github_person import GitHubPersonCollector
from core.models import (
    Category, CollectorResult, Finding, OsintPerson, OsintTarget, Severity,
)

logger = logging.getLogger(__name__)

_API = "https://api.github.com"
_TIMEOUT = 15
_MAX_ORGS_CHECKED = 5        # public orgs of the person looked at
_MAX_ORGS_USED = 2           # domain-confirmed orgs expanded
_MAX_REPOS = 3               # recent repositories whose contributors are read
_MAX_PROFILES = 25           # profile fetches per person
_MAX_COLLEAGUES = 10         # new persons per person
_CACHE_TTL = 600.0           # seconds: several persons of one org share the same lists


class GitHubColleaguesCollector(BasePersonCollector):
    name = "GitHub Colleagues"
    tier = 2
    requires_api_key = True
    api_key_env = "GITHUB_TOKEN"
    request_delay = 1.0

    def __init__(self) -> None:
        self._cache: dict[str, tuple[float, object]] = {}

    def applies_to(self, person: OsintPerson, target: OsintTarget) -> bool:
        # confirmed account only, and only if the colleagues found can still be pivoted on
        return bool(person.github_login) and person.depth_found < target.pivot_depth

    async def collect_person(self, person: OsintPerson, target: OsintTarget) -> CollectorResult:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Authorization": f"token {os.getenv(self.api_key_env, '').strip()}",
        }
        findings: list[Finding] = []
        colleagues: list[OsintPerson] = []
        self._progress(f"[GitHub Colleagues] Looking for colleagues of {person.full_name} "
                       f"(@{person.github_login})...")
        try:
            async with httpx.AsyncClient(headers=headers, timeout=_TIMEOUT) as client:
                orgs = await self._orgs(client, person, target)
                budget = {"profiles": 0}
                seen = {person.github_login.lower()}
                for org in orgs[:_MAX_ORGS_USED]:
                    for login, how in await self._candidates(client, org):
                        if len(colleagues) >= _MAX_COLLEAGUES or budget["profiles"] >= _MAX_PROFILES:
                            break
                        if login.lower() in seen:
                            continue
                        seen.add(login.lower())
                        profile = await self._profile(client, login, budget)
                        name = ((profile or {}).get("name") or "").strip().title()
                        if not profile or profile.get("type") != "User" or not name:
                            continue                            # a bare username is not a person
                        if self.is_known(name):
                            continue                            # already found by another source
                        if how.startswith("contributor") and not GitHubPersonCollector._company_matches(
                                profile.get("company"), target, org):
                            continue                            # a community contributor, not staff
                        colleague, finding = self._colleague(person, target, org, how, name, login, profile)
                        colleagues.append(colleague)
                        findings.append(finding)
                        self._progress(finding=finding)         # shown as soon as it is found
        except httpx.HTTPError as exc:
            raise RuntimeError(f"GitHub unreachable: {type(exc).__name__}") from None

        logger.info("GitHub Colleagues: %d new for %s", len(colleagues), person.full_name)
        return CollectorResult(findings=findings, persons=colleagues)

    # ── GitHub ──────────────────────────────────────────────────────────────

    async def _get(self, client: httpx.AsyncClient, path: str, params: dict | None = None,
                   *, soft: bool = False):
        """JSON of an API call (cached), or None for 404 — and, when `soft`, for any other refusal."""
        key = path + repr(sorted((params or {}).items()))
        hit = self._cache.get(key)
        if hit and time.monotonic() - hit[0] < _CACHE_TTL:
            return hit[1]
        await asyncio.sleep(self.request_delay)
        resp = await client.get(f"{_API}{path}", params=params)
        if resp.status_code in (403, 429) and resp.headers.get("x-ratelimit-remaining") == "0":
            raise RuntimeError("GitHub rate limit exceeded")
        if resp.status_code == 404 or (soft and (resp.status_code >= 400 or resp.status_code == 204)):
            data = None
        elif resp.status_code >= 400:
            raise RuntimeError(f"GitHub API error {resp.status_code}")
        else:
            data = resp.json()
        self._cache[key] = (time.monotonic(), data)
        return data

    async def _orgs(self, client: httpx.AsyncClient, person: OsintPerson, target: OsintTarget) -> list[str]:
        """Domain-confirmed GitHub orgs of the person: the one already known, else their public orgs."""
        if person.github_org:
            return [person.github_org]
        listed = await self._get(client, f"/users/{person.github_login}/orgs", {"per_page": 30}) or []
        confirmed = []
        for item in listed[:_MAX_ORGS_CHECKED]:
            login = item.get("login")
            if not login:
                continue
            data = await self._get(client, f"/orgs/{login}")
            if data and GitHubOrgCollector._domain_confirmed(data, target.domain):
                confirmed.append(data.get("login") or login)
        return confirmed

    async def _candidates(self, client: httpx.AsyncClient, org: str) -> list[tuple[str, str]]:
        """(login, how) — public members first, then contributors of the org's recent repositories."""
        found: list[tuple[str, str]] = []
        members = await self._get(client, f"/orgs/{org}/public_members", {"per_page": 30}) or []
        found += [(m["login"], f"public member of GitHub org {org}")
                  for m in members if m.get("type") == "User" and m.get("login")]
        repos = await self._get(client, f"/orgs/{org}/repos",
                                {"type": "public", "sort": "pushed", "per_page": 10}, soft=True) or []
        for repo in [r for r in repos if not r.get("fork")][:_MAX_REPOS]:
            contributors = await self._get(client, f"/repos/{org}/{repo['name']}/contributors",
                                           {"per_page": 30}, soft=True) or []
            found += [(c["login"], f"contributor of {org}/{repo['name']}")
                      for c in contributors if c.get("type") == "User" and c.get("login")]
        return found

    async def _profile(self, client: httpx.AsyncClient, login: str, budget: dict) -> dict | None:
        budget["profiles"] += 1
        return await self._get(client, f"/users/{login}", soft=True)

    # ── findings ────────────────────────────────────────────────────────────

    def _colleague(self, person: OsintPerson, target: OsintTarget, org: str, how: str, name: str,
                   login: str, profile: dict) -> tuple[OsintPerson, Finding]:
        url = profile.get("html_url") or f"https://github.com/{login}"
        colleague = OsintPerson(
            full_name=name, role=f"colleague ({how})", source=self.name,
            depth_found=person.depth_found + 1, github_login=login, github_org=org)
        finding = Finding(
            id="", severity=Severity.INFO, category=Category.COMPANY_INFO,
            title=f"GitHub colleague: {name} (@{login})",
            description=(f"{name} ({url}) — {how}; found through {person.full_name} "
                         f"(@{person.github_login}). Company field: {profile.get('company') or '—'}. "
                         "A lead for the next pivot level."),
            affected_asset=target.domain, source=self.name, source_url=url,
            mitre_attack="T1589.003",
            raw_data={"login": login, "org": org, "how": how, "found_through": person.github_login,
                      "company": profile.get("company")},
        )
        return colleague, finding
