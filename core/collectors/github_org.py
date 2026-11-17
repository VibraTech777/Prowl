"""
core/collectors/github_org.py — GitHub organization + public members (phase 1).

Looks for the company's public GitHub organization and lists its PUBLIC members.
Members of a domain-confirmed org with a real name become OsintPerson and feed the
person pivot (--pivot). An org matched by name only yields its org finding and nothing else.

GITHUB_TOKEN is optional and read on every call (not in __init__: collectors are
built before cli/main.py runs load_dotenv()). Without it GitHub allows only
60 requests/hour — and this collector can use up to ~30 per run
(8 org candidates + public_members + 20 member profiles).
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
from urllib.parse import urlparse

import httpx

from core.collectors.base import BaseCollector
from core.models import (
    Category, CollectorResult, Finding, OsintPerson, OsintTarget, Severity,
)

logger = logging.getLogger(__name__)

_API = "https://api.github.com"
_TIMEOUT = 15
_MAX_MEMBERS = 20
_MAX_CANDIDATES = 8

# Common GitHub org naming around a company's domain base ("zed" → "zed-labs", "getzed").
_CANDIDATE_FORMATS = (
    "{base}-industries", "{base}hq", "{base}-inc", "{base}-labs",
    "{base}app", "get{base}", "{base}io",
)

# A valid GitHub login: also keeps candidates derived from company names
# (spaces, "&", "/", "..") from ever reaching the URL path.
_LOGIN_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,37}[a-z0-9])?$")


class GitHubOrgCollector(BaseCollector):
    name = "GitHub Org"
    tier = 1
    requires_api_key = False
    api_key_env = "GITHUB_TOKEN"         # optional
    french_only = False
    request_delay = 2.0
    # Up to ~22 GitHub requests per run: only worth it when the person pivot is on.
    # (is_available() takes no target, so the runner reads this flag instead.)
    skip_without_pivot: bool = True

    async def collect(self, target: OsintTarget) -> CollectorResult:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        token = os.getenv(self.api_key_env, "").strip()
        if token:
            headers["Authorization"] = f"token {token}"

        self._progress("[GitHub Org] Starting scan — this may take a while...")
        try:
            async with httpx.AsyncClient(headers=headers, timeout=_TIMEOUT) as client:
                # STEP 1 — find the org. A domain-confirmed org wins immediately; an
                # org that exists but is NOT confirmed is only a fallback (the next
                # candidates may be the real one), kept for intel, never for the pivot.
                org = fallback = None
                org_login = ""
                for i, candidate in enumerate(self._candidates(target)):
                    if i:
                        await asyncio.sleep(self.request_delay)
                    resp = await client.get(f"{_API}/orgs/{candidate}")
                    if resp.status_code == 404:
                        continue
                    self._check(resp)
                    data = resp.json()
                    login = data.get("login") or candidate
                    if self._domain_confirmed(data, target.domain):
                        org, org_login = data, login
                        break
                    if fallback is None:
                        fallback = (data, login)
                if org is None and fallback is not None:
                    org, org_login = fallback
                if org is None:
                    return CollectorResult(findings=[])

                # STEP 2 — public members, ONLY for a domain-confirmed org: an org matched
                # by name alone may be unrelated, and its members must not be profiled.
                # /public_members (not /members): with a token belonging to the org,
                # /members would also list non-public members.
                confirmed = self._domain_confirmed(org, target.domain)
                profiles: list[tuple[str, dict]] = []
                member_findings: list[Finding] = []
                persons: list[OsintPerson] = []
                logins: list[str] = []
                if confirmed:
                    resp = await client.get(
                        f"{_API}/orgs/{org_login}/public_members", params={"per_page": 30})
                    self._check(resp)
                    logins = [
                        m["login"] for m in resp.json()
                        if m.get("type") == "User" and m.get("login")
                    ][:_MAX_MEMBERS]

                for login in logins:
                    await asyncio.sleep(self.request_delay)
                    resp = await client.get(f"{_API}/users/{login}")
                    if resp.status_code == 404:
                        continue
                    self._check(resp)
                    profiles.append((login, resp.json()))
                    # reported as soon as this member's profile has been fetched
                    finding, person = self._member(target, org_login, login, resp.json())
                    member_findings.append(finding)
                    if person is not None:
                        persons.append(person)
                    self._progress(finding=finding)
        except httpx.HTTPError as exc:
            raise RuntimeError(f"GitHub Org unreachable: {type(exc).__name__}: {exc}") from exc

        # STEP 3 — findings and persons
        org_url = f"https://github.com/{org_login}"
        members_note = f", {len(profiles)} members" if confirmed else ""   # not listed otherwise
        findings: list[Finding] = [self._finding(
            target,
            f"GitHub org: {org_login} — {org.get('public_repos', '?')} public repos"
            f"{members_note}",
            f"GitHub organization matching '{target.domain}'. URL: {org_url}."
            + (" Domain confirmed via org profile."
               if confirmed else " Matched by name only — verify manually."),
            org_url, "T1596", {"org": org_login, "domain_confirmed": confirmed},
        )]
        findings.extend(member_findings)
        self._progress(finding=findings[0])           # the org finding needs the member count

        logger.info("GitHub Org: %s — %d members, %d persons", org_login, len(profiles), len(persons))
        return CollectorResult(findings=findings, persons=persons)

    # ── helpers ─────────────────────────────────────────────────────────────

    @staticmethod
    def _candidates(target: OsintTarget) -> list[str]:
        """
        Up to _MAX_CANDIDATES valid, deduplicated org logins, most likely first:
        domain base, company slug, base + common suffixes/prefixes, company slug
        without hyphens (first to be cut when the cap is reached).
        """
        base = re.sub(r"[^a-z0-9-]", "", target.domain.split(".")[0].lower())
        raw = [base]
        slug = ""
        if target.company_name:
            # "Zed Industries" → "zed-industries"; specials ("&", "/", "..") become separators
            slug = re.sub(r"[^a-z0-9]+", "-", target.company_name.lower()).strip("-")
            raw.append(slug)
        if base:
            raw += [fmt.format(base=base) for fmt in _CANDIDATE_FORMATS]
        if slug:
            raw.append(slug.replace("-", ""))

        candidates: list[str] = []
        for c in raw:
            if _LOGIN_RE.match(c) and c not in candidates:
                candidates.append(c)
        return candidates[:_MAX_CANDIDATES]

    def _member(self, target: OsintTarget, org_login: str, login: str,
                profile: dict) -> tuple[Finding, OsintPerson | None]:
        """The finding for one public member, and the person to pivot on (real names only)."""
        real_name = (profile.get("name") or "").strip()
        name = real_name.title() if real_name else login
        note = "" if real_name else " (username only)"
        url = profile.get("html_url") or f"https://github.com/{login}"
        finding = self._finding(
            target,
            f"GitHub org member: {name} (@{login}){note}",
            f"{login} is a public member of GitHub org {org_login}. URL: {url}."
            + (f" Bio: {profile['bio']}" if profile.get("bio") else ""),
            url, "T1596",
            {"login": login, "company": profile.get("company"), "bio": profile.get("bio")},
        )
        person = (
            OsintPerson(full_name=name, role="employee", email="",
                        source=self.name, depth_found=1, github_login=login,
                        github_org=org_login)
            if real_name else None      # a bare username is not a person to pivot on
        )
        return finding, person

    @staticmethod
    def _domain_confirmed(org: dict, domain: str) -> bool:
        """True if the org's blog host or email domain IS the target domain (or a subdomain).

        Host comparison, not substring: "evilzed.dev" must not confirm "zed.dev".
        """
        domain = domain.lower().strip(".")
        hosts = []
        blog = str(org.get("blog") or "").strip().lower()
        if blog:
            hosts.append(urlparse(blog if "://" in blog else f"//{blog}").hostname or "")
        email = str(org.get("email") or "").strip().lower()
        if "@" in email:
            hosts.append(email.rsplit("@", 1)[1])
        return any(h == domain or h.endswith("." + domain) for h in hosts if h)

    @staticmethod
    def _check(resp: httpx.Response) -> None:
        if resp.status_code in (403, 429):
            raise RuntimeError("GitHub rate limit exceeded")
        if resp.status_code >= 400:
            raise RuntimeError(f"GitHub API error {resp.status_code}")

    def _finding(self, target: OsintTarget, title: str, description: str,
                 url: str, mitre: str, raw: dict) -> Finding:
        return Finding(
            id="",
            severity=Severity.INFO,
            category=Category.COMPANY_INFO,
            title=title,
            description=description,
            affected_asset=target.domain,
            source=self.name,
            source_url=url,
            mitre_attack=mitre,
            raw_data=raw,
        )
