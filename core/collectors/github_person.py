"""
core/collectors/github_person.py — GitHub person collector (person pivot).

Searches GitHub for a person by full name (and by email when known), then
reports the profile, the languages used and suspicious repository names.
A GITHUB_TOKEN is optional but raises the rate limit from 60 to 5000 req/h.

Semi-active: requests appear in GitHub's API logs.
"""

from __future__ import annotations

import logging
import os
import re

import httpx

from core.collectors.base import BasePersonCollector
from core.models import (
    Category, CollectorResult, Finding, OsintPerson, OsintTarget, Severity,
)

logger = logging.getLogger(__name__)

_NAME_ONLY_NOTE = "Name search only — may be homonym. Verify manually."

_API = "https://api.github.com"
_TIMEOUT = 15

# Repo names containing one of these words / compound terms are reported
# (case-insensitive). Whole-word matching: "hotkeys" must not match "keys".
HIGH_REPO_PATTERNS = [
    "credentials", "credential",
    "secrets", "secret-",        # "secret-manager" yes, "secretariat" no
    "api-key", "api-keys",
    "private-key", "private-keys", "private_key", "private_keys",
    "ssh-key", "ssh-keys",
    ".env",                      # ".env", ".env-prod", "project.env"; not ".envoy"
    "backup-", "-backup",
    "token-dump", "token-leak",  # bare "token" is NOT listed: "token-bucket", "jwt-token"…
    "leak", "leaked",
    "dump", "dumper",
    "exploit",
]
# "password" alone is too often a harmless project ("password-generator"): MEDIUM only.
MEDIUM_REPO_PATTERNS = ["password", "passwords"]


def _compile(pattern: str) -> re.Pattern[str]:
    """
    A pattern matches only as a whole word / compound term, never inside a longer word.

    A side of the pattern needs a boundary only if it starts/ends with a letter or
    digit: "-backup" and "secret-" already carry their own hyphen boundary on that
    side. Any non-alphanumeric character (-, _, ., /) counts as a separator.
    """
    left = r"(?<![a-z0-9])" if pattern[0].isalnum() else ""
    right = r"(?![a-z0-9])" if pattern[-1].isalnum() else ""
    return re.compile(f"{left}{re.escape(pattern)}{right}")


_HIGH_REGEXES = [_compile(p) for p in HIGH_REPO_PATTERNS]
_MEDIUM_REGEXES = [_compile(p) for p in MEDIUM_REPO_PATTERNS]


def repo_name_severity(name: str) -> Severity | None:
    """HIGH, MEDIUM, or None if the repository name is not suspicious."""
    name = name.lower()
    if any(rx.search(name) for rx in _HIGH_REGEXES):
        return Severity.HIGH
    if any(rx.search(name) for rx in _MEDIUM_REGEXES):
        return Severity.MEDIUM
    return None


class _Unprocessable(Exception):
    """HTTP 422 — the query itself is not searchable (e.g. name too short)."""


class GitHubPersonCollector(BasePersonCollector):
    name = "GitHub"
    tier = 2
    requires_api_key = False    # token is optional but recommended
    api_key_env = "GITHUB_TOKEN"

    @property
    def request_delay(self) -> float:
        """
        1.5 s with a token, 6.0 s without (stays under GitHub's 10 req/min
        unauthenticated search limit). Read lazily rather than in __init__:
        collectors are instantiated at import time, i.e. BEFORE cli/main.py
        runs load_dotenv(), so a token defined in .env would be missed.
        """
        return 1.5 if os.getenv(self.api_key_env, "").strip() else 6.0

    async def collect_person(
        self, person: OsintPerson, target: OsintTarget
    ) -> CollectorResult:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        token = os.getenv(self.api_key_env, "").strip()
        if token:
            headers["Authorization"] = f"token {token}"

        findings: list[Finding] = []
        seen_logins: set[str] = set()
        self._progress(f"[GitHub] Starting scan of {person.full_name} — this may take a while...")

        try:
            async with httpx.AsyncClient(headers=headers, timeout=_TIMEOUT) as client:
                # 0. Known login (org member found by GitHub Org): direct lookup, no search.
                # A name search could miss the real account or return namesakes.
                if person.github_login:
                    resp = await client.get(f"{_API}/users/{person.github_login}")
                    if resp.status_code == 404:
                        logger.warning("GitHub: login %s of %s not found",
                                       person.github_login, person.full_name)
                        return CollectorResult(findings=[], persons=[])
                    self._check(resp)
                    await self._describe(client, [resp.json()], person, target,
                                         findings, seen_logins)
                    logger.info("GitHub: %d findings for %s (direct lookup)",
                                len(findings), person.full_name)
                    return CollectorResult(findings=findings, persons=[])

                # 1. Search by full name (unconfirmed profiles: INFO only)
                try:
                    users = await self._search(client, f"{person.full_name} type:user", 5)
                except _Unprocessable:
                    return CollectorResult(findings=[], persons=[])
                await self._describe(client, users, person, target, findings, seen_logins)

                # 2. Search by email, when known — token only: unauthenticated,
                # a second search per person exceeds GitHub's 10 searches/min.
                if person.email and not token:
                    logger.debug(
                        "GitHub: no %s — email search skipped for %s (name search only)",
                        self.api_key_env, person.full_name,
                    )
                if person.email and token:
                    try:
                        users = await self._search(client, f"{person.email} in:email", 3)
                    except _Unprocessable:
                        users = []
                    await self._describe(client, users, person, target, findings, seen_logins)
        except httpx.HTTPError as exc:
            raise RuntimeError(f"GitHub unreachable: {type(exc).__name__}: {exc}") from exc

        logger.info("GitHub: %d findings for %s", len(findings), person.full_name)
        return CollectorResult(findings=findings, persons=[])

    # ── HTTP ────────────────────────────────────────────────────────────────

    @staticmethod
    def _check(resp: httpx.Response) -> None:
        if resp.status_code in (403, 429):
            raise RuntimeError("GitHub rate limit exceeded")
        if resp.status_code == 422:
            raise _Unprocessable()
        if resp.status_code >= 400:
            raise RuntimeError(f"GitHub API error {resp.status_code}")

    async def _search(self, client: httpx.AsyncClient, query: str, per_page: int) -> list[dict]:
        resp = await client.get(f"{_API}/search/users", params={"q": query, "per_page": per_page})
        self._check(resp)
        return resp.json().get("items", []) or []

    async def _profile(self, client: httpx.AsyncClient, item: dict) -> dict:
        """Search results lack repo/follower counts and company — fetch them."""
        if "public_repos" in item:
            return item
        resp = await client.get(f"{_API}/users/{item['login']}")
        if resp.status_code == 404:
            return item
        self._check(resp)
        return resp.json()

    async def _repos(self, client: httpx.AsyncClient, login: str) -> list[dict]:
        resp = await client.get(
            f"{_API}/users/{login}/repos", params={"per_page": 30, "sort": "updated"}
        )
        if resp.status_code == 404:
            return []
        self._check(resp)
        return resp.json() or []

    # ── Findings ────────────────────────────────────────────────────────────

    async def _describe(
        self,
        client: httpx.AsyncClient,
        users: list[dict],
        person: OsintPerson,
        target: OsintTarget,
        findings: list[Finding],
        seen_logins: set[str],
    ) -> None:
        for item in users:
            login = item.get("login")
            if not login or login in seen_logins:
                continue
            seen_logins.add(login)

            profile = await self._profile(client, item)
            html_url = profile.get("html_url") or f"https://github.com/{login}"
            # Confirmed = this exact login is a public member of the target's GitHub org
            # (person.github_login / github_org, set by the GitHub Org collector). Any other
            # profile comes from a name search alone and may be a homonym: INFO at most.
            confirmed = bool(person.github_login) and login.lower() == person.github_login.lower()
            org = person.github_org if confirmed else ""
            matches_company = self._company_matches(profile.get("company"), target, org)
            name_only = "" if confirmed else f" {_NAME_ONLY_NOTE}"

            self._add(findings, Finding(
                id="",
                # MEDIUM for a confirmed member of the target's org: severity alone carries
                # the signal (no separate confidence field). The company field is only
                # supporting detail there. Name-only matches stay INFO.
                severity=Severity.MEDIUM if confirmed else Severity.INFO,
                category=Category.COMPANY_INFO,
                title=(
                    f"GitHub profile: {login} ({html_url}) — "
                    f"{profile.get('public_repos', '?')} public repos, "
                    f"{profile.get('followers', '?')} followers"
                    + (" [company match]" if matches_company
                       else " [org member]" if confirmed else "")
                ),
                description=(
                    f"GitHub account matching '{person.full_name}'. URL: {html_url}. "
                    f"Company field: {profile.get('company') or '—'}. "
                    + (f"Confirmed public member of the target's GitHub org"
                       f"{f' ({org})' if org else ''}."
                       if confirmed else
                       "The company field matches the target — likely the same person."
                       if matches_company else
                       "No company match — may be a namesake; verify manually.")
                    + name_only
                ),
                affected_asset=person.full_name,
                source=self.name,
                source_url=html_url,
                mitre_attack="T1596",
                raw_data={"login": login, "company": profile.get("company")},
            ))

            repos = await self._repos(client, login)

            languages: list[str] = []
            for repo in repos:
                lang = repo.get("language")
                if lang and lang not in languages:
                    languages.append(lang)
            if languages:
                self._add(findings, Finding(
                    id="",
                    severity=Severity.INFO,
                    category=Category.TECH_EXPOSURE,
                    title=f"GitHub tech stack for {login}: {', '.join(languages)}",
                    description=f"Languages used in the 30 most recently updated repos of {login}.",
                    affected_asset=person.full_name,
                    source=self.name,
                    source_url=html_url,
                    mitre_attack="T1592",
                    raw_data={"login": login, "languages": languages},
                ))

            for repo in repos:
                repo_name = repo.get("name") or ""
                repo_severity = repo_name_severity(repo_name)
                if repo_severity is not None:
                    self._add(findings, Finding(
                        id="",
                        severity=repo_severity if confirmed else Severity.INFO,
                        category=Category.CODE_LEAK,
                        title=f"Suspicious repo name on GitHub: {login}/{repo_name}",
                        description=(
                            "The repository name suggests credentials, secrets or backups. "
                            "Review its content manually." + name_only
                        ),
                        affected_asset=f"{login}/{repo_name}",
                        source=self.name,
                        source_url=repo.get("html_url") or f"https://github.com/{login}/{repo_name}",
                        mitre_attack="T1552",
                        raw_data={"login": login, "repo": repo_name},
                    ))

    def _add(self, findings: list[Finding], finding: Finding) -> None:
        """Keep a finding and report it at once (the profile is not worth waiting for)."""
        findings.append(finding)
        self._progress(finding=finding)

    @staticmethod
    def _company_matches(company: str | None, target: OsintTarget, org: str = "") -> bool:
        """Does the profile's company field name the target: its domain, company name or GitHub org?"""
        company = (company or "").strip().lstrip("@").strip().lower()   # GitHub prefixes orgs with "@"
        if not company:
            return False
        names = {n.strip().lower() for n in (target.company_name, org) if n and n.strip()}
        return target.domain.lower() in company or any(n in company for n in names)
