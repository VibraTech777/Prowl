"""
core/collectors/github_gitleak.py — Real e-mail address from a GitHub user's public commits.

Every git commit carries the author's e-mail (git config user.email). For a person whose
GitHub login is known (org member found by GitHub Org), this collector reads it from the
author's most recent public commits:

    GET /users/{login}/repos?sort=pushed&per_page=5
    GET /repos/{login}/{repo}/commits?author={login}&per_page=1      (per repo, until found)

GitHub's own noreply addresses are ignored. The first real address wins and is stored in
person.email: unlike the EmailFormat guess, it was published by the person themselves
(git config is self-declared, but it is attached to the account's own commits).

GITHUB_TOKEN is optional and read on every call (collectors are built before load_dotenv()).
Semi-active: requests appear in GitHub's API logs.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re

import httpx

from core.collectors.base import BasePersonCollector
from core.models import (
    Category, CollectorResult, Finding, OsintPerson, OsintTarget, Severity,
)

logger = logging.getLogger(__name__)

_API = "https://api.github.com"
_TIMEOUT = 15
_MAX_REPOS = 5

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")
_NOT_REAL_SUFFIXES = (
    "@users.noreply.github.com",          # GitHub's private address
    "@localhost", ".local", ".localdomain",   # unconfigured git: user@MacBook.local
)
_NOT_REAL = {"noreply@github.com"}


def is_real_email(email: str | None) -> bool:
    """A well-formed address that is not GitHub's noreply nor a machine default."""
    email = (email or "").strip().lower()
    if not _EMAIL_RE.match(email) or email in _NOT_REAL:
        return False
    return not email.endswith(_NOT_REAL_SUFFIXES)


class GitLeakCollector(BasePersonCollector):
    name = "GitLeak"
    tier = 1
    requires_api_key = False        # GITHUB_TOKEN optional, raises the rate limit
    api_key_env = "GITHUB_TOKEN"
    request_delay = 0.5
    # Informational: person collectors only ever run during the pivot.
    skip_without_pivot: bool = True

    async def collect_person(self, person: OsintPerson, target: OsintTarget) -> CollectorResult:
        login = (person.github_login or "").strip()
        if not login:                                   # no signal: no request at all
            return CollectorResult(findings=[])

        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        token = os.getenv(self.api_key_env, "").strip()
        if token:
            headers["Authorization"] = f"token {token}"

        found: tuple[str, str, str] | None = None        # (email, repo, commit url)
        self._progress(f"[GitLeak] Starting scan of {person.full_name} — this may take a while...")
        try:
            async with httpx.AsyncClient(headers=headers, timeout=_TIMEOUT) as client:
                resp = await client.get(
                    f"{_API}/users/{login}/repos",
                    params={"sort": "pushed", "per_page": _MAX_REPOS},
                )
                if resp.status_code == 404:
                    logger.warning("GitLeak: GitHub user %s not found", login)
                    return CollectorResult(findings=[])
                self._check(resp)
                repos = [r["name"] for r in (resp.json() or []) if r.get("name")][:_MAX_REPOS]

                for i, repo in enumerate(repos):
                    if i:
                        await asyncio.sleep(self.request_delay)
                    resp = await client.get(
                        f"{_API}/repos/{login}/{repo}/commits",
                        params={"author": login, "per_page": 1},
                    )
                    if resp.status_code in (404, 409, 451):   # gone, empty or blocked repo
                        continue
                    self._check(resp)
                    for item in resp.json() or []:
                        email = ((item.get("commit") or {}).get("author") or {}).get("email")
                        if is_real_email(email):
                            found = (email.strip(), repo, item.get("html_url") or "")
                            break
                    if found:
                        break                                # first real address is enough
        except httpx.HTTPError as exc:
            raise RuntimeError(f"GitLeak unreachable: {type(exc).__name__}: {exc}") from exc

        if found is None:
            logger.info("GitLeak: no real email in the recent commits of %s", login)
            return CollectorResult(findings=[])

        email, repo, commit_url = found
        person.email = email            # published by the person: a confirmed address
        logger.info("GitLeak: real email found for %s (%s)", login, repo)
        finding = Finding(
            id="",
            severity=Severity.MEDIUM,
            category=Category.EMAIL,
            title="Real email found in public commits",
            description=f"{email} — found in commit history of {login}",
            affected_asset=email,
            source=self.name,
            source_url=commit_url or f"https://github.com/{login}/{repo}",
            mitre_attack="T1589.002",        # Gather Victim Identity Information: Email Addresses
            raw_data={"login": login, "repo": repo, "person": person.full_name},
        )
        self._progress(finding=finding)
        return CollectorResult(findings=[finding])

    @staticmethod
    def _check(resp: httpx.Response) -> None:
        if resp.status_code in (403, 429):
            raise RuntimeError("GitHub rate limit exceeded")
        if resp.status_code >= 400:
            raise RuntimeError(f"GitHub API error {resp.status_code}")
