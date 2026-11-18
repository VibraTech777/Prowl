"""
core/collectors/whatsmyname.py — Username lookup on social / coding / tech platforms (person pivot).

For a person whose GitHub login is known, checks whether the same username exists on the
platforms listed in the WhatsMyName project (https://github.com/WebBreacher/WhatsMyName).
The list is downloaded once per process and filtered to a few categories.

A site check, as WhatsMyName defines it: GET uri_check with {account} replaced; the profile
exists if the status is the expected one (e_code, usually 200), the body contains e_string
(when given) and does NOT contain m_string (the "no such user" marker).

Sites whose check URL is a free-text SEARCH (?q={account}, ?inname={account}…) answer 200 for
fuzzy matches too (a substring of a display name, an unrelated account). For those, the hit is
kept only if the username appears in the response as a whole word (see is_search_style /
contains_whole_word). Exact-profile checks are not affected.

A username match is NOT an identity match: the same login on another site may belong to
someone else. Findings say so; severity is only a hint about the kind of platform.

Semi-active: every checked platform receives one request containing the username.
The list uses the current field names (cat, e_code, e_string, m_string) — the legacy names
(category, account_existence_code, account_missing_string) are accepted too.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from urllib.parse import parse_qsl, quote, urlparse

import httpx

from core.collectors.base import BasePersonCollector
from core.models import (
    Category, CollectorResult, Finding, OsintPerson, OsintTarget, Severity,
)

logger = logging.getLogger(__name__)

WMN_URL = "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json"
ALLOWED_CATEGORIES = {"social", "coding", "professional", "business", "tech"}
# "business" is the real list's category for professional sites; "professional" is kept
# for older list versions. Profiles found there are MEDIUM, the others INFO.
PROFESSIONAL_CATEGORIES = {"professional", "business"}
# Sites whose result GitHubPersonCollector already reports, with the same URL and more
# detail (checked live: "GitHub (User)" → https://github.com/<login>, i.e. the profile finding
# with repos, followers, languages). "GitHub (Gists)" is NOT excluded: other URL, other data.
EXCLUDED_SITES = {"GitHub (User)"}

# Query parameters that carry a free-text search term. Deliberately NOT "username": exact lookups
# such as HudsonRock or the OTX validator use it and their answer does not repeat the username.
_SEARCH_PARAMS = frozenset({"q", "query", "search", "inname", "term", "keyword", "user_nick"})

_LIST_TIMEOUT = 20
_SITE_TIMEOUT = 5            # slow sites are skipped
_CONCURRENCY = 5
_MAX_BODY = 256 * 1024       # never read more than this from a profile page
_HEADERS = {"User-Agent": "Prowl OSINT / github.com/prowl"}


def is_search_style(site: dict) -> bool:
    """True if the check URL puts {account} into a free-text search parameter (fuzzy matching)."""
    url = site.get("uri_check") or site.get("check_uri") or ""
    return any(
        key.lower() in _SEARCH_PARAMS and "{account}" in value
        for key, value in parse_qsl(urlparse(url).query, keep_blank_values=True)
    )


def contains_whole_word(text: str, word: str) -> bool:
    """
    Case-insensitive: `word` appears in `text` as a whole username, not inside a longer one.
    Letters, digits, "_" and "-" glue to the word ("usulpro-fan" is another account), and so
    does a "." between two alphanumerics ("john.smith"), but a sentence-ending "." does not.
    """
    pattern = (
        r"(?<![A-Za-z0-9_-])(?<![A-Za-z0-9]\.)"
        + re.escape(word)
        + r"(?![A-Za-z0-9_-])(?!\.[A-Za-z0-9])"
    )
    return re.search(pattern, text, re.IGNORECASE) is not None


def select_sites(data: dict) -> list[dict]:
    """Sites to check: allowed category, not flagged invalid, plain GET (no POST body)."""
    selected = []
    for s in data.get("sites", []) or []:
        category = s.get("cat", s.get("category"))
        url = s.get("uri_check") or s.get("check_uri") or ""
        if (
            category in ALLOWED_CATEGORIES
            and s.get("name") not in EXCLUDED_SITES
            and s.get("valid", True) is not False
            and not s.get("post_body")
            and "{account}" in url
            and urlparse(url).scheme in ("http", "https")
        ):
            selected.append(s)
    return selected


class WhatsMyNameCollector(BasePersonCollector):
    name = "WhatsMyName"
    tier = 1
    requires_api_key = False
    request_delay = 0.3
    skip_without_pivot: bool = True      # informational: person collectors only run in the pivot

    def __init__(self) -> None:
        self._sites: list[dict] | None = None     # downloaded once, then reused
        self._load_error: str = ""

    async def collect_person(self, person: OsintPerson, target: OsintTarget) -> CollectorResult:
        login = (person.github_login or "").strip()
        if not login:                                   # no signal: no request at all
            return CollectorResult(findings=[])

        sites = await self._load_sites()
        sem = asyncio.Semaphore(_CONCURRENCY)       # stability over speed: do not raise
        stats = {"error": 0}
        self._progress(f"[WhatsMyName] Checking {login} across {len(sites)} platforms "
                       "— this may take a while...")

        async with httpx.AsyncClient(
            headers=_HEADERS, timeout=_SITE_TIMEOUT, follow_redirects=False,
            limits=httpx.Limits(max_connections=_CONCURRENCY),
        ) as client:
            # Each confirmed profile is reported by _check() the moment it is found;
            # gather() only keeps the results in the list's order for the CollectorResult.
            results = await asyncio.gather(
                *(self._check(client, sem, site, person, login, stats) for site in sites)
            )

        findings = [f for f in results if f is not None]
        logger.info("WhatsMyName: %s found on %d/%d sites (%d unreachable/slow)",
                    login, len(findings), len(sites), stats["error"])
        return CollectorResult(findings=findings)

    # ── site list ───────────────────────────────────────────────────────────

    async def _load_sites(self) -> list[dict]:
        if self._sites is not None:
            return self._sites
        if self._load_error:                             # do not re-download for every person
            raise RuntimeError(self._load_error)
        try:
            async with httpx.AsyncClient(headers=_HEADERS, timeout=_LIST_TIMEOUT) as client:
                resp = await client.get(WMN_URL)
            if resp.status_code != 200:
                raise RuntimeError(f"WhatsMyName list HTTP {resp.status_code}")
            self._sites = select_sites(json.loads(resp.text))
        except httpx.HTTPError as exc:
            self._load_error = f"WhatsMyName list unreachable: {type(exc).__name__}: {exc}"
            raise RuntimeError(self._load_error) from exc
        except ValueError as exc:                        # invalid JSON
            self._load_error = f"WhatsMyName list is not valid JSON: {exc}"
            raise RuntimeError(self._load_error) from exc
        except RuntimeError as exc:
            self._load_error = str(exc)
            raise
        logger.info("WhatsMyName: %d platforms selected (categories: %s)",
                    len(self._sites), ", ".join(sorted(ALLOWED_CATEGORIES)))
        return self._sites

    # ── one platform ────────────────────────────────────────────────────────

    async def _check(self, client: httpx.AsyncClient, sem: asyncio.Semaphore,
                     site: dict, person: OsintPerson, login: str, stats: dict) -> Finding | None:
        """Check one platform; on a hit, report the finding immediately and return it."""
        template = site.get("uri_check") or site.get("check_uri")
        url = template.replace("{account}", quote(login, safe=""))
        expected = site.get("e_code", site.get("account_existence_code", 200))
        present = site.get("e_string") or site.get("account_existence_string") or ""
        missing = site.get("m_string") or site.get("account_missing_string") or ""

        async with sem:
            try:
                async with client.stream("GET", url, headers=site.get("headers") or None) as resp:
                    if resp.status_code != expected:
                        return None
                    body = b""
                    async for chunk in resp.aiter_bytes():
                        body += chunk
                        if len(body) >= _MAX_BODY:
                            break
            except httpx.HTTPError as exc:               # slow / dead site: skip, but counted
                stats["error"] += 1
                logger.debug("WhatsMyName: %s skipped (%s)", site.get("name"), type(exc).__name__)
                return None
            finally:
                await asyncio.sleep(self.request_delay)

        text = body[:_MAX_BODY].decode("utf-8", "replace")      # a chunk may overshoot the cap
        if present and present not in text:
            return None
        if missing and missing in text:
            return None
        if is_search_style(site) and not contains_whole_word(text, login):
            return None                      # a fuzzy search hit, not this username
        profile_url = site.get("uri_pretty", "").replace("{account}", quote(login, safe="")) or url
        finding = self._finding(person, login, site, profile_url)
        self._progress(finding=finding)                  # shown now, not at the end of the run
        return finding

    def _finding(self, person: OsintPerson, login: str, site: dict, url: str) -> Finding:
        category = site.get("cat", site.get("category"))
        return Finding(
            id="",
            severity=Severity.MEDIUM if category in PROFESSIONAL_CATEGORIES else Severity.INFO,
            category=Category.COMPANY_INFO,
            title=f"Username '{login}' found on {site.get('name')}",
            description=f"{url} — same username only, may be a different person. Verify manually.",
            affected_asset=person.full_name,
            source=self.name,
            source_url=url,
            mitre_attack="T1593.001",           # Search Open Websites/Domains: Social Media
            raw_data={"login": login, "site": site.get("name"), "category": category, "url": url},
        )
