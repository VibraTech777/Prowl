"""
core/collectors/google_dorks.py — Google dorks (site:, filetype:, inurl:, intitle:) through SerpAPI.

Runs a short, fixed list of search-engine queries about the target domain and reports what Google
has indexed: documents, config / backup / log files, directory listings, admin and login pages,
error messages, API docs, extra subdomains, and mentions of the domain on Pastebin and GitHub.

Passive with respect to the target: only SerpAPI (a third party) receives the queries, the target
never sees a request. Every result is "indexed by Google", NOT verified: the findings say so.

Needs SERPAPI_API_KEY (free plan: 250 searches/month, so ~25 scans: one scan = len(DORKS) queries;
SerpAPI does not charge for a repeated identical query within an hour). Google's own Custom Search
JSON API is closed to new customers and ends on 2027-01-01, hence SerpAPI.

The API key travels in the URL (SerpAPI's only way): it is never logged, never put in a finding,
and error messages carry the exception type only.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
from dataclasses import dataclass
from urllib.parse import urlparse

import httpx

from core.collectors.base import BaseCollector, CollectorSkipped
from core.crawler.link_scorer import score_url
from core.models import Category, CollectorResult, Finding, OsintTarget, Severity

logger = logging.getLogger(__name__)

_API = "https://serpapi.com/search.json"
_TIMEOUT = 30
_RESULTS_PER_QUERY = 10
_DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$")

_DOC_EXTS = frozenset({"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx"})
_SENSITIVE_EXTS = frozenset({"sql", "bak", "log", "conf", "env", "ini", "cfg", "old", "swp"})
# A credential being SET to a literal ("password: x", "TOKEN=abc", "api_key": "…"), not merely the
# word, and not read from somewhere ("$password = $cred.Password", "token = os.getenv(…)", "{{ x }}").
_SECRET_ASSIGNMENT = re.compile(
    r"(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|credentials?)[\"']?\s*[:=]\s*+"       # possessive: no backtracking into the lookahead
    r"(?![`$({<%]|(?:os\.)?getenv|os\.environ|process\.env)", re.IGNORECASE)
_PRIVATE_KEY = re.compile(r"BEGIN [A-Z ]*PRIVATE KEY", re.IGNORECASE)
_NEAR = 80                   # chars: the domain and the credential must sit this close in the snippet
# Files that exist to hold secrets or configuration: a mention of the target in one of them counts
_SECRET_FILES = frozenset({
    ".env", "credentials", "secrets", "secret", "id_rsa", ".htpasswd", ".git-credentials",
    "wp-config.php", "settings.py", "application.properties", "database.yml", "config.json",
    "config.php", "config.yml", "config.yaml", "config.ini",
})
_ADMIN_SCORE = 70            # an indexed URL whose path scores this much (admin, backup…) → MEDIUM


@dataclass(frozen=True)
class Dork:
    key: str
    label: str               # start of the finding title
    query: str               # {d} = the target domain
    category: Category


def _any(op: str, *values: str) -> str:
    return "(" + " OR ".join(f"{op}:{v}" for v in values) + ")"


DORKS: tuple[Dork, ...] = (
    Dork("documents", "Indexed document",
         f"site:{{d}} {_any('filetype', *sorted(_DOC_EXTS))}", Category.WEB_FINDING),
    Dork("sensitive_files", "Indexed sensitive file",
         f"site:{{d}} {_any('filetype', *sorted(_SENSITIVE_EXTS))}", Category.CODE_LEAK),
    Dork("directory_listing", "Indexed directory listing",
         'site:{d} intitle:"index of /"', Category.WEB_FINDING),
    Dork("admin_login", "Indexed admin / login page",
         f"site:{{d}} {_any('inurl', 'admin', 'login', 'signin', 'portal', 'dashboard')}",
         Category.WEB_FINDING),
    Dork("debug_backup", "Indexed debug / backup / staging page",
         f"site:{{d}} {_any('inurl', 'phpinfo', 'debug', 'backup', 'staging')}", Category.WEB_FINDING),
    Dork("errors", "Indexed error message",
         'site:{d} (intext:"sql syntax near" OR intext:"Warning: mysql" OR intext:"Fatal error" '
         'OR intext:"Traceback (most recent call last)")', Category.WEB_FINDING),
    Dork("api_docs", "Indexed API documentation",
         f"site:{{d}} {_any('inurl', 'swagger', 'api-docs', 'graphql', 'openapi')}", Category.WEB_FINDING),
    Dork("subdomains", "Subdomain discovered (Google)", "site:*.{d} -site:www.{d}", Category.SUBDOMAIN),
    Dork("pastebin", "Pastebin mention", 'site:pastebin.com "{d}"', Category.CODE_LEAK),
    Dork("github", "GitHub code mention",
         'site:github.com "{d}" (password OR secret OR token OR "api_key")', Category.CODE_LEAK),
)


class _SearchFailed(Exception):
    """A search could not be completed: `quota` tells apart "stop, try later" from a bad setup."""

    def __init__(self, reason: str, quota: bool = False):
        super().__init__(reason)
        self.quota = quota


class GoogleDorksCollector(BaseCollector):
    name = "Google Dorks"
    tier = 1
    requires_api_key = True
    api_key_env = "SERPAPI_API_KEY"
    request_delay = 1.0

    async def collect(self, target: OsintTarget) -> CollectorResult:
        domain = target.domain.strip().lower()
        if not _DOMAIN_RE.match(domain):
            raise CollectorSkipped("the domain cannot be used in a search query")
        key = os.getenv(self.api_key_env, "").strip()

        self._progress(f"[Google Dorks] Starting scan — {len(DORKS)} queries via SerpAPI "
                       "(this may take a while...)")
        findings: list[Finding] = []
        seen: set[str] = set()                    # a URL found by two dorks is reported once

        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            for i, dork in enumerate(DORKS):
                if i:
                    await asyncio.sleep(self.request_delay)
                query = dork.query.format(d=domain)
                try:
                    results = await self._search(client, key, query)
                except _SearchFailed as exc:
                    if i == 0:                      # nothing worked: a failure, not a partial run
                        raise RuntimeError(f"Google Dorks: {exc}") from None
                    logger.warning("Google Dorks stopped after %d/%d queries: %s", i, len(DORKS), exc)
                    findings.append(self._incomplete(domain, i, str(exc)))
                    self._progress(finding=findings[-1])
                    break
                for result in results:
                    finding = self._classify(dork, query, result, domain)
                    if finding is not None and finding.affected_asset not in seen:
                        seen.add(finding.affected_asset)
                        findings.append(finding)
                        self._progress(finding=finding)

        logger.info("Google Dorks: %d findings for %s", len(findings), domain)
        return CollectorResult(findings=findings)

    # ── SerpAPI ─────────────────────────────────────────────────────────────

    async def _search(self, client: httpx.AsyncClient, key: str, query: str) -> list[dict]:
        params = {"engine": "google", "q": query, "num": _RESULTS_PER_QUERY, "hl": "en",
                  "api_key": key}
        try:
            resp = await client.get(_API, params=params)
        except httpx.HTTPError as exc:
            # type name only: some httpx messages embed the URL, and the URL holds the key
            raise _SearchFailed(f"SerpAPI unreachable: {type(exc).__name__}") from None
        try:
            data = resp.json()
        except ValueError:
            data = {}
        error = str(data.get("error", "")) if isinstance(data, dict) else ""
        lowered = error.lower()

        # SerpAPI answers an empty search with 200 + "Google hasn't returned any results for this
        # query." in `error`: that is an empty answer, not a failure (any wording of it)
        if resp.status_code == 200 and any(w in lowered for w in ("any results", "no results", "hasn't returned")):
            return []
        if resp.status_code == 429 or any(w in lowered for w in ("run out of searches", "limit", "quota")):
            raise _SearchFailed("SerpAPI quota exhausted", quota=True)
        if resp.status_code in (401, 403) or "api key" in lowered:
            raise _SearchFailed("SerpAPI rejected the API key (check SERPAPI_API_KEY)")
        if resp.status_code >= 400 or error:
            raise _SearchFailed(f"SerpAPI error {resp.status_code}")
        results = data.get("organic_results") if isinstance(data, dict) else None
        return [r for r in (results or []) if isinstance(r, dict)]

    # ── results → findings ──────────────────────────────────────────────────

    def _classify(self, dork: Dork, query: str, result: dict, domain: str) -> Finding | None:
        link = str(result.get("link") or "").strip()
        parsed = urlparse(link)
        host = (parsed.hostname or "").lower()
        if parsed.scheme not in ("http", "https") or not host:
            return None
        title = str(result.get("title") or "")
        snippet = str(result.get("snippet") or "")
        in_scope = host == domain or host.endswith("." + domain)
        shown = (host + parsed.path if host != domain else parsed.path or "/")[:110]
        severity, label = Severity.INFO, f"{dork.label}: {shown}"

        if dork.key in ("pastebin", "github"):                 # a third party's page about the target
            if domain not in f"{title} {snippet} {link}".lower():
                return None
            # The dork itself asks for password/token/…, so the bare words prove nothing: MEDIUM
            # only if a credential is set right next to the domain, a private key is shown, or the
            # page is a secrets / config file.
            if _leaks_a_credential(domain, f"{title} {snippet}") or _is_secret_file(parsed.path):
                severity = Severity.MEDIUM
        else:                                                   # site: queries answer about the target
            if not in_scope:
                return None
            if dork.key == "documents":
                if _ext(parsed.path) not in _DOC_EXTS:
                    return None
            elif dork.key == "sensitive_files":
                if _ext(parsed.path) not in _SENSITIVE_EXTS:
                    return None
                severity = Severity.MEDIUM
            elif dork.key == "directory_listing":
                if "index of" not in title.lower():
                    return None
                severity = Severity.MEDIUM
            elif dork.key == "errors":
                severity = Severity.MEDIUM
            elif dork.key in ("admin_login", "debug_backup") and score_url(link) >= _ADMIN_SCORE:
                severity = Severity.MEDIUM
            elif dork.key == "subdomains":
                if host == domain or host == "www." + domain:
                    return None
                return self._finding(dork, query, result, severity, f"{dork.label}: {host}", host)

        return self._finding(dork, query, result, severity, label, link)

    def _finding(self, dork: Dork, query: str, result: dict, severity: Severity,
                 title: str, asset: str) -> Finding:
        link = str(result.get("link") or "")
        page_title = str(result.get("title") or "").strip()
        snippet = str(result.get("snippet") or "").strip()
        return Finding(
            id="", severity=severity, category=dork.category, title=title,
            description=(
                f"{page_title or link}" + (f" — {snippet}" if snippet else "")
                + f". Indexed by Google (query: {query}); not verified, open it to check."
            ),
            affected_asset=asset, source=self.name, source_url=link,
            mitre_attack="T1593.002",          # Search Open Websites/Domains: Search Engines
            raw_data={"dork": dork.key, "query": query, "title": page_title, "snippet": snippet,
                      "position": result.get("position")},
        )

    def _incomplete(self, domain: str, done: int, reason: str) -> Finding:
        return Finding(
            id="", severity=Severity.INFO, category=Category.WEB_FINDING,
            title=f"Google dorks incomplete: {done}/{len(DORKS)} queries run",
            description=f"The search stopped early ({reason}). The results above are partial: "
                        "run the scan again later for the remaining queries.",
            affected_asset=domain, source=self.name, source_url="https://serpapi.com/dashboard",
            mitre_attack="T1593.002", raw_data={"done": done, "total": len(DORKS), "reason": reason},
        )


def _leaks_a_credential(domain: str, text: str) -> bool:
    """A credential assignment within _NEAR characters of the domain, or a private-key block."""
    if _PRIVATE_KEY.search(text):
        return True
    low = text.lower()
    domain_at = [m.start() for m in re.finditer(re.escape(domain), low)]
    return any(abs(m.start() - d) <= _NEAR for m in _SECRET_ASSIGNMENT.finditer(text) for d in domain_at)


def _is_secret_file(path: str) -> bool:
    name = path.rsplit("/", 1)[-1].lower()
    return name in _SECRET_FILES or name.startswith(".env.")


def _ext(path: str) -> str:
    """Lower-case extension of the last path segment ("/.env" → "env", "/a/b" → "")."""
    last = path.rsplit("/", 1)[-1]
    return last.rsplit(".", 1)[-1].lower() if "." in last else ""
