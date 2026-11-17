"""
core/collectors/web_crawl.py — Semi-active web crawler collector.

Performs a BFS crawl of the target domain up to target.crawl_depth levels.
Sends real HTTP requests — appears in target server logs.
Only runs when target.crawl is True (enforced by runner._matches_mode; the CLI sets it
by default, `--no-crawl` turns it off).

robots.txt is respected (RFC 9309): fetched first, then
  - URLs it disallows for "Prowl" / "*" are neither crawled nor probed;
  - a Crawl-delay raises the delay between requests (capped);
  - if the whole site is disallowed the collector is reported as skipped;
  - 4xx (no robots.txt) = everything allowed; 5xx / unreachable = the crawl is not started
    and the failure is reported (the RFC says to assume a full disallow).
There is deliberately no way to bypass it. robots.txt is downloaded once; the probe of
/robots.txt itself reuses that response.
"""

from __future__ import annotations

import asyncio
import logging
import re
import warnings
from collections import deque
from urllib.parse import urljoin, urlparse
from urllib.robotparser import RobotFileParser

import httpx
from bs4 import BeautifulSoup, MarkupResemblesLocatorWarning

from core.collectors.base import BaseCollector, CollectorSkipped
from core.crawler.link_scorer import score_url
from core.crawler.page_models import FormInfo, PageAnalysis
from core.models import Category, CollectorResult, Finding, OsintTarget, Severity

logger = logging.getLogger(__name__)

_USER_AGENT = "Mozilla/5.0 (compatible; Prowl/0.1.0; +https://github.com/prowl)"
_EMAIL_RE   = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")

# Interesting extensions to probe even if not linked
_PROBE_PATHS = ["/.git/HEAD", "/.env", "/.htpasswd", "/robots.txt", "/sitemap.xml"]

# Score threshold to generate a Finding
_FINDING_THRESHOLD = 50

# Rate limiting: seconds between requests
_REQUEST_DELAY = 0.5

# Max pages per crawl run (safety cap)
_MAX_PAGES = 100

# robots.txt
_ROBOTS_TOKEN = "Prowl"              # product token matched against "User-agent:" lines
_ROBOTS_MAX_BYTES = 500 * 1024       # RFC 9309: parse at least 500 KiB
_MAX_CRAWL_DELAY = 5.0               # a huge Crawl-delay must not stall the whole scan


def _parse_html(text: str) -> BeautifulSoup:
    """
    Parse a response body. A short text/plain body that looks like a URL or a file name makes
    BeautifulSoup emit MarkupResemblesLocatorWarning, which leaked to the terminal. It is
    harmless here (the body is whatever the server sent), so it is silenced for this call only.
    (A `module="bs4"` filter would not match: the warning is attributed to this file.)
    """
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", MarkupResemblesLocatorWarning)
        return BeautifulSoup(text, "lxml")


class _Robots:
    """robots.txt rules for one crawl. Without a parser, everything is allowed."""

    def __init__(self, parser: RobotFileParser | None = None) -> None:
        self._parser = parser
        self.blocked = 0                      # URLs skipped because of the rules

    def allowed(self, url: str) -> bool:
        if self._parser is None or self._parser.can_fetch(_ROBOTS_TOKEN, url):
            return True
        self.blocked += 1
        return False

    def delay(self) -> float:
        """Seconds between requests: our own rate, or the site's Crawl-delay if larger."""
        asked = self._parser.crawl_delay(_ROBOTS_TOKEN) if self._parser else None
        return max(_REQUEST_DELAY, min(float(asked or 0), _MAX_CRAWL_DELAY))


class WebCrawlCollector(BaseCollector):
    name = "Web Crawler"
    tier = 1
    requires_api_key = False
    requires_crawl = True   # excluded by _matches_mode unless target.crawl (CLI: on, --no-crawl)

    async def collect(self, target: OsintTarget) -> CollectorResult:
        seed_url = f"https://{target.domain}"
        findings: list[Finding] = []
        self._progress("[Web Crawler] Starting scan — this may take a while...")

        async with httpx.AsyncClient(
            headers={"User-Agent": _USER_AGENT},
            timeout=10,
            follow_redirects=True,
            verify=False,   # target may have self-signed cert
        ) as client:

            robots, robots_response = await self._load_robots(client, seed_url)
            if not robots.allowed(f"{seed_url}/"):
                raise CollectorSkipped("robots.txt disallows crawling this site")

            pages = await self._bfs_crawl(client, seed_url, target, robots)

            # Probe sensitive paths regardless of link presence (robots.txt still applies)
            for path in _PROBE_PATHS:
                url = f"https://{target.domain}{path}"
                if url in {p.url for p in pages} or not robots.allowed(url):
                    continue
                if path == "/robots.txt":
                    # already downloaded to read the rules: analyse it, do not request it again
                    if robots_response.status_code == 200:
                        pages.append(self._analyze(robots_response, url, depth=0))
                    continue
                page = await self._fetch_page(client, url, depth=0)
                if page and page.status_code == 200:
                    pages.append(page)
                await asyncio.sleep(robots.delay())

        if robots.blocked:
            logger.info("Web Crawler: %d URL(s) skipped (robots.txt)", robots.blocked)
            self._progress(f"[Web Crawler] robots.txt respected: {robots.blocked} URL(s) not crawled")

        findings.extend(self._pages_to_findings(pages, target))
        for f in findings:
            self._progress(finding=f)           # findings need the whole crawl (dedup across pages)
        logger.info("Web Crawler: %d pages crawled, %d findings", len(pages), len(findings))
        return CollectorResult(findings=findings)

    # ── robots.txt ──────────────────────────────────────────────────────────

    @staticmethod
    async def _load_robots(client: httpx.AsyncClient, seed: str) -> tuple[_Robots, httpx.Response]:
        """
        Fetch and parse robots.txt (RFC 9309 status handling, see the module docstring).

        Returns the rules AND the response: the sensitive-path probing reuses it instead of
        requesting /robots.txt a second time.
        """
        try:
            resp = await client.get(f"{seed}/robots.txt")
        except httpx.HTTPError as exc:
            raise RuntimeError(
                f"Web Crawler: seed URL unreachable: {seed} "
                f"(robots.txt: {type(exc).__name__}) — crawl not started"
            ) from exc
        if resp.status_code >= 500:
            server = resp.headers.get("server", "")
            raise RuntimeError(
                f"Web Crawler: seed {seed} answered HTTP {resp.status_code}"
                f"{f' (Server: {server})' if server else ''} — blocked or down, nothing crawled "
                f"(robots.txt unavailable: RFC 9309 says to assume the site is off limits)"
            )
        if resp.status_code >= 400:
            return _Robots(), resp                # no robots.txt: everything is allowed
        parser = RobotFileParser()
        parser.parse(resp.text[:_ROBOTS_MAX_BYTES].splitlines())
        return _Robots(parser), resp

    # ── BFS ─────────────────────────────────────────────────────────────────

    async def _bfs_crawl(
        self, client: httpx.AsyncClient, seed: str, target: OsintTarget,
        robots: _Robots | None = None,
    ) -> list[PageAnalysis]:
        robots = robots or _Robots()
        visited: set[str] = set()
        queue: deque[tuple[str, int]] = deque([(seed, 0)])
        pages: list[PageAnalysis] = []

        # Verify seed is reachable — permanent failure on first attempt
        # avoids a silent empty result that the runner treats as success.
        seed_page = await self._fetch_page(client, seed, 0)
        if seed_page is None:
            raise RuntimeError(
                f"Web Crawler: seed URL unreachable: {seed}"
            )
        if seed_page.status_code >= 400:
            # A WAF / bot protection (403, 429, 503…) answers instead of the site: crawling
            # nothing is a failure, not "0 findings" (the report would show a green ✓).
            server = f" (Server: {seed_page.server_header})" if seed_page.server_header else ""
            raise RuntimeError(
                f"Web Crawler: seed {seed} answered HTTP {seed_page.status_code}{server} "
                f"— blocked or down, nothing crawled"
            )
        visited.add(seed)
        visited.add(seed_page.url)   # post-redirect URL
        pages.append(seed_page)
        await asyncio.sleep(robots.delay())

        # Enqueue seed's links for BFS (only if the crawl goes below depth 0)
        if target.crawl_depth >= 1:
            for link in seed_page.links:
                if link not in visited and self._in_scope(link, target.domain):
                    queue.append((link, 1))

        while queue and len(pages) < _MAX_PAGES:
            url, depth = queue.popleft()
            if url in visited:
                continue
            visited.add(url)
            if not robots.allowed(url):
                continue                          # disallowed by robots.txt: never requested

            page = await self._fetch_page(client, url, depth)
            if page is None:
                continue
            pages.append(page)
            visited.add(page.url)   # mark final URL (post-redirect)
            await asyncio.sleep(robots.delay())

            if depth < target.crawl_depth:
                for link in page.links:
                    if link not in visited and self._in_scope(link, target.domain):
                        queue.append((link, depth + 1))

        return pages

    # ── HTTP + parse ─────────────────────────────────────────────────────────

    async def _fetch_page(
        self, client: httpx.AsyncClient, url: str, depth: int
    ) -> PageAnalysis | None:
        try:
            resp = await client.get(url)
        except Exception as exc:
            logger.debug("Crawl fetch failed %s: %s", url, exc)
            return None
        return self._analyze(resp, url, depth)

    def _analyze(self, resp: httpx.Response, url: str, depth: int) -> PageAnalysis:
        """Turn an already received response into a PageAnalysis (no request)."""
        final_url = str(resp.url)   # post-redirect URL
        content_type = resp.headers.get("content-type", "")
        if "text/html" not in content_type and "text/plain" not in content_type:
            # Binary or non-HTML — record existence but skip parsing
            return PageAnalysis(
                url=final_url, status_code=resp.status_code, title="",
                links=[], emails=[], forms=[],
                server_header=resp.headers.get("server", ""),
                tech_hints=[], interesting_score=score_url(url),
                depth=depth,
            )

        soup = _parse_html(resp.text)
        base  = str(resp.url)

        title  = soup.title.string.strip() if soup.title and soup.title.string else ""
        links  = self._extract_links(soup, base)
        emails = list(set(_EMAIL_RE.findall(resp.text)))
        forms  = self._extract_forms(soup, base)
        hints  = self._extract_tech_hints(resp, soup)

        return PageAnalysis(
            url=final_url,
            status_code=resp.status_code,
            title=title,
            links=links,
            emails=emails,
            forms=forms,
            server_header=resp.headers.get("server", ""),
            tech_hints=hints,
            interesting_score=score_url(url),
            depth=depth,
        )

    # ── Extractors ───────────────────────────────────────────────────────────

    def _extract_links(self, soup: BeautifulSoup, base: str) -> list[str]:
        links = []
        for tag in soup.find_all("a", href=True):
            href = tag["href"].strip()
            if href.startswith(("#", "mailto:", "javascript:", "tel:")):
                continue
            abs_url = urljoin(base, href).split("#")[0]
            if abs_url not in links:
                links.append(abs_url)
        return links

    def _extract_forms(self, soup: BeautifulSoup, base: str) -> list[FormInfo]:
        forms = []
        for form in soup.find_all("form"):
            action  = urljoin(base, form.get("action", ""))
            method  = form.get("method", "GET").upper()
            inputs  = [i.get("name", "") for i in form.find_all("input") if i.get("name")]
            has_pwd = any(
                i.get("type", "").lower() == "password"
                for i in form.find_all("input")
            )
            forms.append(FormInfo(
                action=action, method=method,
                input_names=inputs, has_password_field=has_pwd,
            ))
        return forms

    def _extract_tech_hints(self, resp: httpx.Response, soup: BeautifulSoup) -> list[str]:
        hints = []
        for header in ("server", "x-powered-by", "x-generator", "x-drupal-cache",
                       "x-wordpress-id", "x-aspnet-version"):
            val = resp.headers.get(header)
            if val:
                hints.append(f"{header}: {val}")
        for meta in soup.find_all("meta", attrs={"name": ["generator", "framework"]}):
            content = meta.get("content", "")
            if content:
                hints.append(f"meta generator: {content}")
        return hints

    # ── Findings factory ─────────────────────────────────────────────────────

    def _pages_to_findings(
        self, pages: list[PageAnalysis], target: OsintTarget
    ) -> list[Finding]:
        findings: list[Finding] = []
        all_emails: set[str] = set()

        for page in pages:
            # Interesting URL scoring
            if page.interesting_score >= _FINDING_THRESHOLD and 200 <= page.status_code < 300:
                severity = (
                    Severity.CRITICAL if page.interesting_score >= 90
                    else Severity.HIGH if page.interesting_score >= 70
                    else Severity.MEDIUM
                )
                findings.append(Finding(
                    id="",
                    severity=severity,
                    category=Category.WEB_FINDING,
                    title=f"Sensitive path accessible: {urlparse(page.url).path or '/'}",
                    description=(
                        f"HTTP {page.status_code} at {page.url}. "
                        f"Interest score: {page.interesting_score}/100. "
                        + (f"Server: {page.server_header}. " if page.server_header else "")
                        + "This path may expose credentials, configuration, or admin access."
                    ),
                    affected_asset=target.domain,
                    source=self.name,
                    source_url=page.url,
                    mitre_attack="T1083",
                    raw_data={"score": page.interesting_score, "status": page.status_code},
                ))

            # Login forms
            for form in page.forms:
                if form.has_password_field:
                    findings.append(Finding(
                        id="",
                        severity=Severity.MEDIUM,
                        category=Category.WEB_FINDING,
                        title=f"Login form discovered: {urlparse(page.url).path or '/'}",
                        description=(
                            f"A form with a password field was found at {page.url}. "
                            f"Action: {form.action}, method: {form.method}. "
                            f"Inputs: {', '.join(form.input_names) or 'none'}."
                        ),
                        affected_asset=target.domain,
                        source=self.name,
                        source_url=page.url,
                        mitre_attack="T1078",
                        raw_data={"action": form.action, "inputs": form.input_names},
                    ))

            # Emails (deduplicated across pages)
            for email in page.emails:
                email_domain = email.split("@")[-1].lower().rstrip(".")
                in_scope = (
                    email_domain == target.domain
                    or email_domain.endswith("." + target.domain)
                )
                if not in_scope:
                    continue
                if email not in all_emails:
                    all_emails.add(email)
                    findings.append(Finding(
                        id="",
                        severity=Severity.INFO,
                        category=Category.EMAIL,
                        title=f"Email found in page source: {email}",
                        description=f"Email address harvested from {page.url}.",
                        affected_asset=email,
                        source=self.name,
                        source_url=page.url,
                        mitre_attack="T1589.002",
                        raw_data={"page": page.url},
                    ))

        # One LOW finding per distinct server fingerprint
        tech_map: dict[str, list[str]] = {}  # fingerprint → [urls]
        for page in pages:
            if page.tech_hints:
                key = " | ".join(sorted(page.tech_hints))
                tech_map.setdefault(key, []).append(page.url)

        for fingerprint, urls in tech_map.items():
            representative_url = urls[0]
            findings.append(Finding(
                id="",
                severity=Severity.LOW,
                category=Category.TECH_EXPOSURE,
                title=f"Server technology stack disclosed: {target.domain}",
                description=(
                    f"Fingerprint: {fingerprint}. "
                    f"Observed on {len(urls)} page(s). "
                    f"First seen: {representative_url}"
                ),
                affected_asset=target.domain,
                source=self.name,
                source_url=representative_url,
                mitre_attack="T1592.002",
                raw_data={"fingerprint": fingerprint, "pages": urls[:10]},
            ))

        return findings

    # ── Helpers ──────────────────────────────────────────────────────────────

    @staticmethod
    def _in_scope(url: str, domain: str) -> bool:
        """True if url's hostname is the target domain or a subdomain."""
        try:
            host = urlparse(url).netloc.lower().split(":")[0]
            return host == domain or host.endswith("." + domain)
        except Exception:
            return False
