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

The file is also REPORTED: its Disallow rules are paths the site wants crawlers to avoid, which
is often where the interesting things are. They are listed in one finding (MEDIUM if a path looks
sensitive, INFO otherwise) and are never requested.

The same goes for the other files a site publishes about itself (core/crawler/discovery.py):
sitemap.xml (and the sitemaps robots.txt declares), security.txt, OpenID Connect configuration,
Android / Apple app-link files, humans.txt, crossdomain.xml, clientaccesspolicy.xml. Each is one
GET, only if robots.txt allows it, read as text and reported — the URLs they list are never
requested.
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
from core.crawler.discovery import DISCOVERY_PATHS, MAX_BYTES, PARSERS, build_finding
from core.crawler.link_scorer import score_url
from core.crawler.page_models import FormInfo, PageAnalysis
from core.models import Category, CollectorResult, Finding, OsintTarget, Severity

logger = logging.getLogger(__name__)

_USER_AGENT = "Mozilla/5.0 (compatible; Prowl/0.1.0; +https://github.com/prowl)"
_EMAIL_RE   = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")

# Interesting extensions to probe even if not linked
_PROBE_PATHS = ["/.git/HEAD", "/.env", "/.htpasswd", "/robots.txt"]

# Sitemaps declared in robots.txt (in scope) fetched in addition to /sitemap.xml
_MAX_DECLARED_SITEMAPS = 3

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

# robots.txt content, reported as a finding
_ROBOTS_SENSITIVE_SCORE = 50         # a Disallow path scoring this much (link_scorer) → MEDIUM
_ROBOTS_MAX_RULES = 500              # rules kept (raw_data); a few huge files have thousands
_ROBOTS_LISTED = 25                  # paths spelled out in the description
_DISALLOW_RE = re.compile(r"^\s*disallow\s*:\s*(\S*)", re.IGNORECASE)
_SITEMAP_RE = re.compile(r"^\s*sitemap\s*:\s*(\S+)", re.IGNORECASE)


def parse_robots_rules(text: str) -> tuple[list[str], list[str]]:
    """
    (Disallow paths, Sitemap URLs) of a robots.txt, deduplicated, in file order.

    Every User-agent group counts: a rule aimed at another robot is still a path the site wants
    hidden. Comments are stripped; an empty "Disallow:" (= allow everything) and a bare "/" (a
    blanket ban, nothing to learn from it) are ignored.
    """
    disallowed: list[str] = []
    sitemaps: list[str] = []
    for line in text.splitlines():
        line = line.split("#", 1)[0]
        if m := _DISALLOW_RE.match(line):
            path = m.group(1)
            if path and path != "/" and path not in disallowed and len(disallowed) < _ROBOTS_MAX_RULES:
                disallowed.append(path)
        elif m := _SITEMAP_RE.match(line):
            if m.group(1) not in sitemaps:
                sitemaps.append(m.group(1))
    return disallowed, sitemaps


def _robots_path_score(path: str) -> int:
    """Interest score (link_scorer) of a Disallow pattern: wildcards and "$" are dropped first."""
    cleaned = path.replace("*", "").replace("$", "").split("?")[0]
    if not cleaned.startswith("/"):
        cleaned = "/" + cleaned
    return score_url("https://x.invalid" + cleaned)


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

            discovered = await self._discover(client, robots, robots_response, target)

        if robots.blocked:
            logger.info("Web Crawler: %d URL(s) skipped (robots.txt)", robots.blocked)
            self._progress(f"[Web Crawler] robots.txt respected: {robots.blocked} URL(s) not crawled")

        findings.extend(self._pages_to_findings(pages, target))
        if robots_response.status_code == 200 and (f := self._robots_finding(robots_response, target)):
            findings.append(f)
        findings.extend(discovered)
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

    # ── discovery files (sitemap, security.txt, .well-known…) ────────────────

    async def _discover(self, client: httpx.AsyncClient, robots: _Robots,
                        robots_response: httpx.Response, target: OsintTarget) -> list[Finding]:
        """Fetch the discovery files robots.txt allows, report the ones that really are one."""
        queue = [(kind, f"https://{target.domain}{path}")
                 for kind, paths in DISCOVERY_PATHS.items() for path in paths]
        if robots_response.status_code == 200:                    # sitemaps robots.txt points to
            _, declared = parse_robots_rules(robots_response.text[:_ROBOTS_MAX_BYTES])
            known = {url for _, url in queue}
            extra = [u for u in declared if u not in known and self._in_scope(u, target.domain)]
            queue += [("sitemap", u) for u in extra[:_MAX_DECLARED_SITEMAPS]]

        findings: list[Finding] = []
        reported: set[str] = set()
        fetched_urls: set[str] = set()               # final URLs already read (after redirects)
        for kind, url in queue:
            if kind in reported and kind != "sitemap":            # security.txt: first location wins
                continue
            if url in fetched_urls or not robots.allowed(url):
                continue
            fetched = await self._fetch_capped(client, url)
            await asyncio.sleep(robots.delay())
            if fetched is None or fetched[0] != 200:
                continue
            if fetched[1] in fetched_urls:                        # a redirect to a file we already have
                continue
            fetched_urls.update({url, fetched[1]})
            parsed = PARSERS[kind](fetched[2])                    # None: a 200 that is not that file
            if parsed is not None and (finding := build_finding(kind, parsed, fetched[1], target, self.name)):
                findings.append(finding)
                reported.add(kind)
        return findings

    @staticmethod
    async def _fetch_capped(client: httpx.AsyncClient, url: str) -> tuple[int, str, str] | None:
        """(status, final URL, text) reading at most MAX_BYTES; None if the request failed."""
        try:
            async with client.stream("GET", url) as resp:
                body = b""
                async for chunk in resp.aiter_bytes():
                    body += chunk
                    if len(body) >= MAX_BYTES:
                        break
                return resp.status_code, str(resp.url), body[:MAX_BYTES].decode("utf-8", "replace")
        except Exception as exc:                                  # dead or slow: skip, like a page
            logger.debug("Discovery fetch failed %s: %s", url, exc)
            return None

    # ── robots.txt as a finding ──────────────────────────────────────────────

    def _robots_finding(self, resp: httpx.Response, target: OsintTarget) -> Finding | None:
        """One finding listing the Disallow rules of a robots.txt (None if there are none)."""
        disallowed, sitemaps = parse_robots_rules(resp.text[:_ROBOTS_MAX_BYTES])
        if not disallowed:
            return None
        sensitive = [p for p in disallowed if _robots_path_score(p) >= _ROBOTS_SENSITIVE_SCORE]
        n = len(disallowed)

        title = f"robots.txt discloses {n} disallowed path{'s' if n != 1 else ''}"
        if sensitive:
            title += " — sensitive: " + ", ".join(sensitive[:3]) + (" …" if len(sensitive) > 3 else "")

        shown = disallowed[:_ROBOTS_LISTED]
        description = (
            f"robots.txt lists {n} Disallow rule{'s' if n != 1 else ''}: paths the site asks "
            "crawlers to stay away from, often worth a manual look. Prowl respects the file "
            "and never requests them. Disallowed: " + ", ".join(shown)
            + (f" … and {n - len(shown)} more" if n > len(shown) else "") + "."
        )
        if sensitive:
            description += " Sensitive-looking: " + ", ".join(sensitive[:_ROBOTS_LISTED]) + "."
        if sitemaps:
            description += " Sitemaps: " + ", ".join(sitemaps[:5]) + "."

        return Finding(
            id="",
            severity=Severity.MEDIUM if sensitive else Severity.INFO,
            category=Category.WEB_FINDING,
            title=title,
            description=description,
            affected_asset=target.domain,
            source=self.name,
            source_url=str(resp.url),
            mitre_attack="T1594",           # Search Victim-Owned Websites
            raw_data={"disallow": disallowed, "sensitive": sensitive, "sitemaps": sitemaps},
        )

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
