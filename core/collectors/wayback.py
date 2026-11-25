"""
core/collectors/wayback.py — What the Wayback Machine remembers about the target (phase 1).

Passive with respect to the target: only archive.org is contacted over HTTP (the old subdomains are
resolved in DNS, nothing more). Four questions, answered from
the CDX index and a handful of archived pages:

  • who used to be on the team?   old /team, /about … pages: names absent from the newest snapshot
                                  become "possible former employees" AND OsintPerson (→ pivot);
  • what used to exist?           subdomains (checked in DNS: gone or still alive), /api/v1/-style
                                  endpoint families and services once indexed on non-standard ports
                                  (a lead for the crawler's --port);
  • which files were exposed?     PDFs and documents, and configs / backups / logs / archives;
  • which stack did it run?       server / framework / CMS / library fingerprints of old homepages.

Nothing is requested from the target: whether an old URL still answers is NOT checked ("may no
longer be online"). Everything is a lead, not a fact: a name on a 2017 page may be a former
employee, a customer quote or a false match.

The Wayback Machine is slow (a CDX query can take 20–60 s), so the requests are few (a dozen small CDX
queries and at most ~13 archived pages), run two at a time, and spaced out.
"""

from __future__ import annotations

import asyncio
import logging
import re
from collections import Counter

import dns.exception
import dns.resolver
import httpx

from core.collectors.base import BaseCollector, CollectorSkipped
from core.crawler.link_scorer import score_url
from core.crawler.wayback import (
    FILES_API_FILTER, SENSITIVE_EXTS, TEAM_PATH_RE, TEAM_QUERY_PATHS, Capture, Inventory,
    NOTABLE_PORTS, archive_url, build_inventory, extension, extract_people, extract_tech, fold, in_scope, parse_cdx,
    pick_spread,
)
from core.models import (
    Category, CollectorResult, Finding, OsintPerson, OsintTarget, Severity,
)

logger = logging.getLogger(__name__)

_CDX = "https://web.archive.org/cdx/search/cdx"
_USER_AGENT = "Prowl OSINT / github.com/prowl"
_TIMEOUT = httpx.Timeout(120.0, connect=20.0)
_CONCURRENCY = 2
_MAX_PAGE_BYTES = 1024 * 1024
_DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$")

_TEAM_URLS = 2               # team-like URLs analysed (e.g. /team and /about)
_TEAM_SNAPSHOTS = 4          # snapshots read per URL, spread over the years
_HOME_SNAPSHOTS = 5          # archived homepages read, spread over the years
_MAX_SUBDOMAINS_CHECKED = 60
_MAX_PERSONS = 30
_MAX_FILES = 25
_LISTED = 15
_SENSITIVE_PATH_SCORE = 70   # archived path scoring this much (admin, backup, phpmyadmin…) → MEDIUM


class _Unavailable(Exception):
    """The Wayback Machine did not give a usable answer."""


class WaybackCollector(BaseCollector):
    name = "Wayback Machine"
    tier = 1
    requires_api_key = False
    request_delay = 1.0

    async def collect(self, target: OsintTarget) -> CollectorResult:
        domain = target.domain.strip().lower()
        if not _DOMAIN_RE.match(domain):
            raise CollectorSkipped("the domain cannot be used in an archive query")
        self._progress("[Wayback Machine] Starting scan — archive.org is slow, this may take "
                       "a few minutes...")

        sem = asyncio.Semaphore(_CONCURRENCY)
        findings: list[Finding] = []
        persons: list[OsintPerson] = []
        problems: list[str] = []
        ok = {"n": 0}                                         # CDX queries that answered

        async with httpx.AsyncClient(headers={"User-Agent": _USER_AGENT}, timeout=_TIMEOUT,
                                     follow_redirects=True) as client:
            def query(params: list[tuple]) -> asyncio.Task:
                return asyncio.create_task(self._cdx(client, sem, params))

            # CDX keys sort the apex first ("io,cobalt)/…" before "io,cobalt,api)/…"): a head query
            # sees the apex pages, a tail query (negative limit) reaches the subdomains.
            head = query(self._cdx_params(domain, "timestamp,original,mimetype", "urlkey", [], 3000))
            tail = query(self._cdx_params(domain, "timestamp,original,mimetype", "urlkey", [], -4000))
            files = query(self._cdx_params(domain, "timestamp,original,mimetype", "urlkey",
                                           [FILES_API_FILTER], 1500))
            # Exact lookups are cheap (a regex filter over a whole domain times out on big sites);
            # the CDX key ignores "www." and the scheme, so one query covers every variant.
            team_q = [query(self._exact_params(f"{domain}/{path}")) for path in TEAM_QUERY_PATHS]
            home_q = [query(self._exact_params(domain))]

            # Three independent branches: each shows its findings as soon as ITS data is here,
            # instead of waiting for the slowest archive.org query.
            await asyncio.gather(
                self._branch_domain(client, domain, [head, tail], files, findings, problems, ok),
                self._branch_team(client, sem, domain, team_q, findings, persons, problems, ok),
                self._branch_tech(client, sem, domain, home_q, findings, problems, ok))

            if not ok["n"]:                                   # nothing worked: a failure
                raise RuntimeError(f"Wayback Machine unavailable ({problems[0]})")

        if problems:                  # a status line, not a finding: it is about archive.org, not the target
            self._progress("[Wayback Machine] Partial results (archive.org did not answer everything: "
                           + "; ".join(problems) + "). Run the scan again later.")
        logger.info("Wayback Machine: %d findings, %d persons for %s", len(findings), len(persons), domain)
        return CollectorResult(findings=findings, persons=persons)

    async def _gather(self, label: str, tasks: list[asyncio.Task], problems: list[str],
                      ok: dict) -> list[Capture]:
        """Captures of finished CDX queries; a failed query is noted once per label (partial result)."""
        captures: list[Capture] = []
        reason = None
        for answer in await asyncio.gather(*tasks, return_exceptions=True):
            if isinstance(answer, _Unavailable):
                reason = reason or str(answer)
            elif isinstance(answer, BaseException):
                raise answer
            else:
                ok["n"] += 1
                captures += answer
        if reason:
            problems.append(f"{label}: {reason}")
        return captures

    async def _branch_domain(self, client, domain, early, files_task, findings, problems, ok) -> None:
        """Subdomains first (as soon as the inventory is here), then endpoints and files."""
        early_caps = await self._gather("inventory", early, problems, ok)
        inv = build_inventory(early_caps, domain)
        shown = {c for c in inv.subdomains}
        self._add_all(findings, await self._subdomain_findings(inv, domain))
        shown_ports = set(inv.ports)
        self._add_all(findings, self._port_findings(inv, domain))
        self._progress(f"[Wayback Machine] inventory read: {len(early_caps)} archived URLs, "
                       f"{len(shown)} subdomains; looking for old APIs and files...")

        everything = early_caps + await self._gather("files and APIs", [files_task], problems, ok)
        inv = build_inventory(everything, domain)
        self._add_all(findings, await self._subdomain_findings(inv, domain, skip=shown))   # new hosts only
        self._add_all(findings, self._port_findings(inv, domain, skip=shown_ports))     # new ports only
        self._add_all(findings, self._endpoint_findings(inv, everything, domain))
        self._add_all(findings, self._file_findings(inv, domain))

    async def _branch_team(self, client, sem, domain, queries, findings, persons, problems, ok) -> None:
        captures = await self._gather("team pages", queries, problems, ok)
        team, team_problem = await self._team(client, sem, captures)
        problems += team_problem
        for finding, person in self._former_staff(team, domain):
            self._add_all(findings, [finding])
            persons.append(person)

    async def _branch_tech(self, client, sem, domain, queries, findings, problems, ok) -> None:
        captures = await self._gather("homepages", queries, problems, ok)
        tech, tech_problem = await self._tech(client, sem, captures)
        problems += tech_problem
        if (finding := self._tech_finding(tech, domain)) is not None:
            self._add_all(findings, [finding])

    def _add_all(self, findings: list[Finding], new: list[Finding]) -> None:
        for finding in new:
            findings.append(finding)
            self._progress(finding=finding)

    # ── archive.org ─────────────────────────────────────────────────────────

    @staticmethod
    def _cdx_params(domain: str, fl: str, collapse: str, filters: list[str], limit: int) -> list[tuple]:
        params = [("url", domain), ("matchType", "domain"), ("output", "json"), ("fl", fl),
                  ("collapse", collapse), ("filter", "statuscode:200")]
        params += [("filter", f) for f in filters]
        return params + [("limit", str(limit))]

    @staticmethod
    def _exact_params(url: str) -> list[tuple]:
        return [("url", url), ("output", "json"), ("fl", "timestamp,original"), ("collapse", "timestamp:4"),
                ("filter", "statuscode:200"), ("limit", "40")]

    async def _cdx(self, client: httpx.AsyncClient, sem: asyncio.Semaphore, params: list[tuple]) -> list[Capture]:
        resp = None
        for attempt in range(2):                              # archive.org often answers 503/504 once
            async with sem:
                try:
                    resp = await client.get(_CDX, params=params)
                except httpx.HTTPError as exc:
                    raise _Unavailable(f"unreachable ({type(exc).__name__})") from None
                finally:
                    await asyncio.sleep(self.request_delay * (3 if attempt == 0 else 1))
            if resp.status_code < 500:
                break
        if resp.status_code != 200:
            raise _Unavailable(f"HTTP {resp.status_code}")
        return parse_cdx(resp.text)

    async def _snapshot(self, client: httpx.AsyncClient, sem: asyncio.Semaphore,
                        capture: Capture) -> tuple[dict[str, str], str] | None:
        """(headers, text) of an archived page, or None. The raw replay (id_) has no banner."""
        async with sem:
            try:
                async with client.stream("GET", archive_url(capture, raw=True)) as resp:
                    if resp.status_code != 200:
                        return None
                    body = b""
                    async for chunk in resp.aiter_bytes():
                        body += chunk
                        if len(body) >= _MAX_PAGE_BYTES:
                            break
                    headers = dict(resp.headers)
            except httpx.HTTPError as exc:
                logger.debug("Wayback snapshot %s failed: %s", capture.timestamp, type(exc).__name__)
                return None
            finally:
                await asyncio.sleep(self.request_delay)
        return headers, body[:_MAX_PAGE_BYTES].decode("utf-8", "replace")

    # ── subdomains ──────────────────────────────────────────────────────────

    async def _subdomain_findings(self, inv: Inventory, domain: str,
                                  skip: set[str] = frozenset()) -> list[Finding]:
        hosts = sorted((h for h in inv.subdomains if h not in skip),
                       key=lambda h: inv.subdomains[h].timestamp, reverse=True)
        hosts = hosts[:_MAX_SUBDOMAINS_CHECKED]
        gate = asyncio.Semaphore(10)

        async def check(host: str) -> str:
            async with gate:
                return await asyncio.to_thread(_dns_state, host)

        states = await asyncio.gather(*(check(h) for h in hosts))
        findings = []
        for host, state in zip(hosts, states):
            cap = inv.subdomains[host]
            gone = state == "gone"
            title = (f"Historic subdomain (no longer resolves): {host}" if gone
                     else f"Subdomain seen in Wayback Machine: {host}")
            note = {"gone": "It no longer resolves in DNS: a decommissioned system, maybe forgotten "
                            "references to it.",
                    "alive": "It still resolves in DNS.",
                    "unknown": "The DNS check was inconclusive."}[state]
            findings.append(self._finding(
                Category.SUBDOMAIN, Severity.INFO, title,
                f"{host} was archived (last capture {cap.year}). {note}", host, cap,
                {"host": host, "last_capture": cap.timestamp, "dns": state}))
        return findings

    # ── non-standard ports ──────────────────────────────────────────────────

    def _port_findings(self, inv: Inventory, domain: str, skip: set[str] = frozenset()) -> list[Finding]:
        """One finding: services once indexed on a port other than 80 / 443 (a lead for --port)."""
        items = sorted(((key, cap) for key, cap in inv.ports.items() if key not in skip),
                       key=lambda kv: (kv[1].port not in NOTABLE_PORTS, -int(kv[1].timestamp[:8]), kv[0]))
        if not items:
            return []
        notable = [(key, cap) for key, cap in items if cap.port in NOTABLE_PORTS]
        title = (f"Non-standard ports seen in the Wayback Machine: {len(items)}"
                 + (" more" if skip else ""))
        if notable:
            title += " — notable: " + ", ".join(f"{k} ({NOTABLE_PORTS[c.port]})" for k, c in notable[:3]) \
                + (" …" if len(notable) > 3 else "")
        listed = ", ".join(f"{key} ({cap.year})" for key, cap in items[:_LISTED])
        more = f" … and {len(items) - _LISTED} more" if len(items) > _LISTED else ""
        first_port = items[0][1].port
        return [self._finding(
            Category.WEB_FINDING, Severity.MEDIUM if notable else Severity.INFO, title,
            f"Web pages were archived on non-standard ports (last capture year): {listed}{more}. Such "
            "services are often less hardened (admin consoles, dev or internal tools). Whether they "
            "still answer was NOT checked; a lead for the web crawler, e.g. "
            f"`prowl -d {domain} --port {first_port}`.",
            domain, items[0][1], {"ports": {k: c.timestamp for k, c in items}})]

    # ── endpoints, files ────────────────────────────────────────────────────

    def _endpoint_findings(self, inv: Inventory, captures: list[Capture], domain: str) -> list[Finding]:
        findings = []
        if inv.api_paths:
            items = sorted(inv.api_paths.items(), key=lambda kv: kv[1].timestamp, reverse=True)
            listed = ", ".join(f"{key} ({cap.year})" for key, cap in items[:_LISTED])
            more = f" … and {len(items) - _LISTED} more" if len(items) > _LISTED else ""
            findings.append(self._finding(
                Category.WEB_FINDING, Severity.INFO,
                f"Historic API endpoints in the Wayback Machine: {len(items)}",
                f"Endpoint families once indexed (last capture year): {listed}{more}. Old API versions "
                "are often left running without the protections of the current one; whether these "
                "still answer was NOT checked.", domain, items[0][1],
                {"endpoints": {k: c.timestamp for k, c in items}}))
        sensitive: dict[str, Capture] = {}
        for c in captures:
            if (in_scope(c.host, domain) and extension(c.path) not in SENSITIVE_EXTS
                    and score_url(c.original) >= _SENSITIVE_PATH_SCORE
                    and (c.original not in sensitive or c.timestamp > sensitive[c.original].timestamp)):
                sensitive[c.original] = c
        if sensitive:
            items = sorted(sensitive.values(), key=lambda c: c.timestamp, reverse=True)
            listed = ", ".join(f"{c.host}{c.path} ({c.year})" for c in items[:10])
            findings.append(self._finding(
                Category.WEB_FINDING, Severity.MEDIUM,
                f"Sensitive-looking paths archived: {len(items)}",
                f"The Wayback Machine captured (HTTP 200) paths such as: {listed}. They were publicly "
                "reachable at the time; whether they still are was NOT checked.", domain, items[0],
                {"paths": [c.original for c in items]}))
        return findings

    def _file_findings(self, inv: Inventory, domain: str) -> list[Finding]:
        findings = []
        for cap in inv.sensitive_files[:_MAX_FILES]:
            findings.append(self._finding(
                Category.CODE_LEAK, Severity.MEDIUM,
                f"Archived sensitive file: {cap.host}{cap.path} (captured {cap.year})",
                f"{cap.original} was publicly reachable and archived in {cap.year}. A configuration, "
                "backup, log or archive file may have exposed secrets; it may no longer be online "
                "(not checked live) but the archived copy can be read through the Wayback Machine.",
                cap.original, cap, {"url": cap.original, "ext": extension(cap.path)}))
        if len(inv.sensitive_files) > _MAX_FILES:
            logger.info("Wayback Machine: %d more archived sensitive files not listed",
                        len(inv.sensitive_files) - _MAX_FILES)
        if inv.documents:
            kinds = Counter(extension(c.path) for c in inv.documents)
            sample = ", ".join(f"{c.host}{c.path} ({c.year})" for c in inv.documents[:_LISTED])
            more = f" … and {len(inv.documents) - _LISTED} more" if len(inv.documents) > _LISTED else ""
            findings.append(self._finding(
                Category.WEB_FINDING, Severity.INFO,
                f"Archived documents: {len(inv.documents)} ("
                + ", ".join(f"{k} {n}" for k, n in kinds.most_common(4)) + ")",
                f"Documents once published on the site: {sample}{more}. Their metadata (authors, "
                "software, internal paths) often names employees; they may no longer be online.",
                domain, inv.documents[0], {"documents": [c.original for c in inv.documents[:200]]}))
        return findings

    # ── people: former team members ─────────────────────────────────────────

    async def _team(self, client: httpx.AsyncClient, sem: asyncio.Semaphore,
                    captures: list[Capture]) -> tuple[dict[str, list[tuple[Capture, dict]]], list[str]]:
        """{team URL: [(capture, {folded name: PersonHit-like dict}) oldest → newest]}."""
        by_url: dict[str, list[Capture]] = {}
        for c in captures:
            if TEAM_PATH_RE.match(c.path):
                by_url.setdefault(c.path.rstrip("/").lower(), []).append(c)   # http/https/www variants merge
        # the URLs with the longest history first (/team usually beats /about)
        urls = sorted(by_url, key=lambda u: len(by_url[u]), reverse=True)[:_TEAM_URLS]
        jobs = [(url, c) for url in urls
                for c in pick_spread(sorted(by_url[url], key=lambda c: c.timestamp), _TEAM_SNAPSHOTS)]
        pages = await asyncio.gather(*(self._snapshot(client, sem, c) for _, c in jobs))
        result: dict[str, list[tuple[Capture, dict]]] = {}
        failed = 0
        for (url, cap), page in zip(jobs, pages):
            if page is None:
                failed += 1
                continue
            people = {fold(p.name): p for p in extract_people(page[1])}
            result.setdefault(url, []).append((cap, people))
        problem = [f"team pages: {failed}/{len(jobs)} archived pages could not be read"] if failed else []
        return result, problem

    def _former_staff(self, team: dict, domain: str) -> list[tuple[Finding, OsintPerson]]:
        """People on an older snapshot of a team page but not on its newest one."""
        newest_names: set[str] = set()
        seen: dict[str, tuple[object, Capture, str]] = {}      # folded name → (hit, oldest capture, newest year)
        usable = False
        for url, snaps in team.items():
            snaps.sort(key=lambda s: s[0].timestamp)
            if len(snaps) < 2 or not snaps[-1][1]:             # one snapshot, or a page with no names
                continue                                        # (JavaScript site): nothing to compare
            usable = True
            newest_names |= set(snaps[-1][1])
            for cap, people in snaps[:-1]:
                for key, hit in people.items():
                    if key not in seen or cap.timestamp < seen[key][1].timestamp:
                        seen[key] = (hit, cap, snaps[-1][0].year)
        if not usable:
            return []
        out: list[tuple[Finding, OsintPerson]] = []
        for key, (hit, cap, newest_year) in seen.items():
            if key in newest_names or len(out) >= _MAX_PERSONS:
                continue
            path = cap.path
            finding = self._finding(
                Category.COMPANY_INFO, Severity.INFO, f"Possible former employee: {hit.name}",
                f"{hit.name}" + (f" ({hit.role})" if hit.role else "")
                + f" appears on {path} in {cap.year} but not on the {newest_year} snapshot of the same "
                "page: they may have left the company (or the page changed). A lead for the person "
                "pivot, to verify.", hit.name, cap,
                {"name": hit.name, "role": hit.role, "first_seen": cap.timestamp,
                 "absent_from": newest_year, "page": cap.original},
                mitre="T1589.003")             # Gather Victim Identity Information: Employee Names
            person = OsintPerson(
                full_name=hit.name,
                role=(hit.role + " — " if hit.role else "") + f"possible former employee (seen {cap.year})",
                source=self.name, depth_found=1)
            out.append((finding, person))
        return out

    # ── technology history ──────────────────────────────────────────────────

    async def _tech(self, client: httpx.AsyncClient, sem: asyncio.Semaphore,
                    captures: list[Capture]) -> tuple[list[tuple[Capture, list[str]]], list[str]]:
        picked = pick_spread(sorted(captures, key=lambda c: c.timestamp), _HOME_SNAPSHOTS)
        pages = await asyncio.gather(*(self._snapshot(client, sem, c) for c in picked))
        history = [(cap, extract_tech(page[0], page[1])) for cap, page in zip(picked, pages) if page]
        failed = len(picked) - len(history)
        return history, ([f"homepages: {failed}/{len(picked)} archived pages could not be read"] if failed else [])

    def _tech_finding(self, history: list[tuple[Capture, list[str]]], domain: str) -> Finding | None:
        rows = [(cap, hints) for cap, hints in history if hints]
        if not rows:
            return None
        history_text = " | ".join(f"{cap.year}: {'; '.join(hints[:8])}" for cap, hints in rows)
        return self._finding(
            Category.TECH_EXPOSURE, Severity.INFO,
            f"Technology history (Wayback Machine): {rows[0][0].year} → {rows[-1][0].year}",
            f"Fingerprints of archived homepages — {history_text}. Past stacks reveal architecture "
            "patterns (and old, vulnerable versions that may survive on forgotten hosts).",
            domain, rows[-1][0], {"history": {cap.year: hints for cap, hints in rows}})

    # ── building findings ───────────────────────────────────────────────────

    def _finding(self, category: Category, severity: Severity, title: str, description: str,
                 asset: str, capture: Capture, raw: dict, mitre: str = "T1593") -> Finding:
        return Finding(
            id="", severity=severity, category=category, title=title, description=description,
            affected_asset=asset, source=self.name, source_url=archive_url(capture),
            mitre_attack=mitre,                # T1593 Search Open Websites/Domains
            raw_data=raw,
        )


def _dns_state(host: str) -> str:
    """"alive" (A/AAAA answer), "gone" (NXDOMAIN / no address at all) or "unknown" (timeout…)."""
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 3.0
    unknown = False
    for rtype in ("A", "AAAA"):
        try:
            if resolver.resolve(host, rtype):
                return "alive"
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            continue
        except (dns.exception.Timeout, dns.resolver.NoNameservers, Exception):
            unknown = True
    return "unknown" if unknown else "gone"
