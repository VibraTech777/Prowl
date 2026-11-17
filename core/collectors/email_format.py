"""
core/collectors/email_format.py — Email address format guesser (person pivot).

Looks up the company's dominant email format on email-format.com
(https://www.email-format.com/d/{domain}/), then applies it to each person's
name to produce a *candidate* address. Nothing is sent to the mailbox: the
candidate is a guess, not a verified address — it is reported as a Finding and never
written to OsintPerson.email. Formats below MIN_CONFIDENCE are not used.

HTML structure (inspected on the live site): one block per format, best score first.

    <div class="format_score_container">
      <div class='format fl'>first_initial  last_name </div>
      <div class='confidence_value fl'>21%</div>
      ...
    </div>

Passive: only the third-party site is contacted, never the target.
A failed lookup is logged and yields an empty result (it never raises).
"""

from __future__ import annotations

import logging
import re
import unicodedata

import httpx
from bs4 import BeautifulSoup

from core.collectors.base import BasePersonCollector
from core.models import (
    Category, CollectorResult, Finding, OsintPerson, OsintTarget, Severity,
)

logger = logging.getLogger(__name__)

# Below this confidence (%) the dominant format is too unreliable to guess from.
MIN_CONFIDENCE = 50

_URL = "https://www.email-format.com/d/{domain}/"
_TIMEOUT = 15
_HEADERS = {"User-Agent": "Prowl OSINT / github.com/prowl"}
_DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$")

# email-format.com vocabulary → template placeholder
_TOKENS = {
    "first_name": "{first}",
    "first_initial": "{f}",
    "last_name": "{last}",
    "last_initial": "{l}",
}
# Accepted templates: "{first}", "{last}" or two placeholders with an optional . _ - between.
_TEMPLATE_RE = re.compile(
    r"^(?:\{(?:first|last)\}|\{(?:first|f|last|l)\}[._-]?\{(?:first|f|last|l)\})$"
)
_PERCENT_RE = re.compile(r"(\d+(?:\.\d+)?)\s*%")


def parse_format(raw: str) -> str | None:
    """
    Convert a site label ("first_name  . last_name") into a template ("{first}.{last}").
    Returns None for anything this collector cannot generate (unknown token, odd separator).
    """
    text = re.sub(r"\s+", "", raw.lower())
    for site_token, placeholder in _TOKENS.items():
        text = text.replace(site_token, placeholder)
    return text if _TEMPLATE_RE.match(text) else None


def pattern_label(template: str) -> str:
    """Human-readable name of a template: "{f}{last}" → "flast", "{first}.{last}" → "first.last"."""
    return re.sub(r"\{(\w+)\}", r"\1", template)


def parse_dominant_pattern(html: str) -> tuple[str, int] | None:
    """Return (template, confidence %) of the best-scored supported format, or None."""
    soup = BeautifulSoup(html, "lxml")
    best: tuple[str, int] | None = None
    for block in soup.select("div.format_score_container"):
        label = block.select_one("div.format")
        if label is None:
            continue
        template = parse_format(label.get_text())
        if template is None:
            continue
        pct = block.select_one("div.confidence_value")
        match = _PERCENT_RE.search(pct.get_text()) if pct else None
        confidence = int(float(match.group(1))) if match else 0
        if best is None or confidence > best[1]:       # ties: first (listed highest) wins
            best = (template, confidence)
    return best


def name_parts(full_name: str) -> tuple[str, str] | None:
    """
    (first, last) as lowercase ASCII, or None if the name has fewer than 2 usable parts.

    Accents are stripped, hyphens/apostrophes dropped ("Jean-Pierre" → "jeanpierre"),
    first = first word, last = last word ("Marie de la Tour" → "marie", "tour").
    """
    ascii_name = unicodedata.normalize("NFKD", full_name).encode("ascii", "ignore").decode()
    words = [re.sub(r"[^a-z0-9]", "", w) for w in ascii_name.lower().split()]
    words = [w for w in words if w]
    if len(words) < 2:
        return None
    return words[0], words[-1]


class EmailFormatCollector(BasePersonCollector):
    name = "EmailFormat"
    tier = 1
    requires_api_key = False
    french_only = False
    request_delay = 1.0

    def __init__(self) -> None:
        # domain → (template, confidence) or None. One lookup per domain per process:
        # the runner calls collect_person() once per person.
        self._cache: dict[str, tuple[str, int] | None] = {}

    async def collect_person(self, person: OsintPerson, target: OsintTarget) -> CollectorResult:
        parts = name_parts(person.full_name)
        if parts is None:
            return CollectorResult(findings=[])

        domain = target.domain.strip().lower()
        pattern = await self._pattern_for(domain)
        if pattern is None:
            return CollectorResult(findings=[])
        template, confidence = pattern
        if confidence < MIN_CONFIDENCE:
            logger.info("EmailFormat: dominant pattern for %s only %d%% (< %d%%), skipped",
                        domain, confidence, MIN_CONFIDENCE)
            return CollectorResult(findings=[])

        first, last = parts
        local = template.format(first=first, last=last, f=first[0], l=last[0])
        email = f"{local}@{domain}"
        # person.email is deliberately never set: a guess must reach the report only,
        # never feed the pivot chain (e.g. GitHub's search by email). It is kept in
        # email_guess so the terminal recap can show it, marked as a guess.
        person.email_guess = email

        label = pattern_label(template)
        finding = Finding(
            id="",
            severity=Severity.INFO,
            # COMPANY_INFO, not EMAIL: the runner lists EMAIL assets as discovered emails,
            # and this address is a guess.
            category=Category.COMPANY_INFO,
            title="Email pattern candidate",
            description=(
                f"{email} — pattern: {template} (confidence: {confidence}%). "
                f"Detected for {domain}; unverified guess for {person.full_name}."
            ),
            affected_asset=email,
            source=self.name,
            source_url=_URL.format(domain=domain),
            mitre_attack="T1589.002",          # Gather Victim Identity Information: Email Addresses
            raw_data={"pattern": label, "confidence": confidence, "person": person.full_name},
        )
        self._progress(finding=finding)
        return CollectorResult(findings=[finding])

    async def _pattern_for(self, domain: str) -> tuple[str, int] | None:
        if domain in self._cache:
            return self._cache[domain]
        self._progress("[EmailFormat] Starting scan — this may take a while...")   # once per domain
        pattern = await self._fetch_pattern(domain)
        self._cache[domain] = pattern          # failures are cached too: no retry per person
        return pattern

    @staticmethod
    async def _fetch_pattern(domain: str) -> tuple[str, int] | None:
        if not _DOMAIN_RE.match(domain):
            logger.warning("EmailFormat: invalid domain %r, skipped", domain)
            return None
        try:
            async with httpx.AsyncClient(headers=_HEADERS, timeout=_TIMEOUT) as client:
                resp = await client.get(_URL.format(domain=domain))   # no redirects: unknown
        except httpx.HTTPError as exc:                                # domains answer 302
            logger.warning("EmailFormat unreachable: %s: %s", type(exc).__name__, exc)
            return None
        if resp.status_code != 200:
            logger.warning("EmailFormat: HTTP %d for %s, no pattern", resp.status_code, domain)
            return None
        pattern = parse_dominant_pattern(resp.text)
        if pattern is None:
            logger.info("EmailFormat: no supported pattern found for %s", domain)
        return pattern
