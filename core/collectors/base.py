"""
core/collectors/base.py — Abstract base classes for all OSINT collectors.

BaseCollector — domain-level sources, run concurrently in phase 1 (implement collect()):
    DNS, WHOIS, crt.sh, DNSDumpster (HackerTarget), GitHub Org, OpenCorporates,
    BODACC, Pappers.fr, Web Crawler, Annuaire Entreprises, Hunter.io.

BasePersonCollector — person sources, run one person at a time in the phase 2 pivot
    (implement collect_person()): GitHub, EmailFormat, GitLeak, WhatsMyName.

Also here: CollectorSkipped (the collector had nothing to search, not a failure) and the
_Progress mixin that lets a slow collector report while it works.
"""

from __future__ import annotations

import logging
import os
from abc import ABC, abstractmethod
from collections.abc import Callable

from core.models import CollectorResult, Finding, OsintPerson, OsintTarget

logger = logging.getLogger(__name__)

# on_progress(message, finding): a status line (finding=None) or one finding, as soon as found.
ProgressCallback = Callable[[str, "Finding | None"], None]


class _Progress:
    """
    Lets a slow collector report while it works instead of only at the end.

    The runner sets `on_progress` (core never imports the UI) and clears it after the run.
    A collector that streams findings this way still returns them in its CollectorResult;
    the terminal knows which ones it already printed.
    """

    on_progress: ProgressCallback | None = None

    def _progress(self, message: str = "", finding: Finding | None = None) -> None:
        if self.on_progress is None:
            return
        try:
            self.on_progress(message, finding)
        except Exception:          # a display problem must never break a collector
            logger.exception("on_progress callback failed for %s", getattr(self, "name", "?"))


SKIP_REASON = "provide --siren for precise results"   # French registry collectors


class CollectorSkipped(Exception):
    """
    Raised by collect() when the collector cannot search because the target lacks
    a required input (e.g. no --company/--siren). Not a failure: the runner reports
    it as "skipped — <reason>", never as an error and never as "✓ 0 findings".
    """


class BaseCollector(_Progress, ABC):
    """
    Abstract OSINT collector.

    Subclass this for every data source. The runner imports all
    concrete collectors from core/collectors/__init__.py and calls
    is_available() before scheduling collect().
    """

    # --- class-level metadata (override in every subclass) ----------------

    name: str = ""              # Human-readable, used in reports and errors
    tier: int = 1               # 1 = free/high-ROI  2 = freemium  3 = paid/deep
    requires_api_key: bool = False
    api_key_env: str = ""       # Name of the env var holding the API key / token
    french_only: bool = False   # True → only runs when target.french is set
    requires_crawl: bool = False   # only runs when target.crawl is True

    # --- availability check -----------------------------------------------

    def is_available(self) -> bool:
        """
        Return True if this collector can run.

        A collector without an API key requirement is always available.
        A collector that needs a key is available only when the matching
        environment variable is set and non-empty.
        """
        if not self.requires_api_key:
            return True
        return bool(os.getenv(self.api_key_env, "").strip())

    # --- abstract interface -----------------------------------------------

    @abstractmethod
    async def collect(self, target: OsintTarget) -> CollectorResult:
        """
        Run the collection against target and return a CollectorResult
        (findings, plus any persons discovered for the person pivot).

        Transient errors (network hiccup, single timeout): catch them
        internally, retry if appropriate, and return an empty CollectorResult
        as a last resort only when the failure is not worth surfacing.

        Permanent failures (all retries exhausted, auth rejected, API
        down): raise RuntimeError with a descriptive message so the runner
        records the collector in report.errors instead of collectors_run.
        The runner catches Exception around each collect() call, so raising
        here is always safe.
        """

    # --- helpers ----------------------------------------------------------

    def __repr__(self) -> str:
        status = "available" if self.is_available() else "unavailable (no API key)"
        return f"<{self.__class__.__name__} tier={self.tier} {status}>"


class BasePersonCollector(_Progress, ABC):
    """
    Abstract collector that investigates ONE person (person pivot).

    Called by core/runner.py for every person found in phase 1 (and, with
    --pivot 2+, for every person discovered by a previous pivot level).
    """

    name: str = ""
    tier: int = 2
    requires_api_key: bool = False
    api_key_env: str = ""
    request_delay: float = 1.5   # seconds to sleep before each call

    # Set by the runner before each person: "is this name already in the person registry?". A collector
    # that DISCOVERS persons (colleagues…) uses it to skip people another source already found.
    is_known: Callable[[str], bool] = staticmethod(lambda name: False)

    def applies_to(self, person: OsintPerson, target: OsintTarget) -> bool:
        """False → the runner skips this collector for this person, silently (no "0 findings" line)."""
        return True

    def is_available(self) -> bool:
        if not self.requires_api_key:
            return True
        return bool(os.getenv(self.api_key_env, "").strip())

    @abstractmethod
    async def collect_person(
        self,
        person: OsintPerson,
        target: OsintTarget,
    ) -> CollectorResult: ...

    def __repr__(self) -> str:
        status = "available" if self.is_available() else "unavailable (no API key)"
        return f"<{self.__class__.__name__} tier={self.tier} {status}>"
