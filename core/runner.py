"""
core/runner.py — Async orchestrator for OSINT collection.

Imports all collectors, filters by availability / mode / country flag,
runs them concurrently, then assembles and returns an OsintReport.
This module has zero dependency on cli/ and never prints.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from collections.abc import Callable

from core.collectors import ALL_COLLECTORS, PERSON_COLLECTORS
from core.collectors.base import CollectorSkipped
from core.collectors.github_person import GitHubPersonCollector
from core.collectors.person_registry import PersonRegistry
from core.models import (
    Category, CollectorResult, Finding, OsintPerson, OsintReport, OsintTarget,
    SEVERITY_ORDER,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


async def run_osint(
    target: OsintTarget,
    selected: list[str] | None = None,
    on_result: Callable[..., None] | None = None,
    on_progress: Callable[..., None] | None = None,
) -> OsintReport:
    """
    Run all eligible collectors concurrently and return a consolidated report.

    core/ never prints: notices about the scan flow ("[INFO] …" / "[WARNING] …") go through
    ``on_progress`` (or the logging module when no callback is given).

    Args:
        target:    Fully populated OsintTarget (domain, mode, flags …).
        selected:  Optional allowlist of collector names. None = run all eligible.
        on_progress: Optional callback ``on_progress(message, finding)`` that slow collectors
                   (e.g. WhatsMyName) call while they work: a status message, or one
                   finding the moment it is confirmed. The runner also sends its own
                   notices through it, as messages starting with "[INFO]" / "[WARNING]".
                   Cleared when the run ends.
        on_result: Optional callback ``on_result(name, findings, error)`` invoked
                   as each collector finishes (completion order, not collector
                   order). ``error`` is None on success, the exception otherwise.
                   Lets a UI show live progress without core/ importing it.

    Returns:
        OsintReport with findings sorted by severity, sequential IDs assigned.
    """
    for c in (*ALL_COLLECTORS, *PERSON_COLLECTORS):      # collectors are module singletons
        c.on_progress = on_progress
    try:
        return await _run_osint(target, selected, on_result, on_progress)
    finally:
        for c in (*ALL_COLLECTORS, *PERSON_COLLECTORS):
            c.on_progress = None


async def _run_osint(
    target: OsintTarget,
    selected: list[str] | None,
    on_result: Callable[..., None] | None,
    on_progress: Callable[..., None] | None = None,
) -> OsintReport:
    start = time.monotonic()

    eligible = [
        c for c in ALL_COLLECTORS
        if _matches_mode(c, target) and (selected is None or c.name in selected)
    ]
    collectors = [c for c in eligible if c.is_available()]
    # Eligible for this run but unusable (no API key): shown as "Name (no key)".
    # Collectors excluded by --mode / --french / --crawl are NOT listed here.
    skipped = [c.name for c in eligible if not c.is_available()]
    if target.pivot_depth >= 1:
        skipped += [c.name for c in PERSON_COLLECTORS if not c.is_available()]

    logger.info(
        "Starting OSINT run — domain=%s mode=%s french=%s collectors=%d",
        target.domain, target.mode, target.french, len(collectors),
    )

    phase1_on_result, phase1_on_progress = _live_deduplicator(on_result, on_progress)
    for c in collectors:                 # phase 1 shares the dedup; the pivot gets the raw callback
        c.on_progress = phase1_on_progress

    async def run_one(collector):
        error: Exception | None = None
        result = CollectorResult(findings=[])
        try:
            result = await collector.collect(target)
        except Exception as exc:
            error = exc

        # Notify outside the try block: a failing callback must never be
        # mistaken for a collector failure.
        _notify(phase1_on_result, collector.name, result.findings, error)
        return collector.name, result, error

    # ── Phase 1: domain collectors, concurrent ───────────────────────────
    # Each wrapper reports as soon as its collector finishes (live output),
    # while gather() still returns results in collector order so the final
    # report is deterministic.
    results = await asyncio.gather(*(run_one(c) for c in collectors))

    all_findings: list[Finding] = []
    all_persons: list[OsintPerson] = []
    errors: dict[str, str] = {}
    collectors_run: list[str] = []
    skipped_reasons: dict[str, str] = {}

    for name, result, error in results:
        if isinstance(error, CollectorSkipped):
            skipped_reasons[name] = str(error)        # nothing to search: not an error
        elif error is not None:
            msg = f"{type(error).__name__}: {error}"
            errors[name] = msg
            logger.error("Collector %s raised an unhandled exception: %s", name, msg)
        else:
            all_findings.extend(result.findings)
            all_persons.extend(result.persons)
            collectors_run.append(name)

    # Several collectors report the same asset (e.g. crt.sh + DNSDumpster).
    # Phase 1 only: pivot findings are kept even if a phase 1 finding shares their title.
    all_findings = _deduplicate_findings(all_findings)

    # ── Phase 2: person pivot (opt-in, sequential and rate-limited) ──────
    pivot_stats: dict[str, dict[str, int]] = {}
    registry = PersonRegistry()                  # also gives the report its deduplicated persons
    registry.add_many(all_persons)
    if target.pivot_depth >= 1:
        if not registry.all or not any(c.is_available() for c in PERSON_COLLECTORS):
            _announce(on_progress, "INFO",
                      "--pivot enabled but no persons found in Phase 1 — pivot skipped.")
        else:
            # Pivot warnings come after Phase 1, once we know requests will really be sent.
            if (
                not os.getenv("GITHUB_TOKEN", "").strip()
                and any(isinstance(c, GitHubPersonCollector) and c.is_available()
                        for c in PERSON_COLLECTORS)
            ):
                _announce(on_progress, "WARNING",
                          "No GITHUB_TOKEN — GitHub pivot limited to name search "
                          "(~5 persons/hr). Set GITHUB_TOKEN in .env for full coverage.")
            if target.pivot_depth >= 2:       # only when requests are really going to be sent
                _announce(on_progress, "INFO",
                          f"--pivot {target.pivot_depth} enabled — deepens recon on discovered "
                          "persons (requires additional person discovery sources for full "
                          "recursion).")
            pivot_findings = await _run_person_pivot(
                target, registry.all, registry, 1, on_result, errors, pivot_stats,
                on_progress=on_progress,
            )
            all_findings.extend(pivot_findings)
            _aggregate_pivot_errors(errors, pivot_stats)

    # Sort by severity (CRITICAL first), stable so equal-severity items
    # keep their original collector order
    all_findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 99))

    # Assign sequential IDs: F001, F002, …
    for i, finding in enumerate(all_findings, start=1):
        finding.id = f"F{i:03d}"

    duration = round(time.monotonic() - start, 2)

    report = OsintReport(
        target=target,
        findings=all_findings,
        assets=_extract_assets(all_findings),
        errors=errors,
        collectors_run=collectors_run,
        duration_seconds=duration,
        pivot_stats=pivot_stats,
        collectors_skipped=skipped,
        skipped_reasons=skipped_reasons,
        persons=registry.all,
    )

    logger.info(
        "Run complete — %d findings, %d errors, %.2fs",
        len(all_findings), len(errors), duration,
    )
    return report


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _announce(on_progress, level: str, text: str) -> None:
    """
    A notice about the scan flow, for the user: "[INFO] text" / "[WARNING] text".

    Sent through on_progress (the CLI prints it on stderr); without a callback it goes to
    the logging module, so a library user still sees it. core/ never prints.
    """
    if on_progress is None:
        logger.log(logging.WARNING if level == "WARNING" else logging.INFO, "%s", text)
        return
    try:
        on_progress(f"[{level}] {text}", None)
    except Exception:
        logger.exception("on_progress callback failed for a %s notice", level)


def _notify(on_result, name: str, findings: list[Finding], error) -> None:
    """Call the on_result callback (a collector finished); a failing callback must never break a run."""
    if not on_result:
        return
    try:
        on_result(name, findings, error=error)
    except Exception:
        logger.exception("on_result callback failed for %s", name)


def _dedup_key(f: Finding) -> tuple[str, str]:
    """
    Identity of a finding for deduplication.

    Subdomain findings are keyed by hostname alone: each collector words its title
    differently ("Subdomain discovered: h" for crt.sh, "Subdomain: h → ip" for
    DNSDumpster). The match is on category + title prefix, not on the prefix alone,
    so summary findings ("DNSDumpster: 6 subdomains…", asset = the apex) never
    collide with a real hostname.
    """
    asset = f.affected_asset.strip().lower()
    title = f.title.strip().lower()
    if f.category == Category.SUBDOMAIN and title.startswith("subdomain"):
        return ("subdomain", asset)
    return (title, asset)


def _deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """
    Drop findings repeating an earlier one (see _dedup_key). The first occurrence keeps
    its place — except that a later duplicate with a strictly higher severity replaces it,
    so merging never downgrades a finding (crt.sh and DNSDumpster flag different keywords).
    """
    index: dict[tuple[str, str], int] = {}
    result: list[Finding] = []
    for f in findings:
        key = _dedup_key(f)
        if key not in index:
            index[key] = len(result)
            result.append(f)
        elif (SEVERITY_ORDER.get(f.severity, 99)
              < SEVERITY_ORDER.get(result[index[key]].severity, 99)):
            result[index[key]] = f
    return result


def _live_deduplicator(on_result, on_progress=None):
    """
    Wrap the live callbacks so a finding already shown is not shown again (phase 1 only).

    Returns (on_result, on_progress), both None when their input is None. They share one
    "seen" set: a subdomain streamed by crt.sh is not streamed again by DNSDumpster, and
    the collector-finished callback only lists what was not displayed yet. Errors and empty
    results are always forwarded (never silent); a collector whose findings were ALL
    duplicates of something already shown is not announced a second time.
    """
    seen: set[tuple[str, str]] = set()
    streamed: set[int] = set()          # ids of findings forwarded through on_progress

    def progress(message, finding=None):
        if finding is None:
            on_progress(message, None)
            return
        key = _dedup_key(finding)
        if key in seen:
            return                       # another collector already displayed it
        seen.add(key)
        streamed.add(id(finding))
        on_progress(message, finding)

    def filtered(name, findings, error=None):
        unique = []
        for f in findings:
            if id(f) in streamed:        # displayed by progress(): keep, the UI knows it
                unique.append(f)
                continue
            key = _dedup_key(f)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        if error is None and findings and not unique:
            return
        on_result(name, unique, error=error)

    return (filtered if on_result else None), (progress if on_progress else None)


def _aggregate_pivot_errors(errors: dict[str, str], stats: dict[str, dict[str, int]]) -> None:
    """
    Replace the per-person "Collector:Person" error entries by one entry per
    collector: "Collector (pivot)" → "3/10 persons failed — <first reason>".
    """
    for name, st in stats.items():
        if not st["errors"]:
            continue
        prefix = f"{name}:"
        individual = [k for k in errors if k.startswith(prefix)]
        reason = errors[individual[0]] if individual else ""
        for key in individual:
            del errors[key]
        errors[f"{name} (pivot)"] = (
            f"{st['errors']}/{st['calls']} persons failed" + (f" — {reason}" if reason else "")
        )


async def _run_person_pivot(
    target: OsintTarget,
    persons: list[OsintPerson],
    registry: PersonRegistry,
    current_level: int,
    on_result,
    errors: dict,
    stats: dict[str, dict[str, int]] | None = None,
    on_progress: Callable[..., None] | None = None,
) -> list[Finding]:
    """
    Recursive person pivot. Returns all findings found at this level and below.

    `errors` receives one "Collector:Person" entry per failed call; `stats` counts
    calls and failures per collector (the caller aggregates both, see
    _aggregate_pivot_errors).

    Level 1 searches the persons found in phase 1; level 2 searches the persons
    discovered at level 1, and so on up to target.pivot_depth. The registry
    guarantees a person is searched at most once (no infinite loops).
    """
    if current_level > target.pivot_depth or not persons:
        return []

    stats = stats if stats is not None else {}

    if len(persons) > target.pivot_limit:
        _announce(on_progress, "INFO",
                  f"Pivot level {current_level}: "
                  f"capped at {target.pivot_limit}/{len(persons)} persons.")
        persons = persons[: target.pivot_limit]

    findings: list[Finding] = []
    next_persons: list[OsintPerson] = []

    available = [c for c in PERSON_COLLECTORS if c.is_available()]

    for person in persons:
        for collector in available:
            await asyncio.sleep(collector.request_delay)   # stealth / rate limit
            label = f"{collector.name} → {person.full_name}"
            st = stats.setdefault(collector.name, {"calls": 0, "errors": 0})
            st["calls"] += 1
            try:
                result = await collector.collect_person(person, target)
            except Exception as exc:
                st["errors"] += 1
                errors[f"{collector.name}:{person.full_name}"] = (
                    f"{type(exc).__name__}: {exc}"
                )
                logger.error("Person collector %s failed for %s: %s",
                             collector.name, person.full_name, exc)
                _notify(on_result, label, [], exc)
                continue

            findings.extend(result.findings)
            _notify(on_result, label, result.findings, None)

            # Register newly discovered persons for the next level
            new = registry.add_many(result.persons)
            for p in new:
                p.depth_found = current_level + 1
            next_persons.extend(new)

    if next_persons and current_level < target.pivot_depth:
        findings.extend(await _run_person_pivot(
            target, next_persons, registry, current_level + 1, on_result, errors, stats,
            on_progress=on_progress,
        ))

    return findings


def _matches_mode(collector, target: OsintTarget) -> bool:
    """
    Decide whether this collector should run given the target's mode and flags.

    Rules:
      - french_only collectors are skipped unless target.french is True.
      - collectors with skip_without_pivot = True (read with getattr, it is not declared on
        the base classes) are skipped when target.pivot_depth == 0.
      - requires_crawl collectors are skipped unless target.crawl is True.
      - In "short" mode only Tier 1 collectors run.
      - In "deep"  mode all tiers (1, 2, 3) run.
    """
    if collector.french_only and not target.french:
        return False
    if getattr(collector, "skip_without_pivot", False) and target.pivot_depth == 0:
        return False
    if collector.requires_crawl and not target.crawl:
        return False
    if target.mode == "short":
        return collector.tier == 1
    return True  # "deep" runs everything that is available


def _extract_assets(findings: list[Finding]) -> dict[str, list[str]]:
    """
    Build a deduplicated asset map from the finding list.
    Consumed by the JSON exporter and the PDF template.
    """
    buckets: dict[str, set[str]] = {
        "subdomains":    set(),
        "emails":        set(),
        "ips":           set(),
    }

    for f in findings:
        if f.category == Category.SUBDOMAIN:
            buckets["subdomains"].add(f.affected_asset)
        elif f.category == Category.EMAIL:
            buckets["emails"].add(f.affected_asset)

    return {key: sorted(vals) for key, vals in buckets.items()}
