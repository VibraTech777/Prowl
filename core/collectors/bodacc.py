"""
core/collectors/bodacc.py — BODACC public announcement collector.

Searches the French Official Gazette (BODACC) for company announcements:
insolvency proceedings, registrations, modifications.
No API key required — data.gouv.fr open data.
french_only = True: only runs when target.french is set.
"""

from __future__ import annotations

import logging

import httpx

from core.collectors.base import SKIP_REASON, BaseCollector, CollectorSkipped
from core.models import Category, CollectorResult, Finding, OsintTarget, Severity

logger = logging.getLogger(__name__)

_BODACC_API = (
    "https://bodacc-datadila.opendatasoft.com"
    "/api/explore/v2.1/catalog/datasets/annonces-commerciales/records"
)
_BODACC_WEB = "https://www.bodacc.fr"

# Keywords in typeavis that signal legal distress
_DISTRESS_KEYWORDS = {
    "procédure": Severity.HIGH,
    "liquidation": Severity.CRITICAL,
    "redressement": Severity.HIGH,
    "sauvegarde": Severity.HIGH,
    "dissolution": Severity.HIGH,
    "radiations": Severity.HIGH,   # struck off the commercial register
}


class BodaccCollector(BaseCollector):
    name = "BODACC"
    tier = 1
    requires_api_key = False
    french_only = True

    async def collect(self, target: OsintTarget) -> CollectorResult:
        findings: list[Finding] = []

        # SIREN only: a name search ("commercant like LEBONCOIN") returns unrelated companies
        # sharing the name, and their radiations would be reported as the target's.
        siren = (target.siren or "").strip()
        if not siren:
            raise CollectorSkipped(SKIP_REASON)
        where = f'registre like "{siren}"'

        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(
                    _BODACC_API,
                    params={
                        "select": "*",
                        "where":  where,
                        "orderby": "dateparution desc",
                        "limit":  20,
                    },
                )
                resp.raise_for_status()
                records = resp.json().get("results", [])

        except httpx.HTTPStatusError as exc:
            raise RuntimeError(
                f"BODACC HTTP {exc.response.status_code} for "
                f"{siren}"
            ) from exc
        except Exception as exc:
            raise RuntimeError(
                f"BODACC unreachable ({type(exc).__name__}: {exc})"
            ) from exc

        if not records:
            logger.info("BODACC: no announcements found for %s", target.company_name or target.siren)
            return CollectorResult(findings=[])

        for record in records:
            familleavis  = record.get("familleavis_lib", "").lower()
            typeavis     = familleavis   # keep variable name for severity check below
            denomination = record.get("commercant", target.company_name or "—")
            date        = record.get("dateparution", "—")
            numero      = record.get("numeroannonce", "")
            source_url  = f"{_BODACC_WEB}/annonce/{numero}" if numero else _BODACC_WEB

            # Title parts — registre is a list in the API (e.g. ["542 051 180", "542051180"])
            registre = record.get("registre") or ""
            if isinstance(registre, list):
                registre = next((r for r in registre if r), "")
            title_date      = record.get("dateparution") or ""
            title_famille   = record.get("familleavis_lib") or ""
            title_commercant = record.get("commercant") or ""

            # Determine severity from announcement type
            severity = Severity.INFO
            for kw, sev in _DISTRESS_KEYWORDS.items():
                if kw in typeavis:
                    severity = sev
                    break

            findings.append(Finding(
                id="",
                severity=severity,
                category=Category.COMPANY_INFO,
                title=f"BODACC [{title_date}] {registre} — {title_famille} — {title_commercant}",
                description=(
                    f"Publication date: {date}. "
                    f"Type: {record.get('familleavis_lib', '—')}. "
                    f"Announcement #{numero}."
                    + (
                        " ⚠ This type of announcement may indicate financial distress."
                        if severity in (Severity.HIGH, Severity.CRITICAL) else ""
                    )
                ),
                affected_asset=target.siren or denomination,
                source=self.name,
                source_url=source_url,
                mitre_attack="T1591",
                raw_data=record,
            ))

        logger.info("BODACC: %d announcements for %s", len(findings), target.company_name or target.siren)
        return CollectorResult(findings=findings)
