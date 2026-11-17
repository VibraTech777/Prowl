"""
core/collectors/pappers.py — Pappers.fr company intelligence collector.

Retrieves legal registration data for French companies via the
Pappers API v2. Requires a free API key from https://www.pappers.fr/api
french_only = True: only runs when target.french is set.
"""

from __future__ import annotations

import logging

import httpx

from core.collectors.base import SKIP_REASON, BaseCollector, CollectorSkipped
from core.collectors.person_registry import is_pivot_candidate
from core.models import (
    Category, CollectorResult, Finding, OsintPerson, OsintTarget, Severity,
)

logger = logging.getLogger(__name__)

_COMPANY_URL  = "https://api.pappers.fr/v2/entreprise"
_PAPPERS_BASE = "https://www.pappers.fr/entreprise"


class PappersCollector(BaseCollector):
    name = "Pappers.fr"
    tier = 1
    requires_api_key = True
    api_key_env = "PAPPERS_API_KEY"
    french_only = True

    async def collect(self, target: OsintTarget) -> CollectorResult:
        import os
        siren = (target.siren or "").strip()
        if not siren:                      # SIREN only: no name search (namesake companies)
            raise CollectorSkipped(SKIP_REASON)
        api_key = os.environ[self.api_key_env]
        findings: list[Finding] = []

        try:
            async with httpx.AsyncClient(timeout=15) as client:
                data = await self._fetch_company(client, api_key, siren)

        except RuntimeError:
            raise
        except Exception as exc:
            logger.warning("Pappers request failed (%s: %s)", type(exc).__name__, exc)
            return CollectorResult(findings=[])

        if not data:
            return CollectorResult(findings=[])

        nom        = data.get("nom_entreprise") or data.get("denomination", "—")
        siege      = data.get("siege", {})
        adresse    = siege.get("adresse_ligne_1", "—")
        ville      = siege.get("ville", "—")
        capital    = data.get("capital", "—")
        naf        = data.get("libelle_code_naf", "—")
        creation   = data.get("date_creation", "—")
        statut     = data.get("statut_rcs", "").lower()
        dirigeants = data.get("dirigeants", [])
        source_url = f"{_PAPPERS_BASE}/{nom.replace(' ', '-').lower()}-{siren}"

        # Base company info finding
        leaders = ", ".join(
            f"{d.get('prenom','')} {d.get('nom','')} ({d.get('qualite','')})"
            for d in dirigeants[:3]
        ) or "—"

        findings.append(Finding(
            id="",
            severity=Severity.INFO,
            category=Category.COMPANY_INFO,
            title=f"French company record: {nom}",
            description=(
                f"SIREN: {siren}. Created: {creation}. Capital: {capital}. "
                f"Activity: {naf}. Address: {adresse}, {ville}. "
                f"Directors: {leaders}."
            ),
            affected_asset=siren,
            source=self.name,
            source_url=source_url,
            mitre_attack="T1591",  # Gather Victim Org Info
            raw_data=data,
        ))

        # Flag problematic legal status
        if any(kw in statut for kw in ("radié", "radiation")):
            findings.append(Finding(
                id="",
                severity=Severity.HIGH,
                category=Category.COMPANY_INFO,
                title=f"Company struck off (radié): {nom}",
                description=(
                    f"{nom} (SIREN {siren}) has been struck off the RCS (Registre du Commerce). "
                    "The company no longer exists legally. Any web presence may be abandoned "
                    "or controlled by a third party."
                ),
                affected_asset=siren,
                source=self.name,
                source_url=source_url,
                mitre_attack="T1584",
                raw_data={"statut_rcs": statut},
            ))

        # Directors → persons for the pivot (natural persons only)
        persons: list[OsintPerson] = []
        for d in dirigeants[:10]:
            full_name = " ".join(p for p in (d.get("prenom"), d.get("nom")) if p).strip()
            if full_name and is_pivot_candidate(full_name, d.get("qualite", "") or ""):
                persons.append(OsintPerson(
                    full_name=full_name,
                    role=d.get("qualite", "") or "",
                    source=self.name,
                ))

        logger.info("Pappers: %d findings, %d persons for SIREN %s",
                    len(findings), len(persons), siren)
        return CollectorResult(findings=findings, persons=persons)

    async def _fetch_company(
        self, client: httpx.AsyncClient, api_key: str, siren: str
    ) -> dict:
        """Return the full company object from Pappers."""
        resp = await client.get(
            _COMPANY_URL,
            params={"api_token": api_key, "siren": siren},
        )
        resp.raise_for_status()
        return resp.json()
