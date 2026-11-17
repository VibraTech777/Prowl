"""
core/collectors/annuaire_entreprises.py — French government company registry.

Queries the public "Recherche d'entreprises" API (annuaire-entreprises.data.gouv.fr):
legal identity, registered office and officers of a French company.
No API key required. Licence Ouverte / Etalab 2.0.
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

_SEARCH_URL = "https://recherche-entreprises.api.gouv.fr/search"
_WEB_URL = "https://annuaire-entreprises.data.gouv.fr/entreprise"
_PER_PAGE = 5
_MAX_DIRECTORS = 10
_TIMEOUT = 10


class AnnuaireEntreprisesCollector(BaseCollector):
    name = "Annuaire Entreprises"
    tier = 1
    requires_api_key = False
    french_only = True

    async def collect(self, target: OsintTarget) -> CollectorResult:
        siren = (target.siren or "").replace(" ", "")

        # SIREN only: a name search can pick a different entity with a similar name
        # (e.g. "Leboncoin" → "CSE LEBONCOIN", a works council).
        if not siren:
            raise CollectorSkipped(SKIP_REASON)
        query = siren

        logger.debug("Annuaire Entreprises: GET %s q=%r per_page=%d (SIREN search)",
                     _SEARCH_URL, query, _PER_PAGE)
        results = await self._search(query)
        match = self._pick_match(results, siren)
        if match is None:
            # Not an error, but never silent: a brand name often differs from the
            # legal name in the registry (e.g. "Meilisearch" is registered as "MEILI").
            logger.warning(
                "Annuaire Entreprises: no match for %r (%d result(s)). The registry uses the "
                "legal name, not the brand — check the SIREN.",
                query, len(results),
            )
            return CollectorResult(findings=[])

        result = self._to_result(match)
        logger.info("Annuaire Entreprises: %d findings, %d persons for %s",
                    len(result.findings), len(result.persons), match.get("siren"))
        return result

    # ── HTTP ────────────────────────────────────────────────────────────────

    async def _search(self, query: str) -> list[dict]:
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(
                    _SEARCH_URL, params={"q": query, "per_page": _PER_PAGE}
                )
        except httpx.HTTPError as exc:
            raise RuntimeError(
                f"Annuaire Entreprises unreachable: {type(exc).__name__}: {exc}"
            ) from exc

        if resp.status_code >= 400:
            raise RuntimeError(f"Annuaire Entreprises API error {resp.status_code}")

        try:
            return resp.json().get("results", []) or []
        except ValueError as exc:
            raise RuntimeError("Annuaire Entreprises returned invalid JSON") from exc

    # ── Matching ────────────────────────────────────────────────────────────

    @staticmethod
    def _pick_match(results: list[dict], siren: str) -> dict | None:
        """The result with exactly that SIREN, or None."""
        return next(
            (r for r in results if str(r.get("siren", "")).replace(" ", "") == siren),
            None,
        )

    # ── Findings ────────────────────────────────────────────────────────────

    def _to_result(self, r: dict) -> CollectorResult:
        siren = str(r.get("siren", ""))
        nom = r.get("nom_complet") or r.get("nom_raison_sociale") or "—"
        url = f"{_WEB_URL}/{siren}"
        findings: list[Finding] = []
        persons: list[OsintPerson] = []

        def add(severity: Severity, title: str, description: str, mitre: str, raw: dict) -> None:
            findings.append(Finding(
                id="",
                severity=severity,
                category=Category.COMPANY_INFO,
                title=title,
                description=description,
                affected_asset=siren,
                source=self.name,
                source_url=url,
                mitre_attack=mitre,
                raw_data=raw,
            ))

        # 1. Identity
        forme = r.get("forme_juridique") or r.get("nature_juridique") or "—"
        created = r.get("date_creation") or "—"
        naf = r.get("code_naf") or r.get("activite_principale") or "—"
        naf_label = r.get("libelle_code_naf")
        naf_txt = f"NAF {naf}" + (f" ({naf_label})" if naf_label else "")
        add(
            Severity.INFO,
            f"Annuaire Entreprises: {nom} — {forme}, created {created}, {naf_txt}",
            f"SIREN {siren}. Legal form {forme}. Created {created}. {naf_txt}. "
            f"Status: {r.get('etat_administratif') or '—'}.",
            "T1591.001",
            r,
        )

        # 2. Registered office
        siege = r.get("siege")
        if siege:
            adresse = siege.get("adresse") or ""
            cp = siege.get("code_postal") or ""
            commune = siege.get("libelle_commune") or ""
            # the API's `adresse` usually already ends with "<postal code> <commune>"
            if cp and cp not in adresse:
                adresse = f"{adresse}, {cp} {commune}".strip(", ")
            add(
                Severity.INFO,
                f"Siege: {adresse or '—'}",
                f"Registered office of {nom} (SIREN {siren}): {adresse or '—'}.",
                "T1591",
                {"siege": siege},
            )

        # 3. Officers (natural persons and legal entities), capped
        for d in (r.get("dirigeants") or [])[:_MAX_DIRECTORS]:
            natural_name = " ".join(p for p in (d.get("prenoms"), d.get("nom")) if p)
            person = natural_name or d.get("denomination")
            if not person:      # e.g. "Commissaire aux comptes titulaire" listed without a name
                continue
            qualite = d.get("qualite") or "—"
            # legal entities and external auditors are not persons to pivot on
            if natural_name and is_pivot_candidate(natural_name, d.get("qualite") or ""):
                persons.append(OsintPerson(
                    full_name=natural_name,
                    role=d.get("qualite") or "",
                    source=self.name,
                ))
            add(
                Severity.INFO,
                f"Director: {person} ({qualite})",
                f"{person} is listed as {qualite} of {nom} (SIREN {siren}).",
                "T1591",
                d,
            )

        # 4. Legally ceased
        if r.get("etat_administratif") == "C":
            closed = r.get("date_fermeture") or "unknown date"
            add(
                Severity.HIGH,
                f"Company legally ceased: {nom}",
                f"{nom} (SIREN {siren}) is administratively closed (since {closed}). "
                "Any remaining web presence may be abandoned or controlled by a third party.",
                "T1591.001",
                {"etat_administratif": "C", "date_fermeture": r.get("date_fermeture")},
            )

        return CollectorResult(findings=findings, persons=persons)
