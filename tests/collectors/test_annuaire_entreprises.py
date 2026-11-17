import httpx
import pytest

from core.collectors import ALL_COLLECTORS
from core.collectors.base import CollectorSkipped
from core.collectors.annuaire_entreprises import AnnuaireEntreprisesCollector
from core.models import Category, OsintTarget, Severity

API = r"https://recherche-entreprises\.api\.gouv\.fr/search.*"


def _target(**kw) -> OsintTarget:
    kw.setdefault("siren", "123456789")        # the collector only runs with a SIREN
    return OsintTarget(company_name=kw.pop("company_name", "Acme"),
                       domain="acme.fr", french=True, **kw)


def _company(siren="123456789", nom="ACME SAS", **kw) -> dict:
    base = {
        "siren": siren,
        "nom_complet": nom,
        "nom_raison_sociale": nom,
        "nature_juridique": "5710",
        "date_creation": "2001-02-03",
        "activite_principale": "62.01Z",
        "etat_administratif": "A",
        "siege": {
            "adresse": "1 RUE DE LA PAIX 75002 PARIS",
            "code_postal": "75002",
            "libelle_commune": "PARIS",
        },
        "dirigeants": [
            {"prenoms": "ALICE", "nom": "MARTIN", "qualite": "Président"},
        ],
    }
    base.update(kw)
    return base


def _query(route) -> dict:
    return dict(route.calls[0].request.url.params)


def test_metadata_and_registration():
    c = AnnuaireEntreprisesCollector()
    assert (c.tier, c.requires_api_key, c.french_only) == (1, False, True)
    assert any(isinstance(x, AnnuaireEntreprisesCollector) for x in ALL_COLLECTORS)


async def test_only_the_result_with_the_exact_siren_is_used(respx_mock):
    """Two results: only the one with the requested SIREN is used."""
    route = respx_mock.get(url__regex=API).respond(json={"results": [
        _company("999999999", "OTHER CORP"),
        _company("123456789", "ACME SAS"),
    ]})
    findings = (await AnnuaireEntreprisesCollector().collect(_target())).findings

    assert _query(route) == {"q": "123456789", "per_page": "5"}
    assert {f.affected_asset for f in findings} == {"123456789"}
    identity = findings[0]
    assert identity.severity is Severity.INFO
    assert identity.category is Category.COMPANY_INFO
    assert identity.mitre_attack == "T1591.001"
    assert identity.title == (
        "Annuaire Entreprises: ACME SAS — 5710, created 2001-02-03, NAF 62.01Z"
    )
    assert identity.source_url.endswith("/entreprise/123456789")


async def test_match_by_siren(respx_mock):
    route = respx_mock.get(url__regex=API).respond(json={"results": [
        _company("999999999", "UNRELATED"),
        _company("542051180", "TOTALENERGIES SE"),
    ]})
    findings = (await AnnuaireEntreprisesCollector().collect(
        _target(company_name="", siren="542 051 180"))).findings

    assert _query(route)["q"] == "542051180"          # spaces stripped, SIREN used as query
    assert {f.affected_asset for f in findings} == {"542051180"}


async def test_siege_and_directors(respx_mock):
    c = _company(dirigeants=[
        {"prenoms": "ALICE", "nom": "MARTIN", "qualite": "Président"},
        {"denomination": "HOLDING SA", "siren": "1", "qualite": "Commissaire aux comptes"},
    ])
    respx_mock.get(url__regex=API).respond(json={"results": [c]})
    findings = (await AnnuaireEntreprisesCollector().collect(_target())).findings
    titles = [f.title for f in findings]

    assert "Siege: 1 RUE DE LA PAIX 75002 PARIS" in titles          # no duplicated postcode
    assert "Director: ALICE MARTIN (Président)" in titles
    assert "Director: HOLDING SA (Commissaire aux comptes)" in titles
    assert all(f.mitre_attack == "T1591" for f in findings[1:])
    assert not any(f.severity is Severity.HIGH for f in findings)


async def test_siege_gets_postcode_when_missing_from_address(respx_mock):
    c = _company(siege={"adresse": "1 RUE X", "code_postal": "75002", "libelle_commune": "PARIS"})
    respx_mock.get(url__regex=API).respond(json={"results": [c]})
    findings = (await AnnuaireEntreprisesCollector().collect(_target())).findings
    assert "Siege: 1 RUE X, 75002 PARIS" in [f.title for f in findings]


async def test_directors_are_capped_at_ten(respx_mock):
    c = _company(dirigeants=[
        {"prenoms": f"P{i}", "nom": f"N{i}", "qualite": "Administrateur"} for i in range(16)
    ])
    respx_mock.get(url__regex=API).respond(json={"results": [c]})
    findings = (await AnnuaireEntreprisesCollector().collect(_target())).findings
    assert sum(f.title.startswith("Director:") for f in findings) == 10


async def test_no_siege_no_siege_finding(respx_mock):
    respx_mock.get(url__regex=API).respond(json={"results": [_company(siege=None, dirigeants=[])]})
    findings = (await AnnuaireEntreprisesCollector().collect(_target())).findings
    assert [f.title.split(":")[0] for f in findings] == ["Annuaire Entreprises"]


async def test_ceased_company(respx_mock):
    respx_mock.get(url__regex=API).respond(json={"results": [
        _company(etat_administratif="C", date_fermeture="2023-06-30"),
    ]})
    findings = (await AnnuaireEntreprisesCollector().collect(_target())).findings

    ceased = [f for f in findings if f.severity is Severity.HIGH]
    assert len(ceased) == 1
    assert ceased[0].title == "Company legally ceased: ACME SAS"
    assert ceased[0].mitre_attack == "T1591.001"
    assert "2023-06-30" in ceased[0].description


async def test_no_match(respx_mock):
    respx_mock.get(url__regex=API).respond(json={"results": []})
    assert (await AnnuaireEntreprisesCollector().collect(_target())).findings == []


async def test_siren_not_in_results_returns_empty(respx_mock):
    respx_mock.get(url__regex=API).respond(json={"results": [_company("999999999")]})
    assert (await AnnuaireEntreprisesCollector().collect(
        _target(company_name="", siren="123456789"))).findings == []


@pytest.mark.parametrize("status", [400, 429, 500, 503])
async def test_api_error(respx_mock, status):
    respx_mock.get(url__regex=API).respond(status)
    with pytest.raises(RuntimeError, match=f"Annuaire Entreprises API error {status}"):
        await AnnuaireEntreprisesCollector().collect(_target())


async def test_connection_error_is_wrapped(respx_mock):
    respx_mock.get(url__regex=API).mock(side_effect=httpx.ConnectError("refused"))
    with pytest.raises(RuntimeError, match="Annuaire Entreprises unreachable: ConnectError"):
        await AnnuaireEntreprisesCollector().collect(_target())


async def test_timeout_is_wrapped(respx_mock):
    respx_mock.get(url__regex=API).mock(side_effect=httpx.ReadTimeout(""))
    with pytest.raises(RuntimeError, match="unreachable: ReadTimeout"):
        await AnnuaireEntreprisesCollector().collect(_target())


@pytest.mark.parametrize("siren", [None, "", "   "])
async def test_annuaire_skipped_without_siren(respx_mock, siren):
    """No SIREN → skipped, even when a company name is provided (name search is imprecise)."""
    route = respx_mock.get(url__regex=API)
    with pytest.raises(CollectorSkipped, match="provide --siren for precise results"):
        await AnnuaireEntreprisesCollector().collect(_target(company_name="Leboncoin", siren=siren))
    assert route.call_count == 0                       # no request without a SIREN


async def test_siren_not_found_is_not_silent(respx_mock, caplog):
    respx_mock.get(url__regex=API).respond(json={"results": []})
    with caplog.at_level("WARNING", logger="core.collectors.annuaire_entreprises"):
        result = await AnnuaireEntreprisesCollector().collect(_target(siren="844156364"))
    assert result.findings == [] and "no match for '844156364'" in caplog.text
    assert "check the SIREN" in caplog.text


async def test_directors_also_become_persons(respx_mock):
    c = _company(dirigeants=[
        {"prenoms": "ALICE", "nom": "MARTIN", "qualite": "Président"},
        {"denomination": "HOLDING SA", "siren": "1", "qualite": "Commissaire aux comptes"},
        # external auditors (natural person) — listed as a finding, never a person to pivot on
        {"prenoms": "LAURENT", "nom": "MICHOT", "qualite": "Commissaire aux comptes titulaire"},
        {"prenoms": "Paul", "nom": "Durand", "qualite": "COMMISSAIRE AUX COMPTES SUPPLÉANT"},
        # a company written in the person fields
        {"prenoms": "SOCIÉTÉ", "nom": "FIDUCIAIRE CONSEIL AUDIT", "qualite": "Gérant"},
        {"prenoms": "", "nom": "CABINET DUPONT SCPA", "qualite": "Associé"},
        {"prenoms": "BOB", "nom": "DURAND", "qualite": "Directeur Général"},
    ])
    respx_mock.get(url__regex=API).respond(json={"results": [c]})
    result = await AnnuaireEntreprisesCollector().collect(_target())

    # legal entities and external auditors are listed as findings but are not persons to pivot on
    assert [(p.full_name, p.role, p.source) for p in result.persons] == [
        ("ALICE MARTIN", "Président", "Annuaire Entreprises"),
        ("BOB DURAND", "Directeur Général", "Annuaire Entreprises"),
    ]
    titles = [f.title for f in result.findings]
    assert "Director: LAURENT MICHOT (Commissaire aux comptes titulaire)" in titles   # still reported


# ── "Meilisearch" regression: real-looking API response ─────────────────────


async def test_directors_without_a_name_are_skipped(respx_mock):
    c = _company(dirigeants=[
        {"prenoms": "ALICE", "nom": "MARTIN", "qualite": "Président"},
        {"prenoms": None, "nom": None, "qualite": "Commissaire aux comptes titulaire"},
    ])
    respx_mock.get(url__regex=API).respond(json={"results": [c]})
    result = await AnnuaireEntreprisesCollector().collect(_target())

    directors = [f.title for f in result.findings if f.title.startswith("Director:")]
    assert directors == ["Director: ALICE MARTIN (Président)"]          # no "Director: — (…)"
    assert [p.full_name for p in result.persons] == ["ALICE MARTIN"]


async def test_legal_name_and_siren_find_the_real_meili_record(respx_mock):
    """Same company under its legal name: MEILI / 844156364."""
    meili = _company("844156364", "MEILI (MEILI)", nom_raison_sociale="MEILI", dirigeants=[
        {"prenoms": "QUENTIN", "nom": "DE QUELEN", "qualite": "Président de SAS"},
        {"prenoms": "CLEMENT", "nom": "RENAULT", "qualite": "Directeur Général"},
        {"prenoms": None, "nom": None, "qualite": "Commissaire aux comptes titulaire"},
    ])
    respx_mock.get(url__regex=API).respond(json={"results": [meili], "total_results": 1})

    by_siren = await AnnuaireEntreprisesCollector().collect(
        _target(company_name="Meilisearch", siren="844156364"))
    assert {f.affected_asset for f in by_siren.findings} == {"844156364"}
    assert len(by_siren.persons) == 2

    assert "Siege" in " ".join(f.title for f in by_siren.findings)
