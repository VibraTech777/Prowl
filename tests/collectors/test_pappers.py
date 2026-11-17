import pytest

from core.collectors.pappers import PappersCollector
from core.models import Category, OsintTarget, Severity

BASE = r"https://api\.pappers\.fr/v2/.*"


def _target(**kw) -> OsintTarget:
    return OsintTarget(company_name="Acme", domain="acme.fr", french=True, **kw)


def test_availability_depends_on_key(monkeypatch):
    monkeypatch.delenv("PAPPERS_API_KEY", raising=False)
    assert PappersCollector().is_available() is False
    monkeypatch.setenv("PAPPERS_API_KEY", "k")
    assert PappersCollector().is_available() is True
    assert PappersCollector().french_only is True


async def test_company_record_finding(monkeypatch, respx_mock):
    monkeypatch.setenv("PAPPERS_API_KEY", "k")
    respx_mock.get(url__regex=BASE).respond(json={
        "nom_entreprise": "ACME SAS", "capital": 1000, "date_creation": "2001-01-01",
        "libelle_code_naf": "Conseil", "statut_rcs": "Inscrit",
        "siege": {"adresse_ligne_1": "1 rue X", "ville": "Paris"},
        "dirigeants": [{"prenom": "A", "nom": "B", "qualite": "Président"}],
    })
    findings = (await PappersCollector().collect(_target(siren="123456789"))).findings
    assert len(findings) == 1
    f = findings[0]
    assert f.severity is Severity.INFO and f.category is Category.COMPANY_INFO
    assert "123456789" in f.description and "Paris" in f.description


async def test_struck_off_company_is_high(monkeypatch, respx_mock):
    monkeypatch.setenv("PAPPERS_API_KEY", "k")
    respx_mock.get(url__regex=BASE).respond(json={
        "nom_entreprise": "OLD SAS", "statut_rcs": "Radié",
    })
    findings = (await PappersCollector().collect(_target(siren="123456789"))).findings
    assert [f.severity for f in findings] == [Severity.INFO, Severity.HIGH]


async def test_directors_become_persons_without_extra_findings(monkeypatch, respx_mock):
    monkeypatch.setenv("PAPPERS_API_KEY", "k")
    respx_mock.get(url__regex=BASE).respond(json={
        "nom_entreprise": "ACME SAS",
        "dirigeants": [
            {"prenom": "Alice", "nom": "Martin", "qualite": "Président"},
            {"denomination": "HOLDING SA", "qualite": "Associé"},   # legal entity → skipped
            {"prenom": "Laurent", "nom": "Michot", "qualite": "Commissaire aux comptes titulaire"},
            {"nom": "SOCIETE FIDUCIAIRE CONSEIL", "qualite": "Gérant"},    # company, not a person
            {"nom": "CABINET DUPONT SARL", "qualite": "Associé"},
            {"prenom": "Sam", "nom": "Sasson", "qualite": "Directeur"},   # "SA" inside a word: kept
        ],
    })
    result = await PappersCollector().collect(_target(siren="123456789"))
    assert len(result.findings) == 1                                   # findings unchanged
    assert [(p.full_name, p.role, p.source) for p in result.persons] == [
        ("Alice Martin", "Président", "Pappers.fr"),
        ("Sam Sasson", "Directeur", "Pappers.fr"),
    ]


@pytest.mark.parametrize("siren", [None, "", "   "])
async def test_pappers_skipped_without_siren(monkeypatch, respx_mock, siren):
    from core.collectors.base import CollectorSkipped

    monkeypatch.setenv("PAPPERS_API_KEY", "k")
    route = respx_mock.get(url__regex=BASE)
    with pytest.raises(CollectorSkipped, match="provide --siren for precise results"):
        await PappersCollector().collect(_target(siren=siren))      # company name is set
    assert route.call_count == 0
