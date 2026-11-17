import httpx
import pytest

from core.collectors.base import CollectorSkipped
from core.collectors.bodacc import BodaccCollector
from core.models import Category, OsintTarget, Severity

API = r"https://bodacc-datadila\.opendatasoft\.com/.*annonces-commerciales/records.*"


def _target(**kw) -> OsintTarget:
    return OsintTarget(company_name=kw.pop("company_name", "Acme"),
                       domain="acme.fr", french=True, **kw)


def _record(famille: str, numero: int = 1) -> dict:
    return {
        "familleavis_lib": famille,
        "commercant": "ACME SAS",
        "dateparution": "2024-05-01",
        "numeroannonce": numero,
    }


def test_flags_and_metadata():
    c = BodaccCollector()
    assert c.french_only is True
    assert c.requires_api_key is False


async def test_siren_query_and_severity_mapping(respx_mock):
    route = respx_mock.get(url__regex=API).respond(json={"results": [
        _record("Modifications diverses", 1),
        _record("Procédures collectives", 2),
        _record("Jugement de liquidation judiciaire", 3),
    ]})
    findings = (await BodaccCollector().collect(_target(siren="542051180"))).findings

    assert 'registre like "542051180"' in str(route.calls[0].request.url).replace("%22", '"').replace("%20", " ")
    sev = {f.raw_data["numeroannonce"]: f.severity for f in findings}
    assert sev == {1: Severity.INFO, 2: Severity.HIGH, 3: Severity.CRITICAL}
    assert all(f.category is Category.COMPANY_INFO for f in findings)
    assert "financial distress" in next(
        f for f in findings if f.raw_data["numeroannonce"] == 2).description
    assert findings[0].affected_asset == "542051180"


async def test_radiation_is_high(respx_mock):
    respx_mock.get(url__regex=API).respond(json={"results": [_record("Radiations")]})
    findings = (await BodaccCollector().collect(_target(siren="542051180"))).findings
    assert findings[0].severity is Severity.HIGH
    assert "financial distress" in findings[0].description


async def test_title_includes_date_registre_famille_and_commercant(respx_mock):
    rec = _record("Modifications diverses")
    rec["registre"] = ["542 051 180", "542051180"]      # API returns a list
    respx_mock.get(url__regex=API).respond(json={"results": [rec]})
    findings = (await BodaccCollector().collect(_target(siren="542051180"))).findings
    assert findings[0].title == (
        "BODACC [2024-05-01] 542 051 180 — Modifications diverses — ACME SAS"
    )


async def test_title_tolerates_missing_fields(respx_mock):
    respx_mock.get(url__regex=API).respond(json={"results": [{"numeroannonce": 9}]})
    findings = (await BodaccCollector().collect(_target(siren="542051180"))).findings
    assert findings[0].title.startswith("BODACC [] ")     # no KeyError / "None"
    assert "None" not in findings[0].title


async def test_query_uses_the_siren_not_the_name(respx_mock):
    route = respx_mock.get(url__regex=API).respond(json={"results": []})
    await BodaccCollector().collect(_target(siren="542051180"))
    url = str(route.calls[0].request.url).replace("%22", '"').replace("%20", " ")
    assert 'registre like "542051180"' in url and "commercant" not in url


@pytest.mark.parametrize("siren", [None, "", "   "])
async def test_bodacc_skipped_without_siren(respx_mock, siren):
    """No SIREN → skipped, even when a company name is provided (name search is imprecise)."""
    route = respx_mock.get(url__regex=API)
    with pytest.raises(CollectorSkipped, match="provide --siren for precise results"):
        await BodaccCollector().collect(_target(company_name="Leboncoin", siren=siren))
    assert route.call_count == 0


async def test_http_error_raises_runtime_error(respx_mock):
    respx_mock.get(url__regex=API).respond(404)
    with pytest.raises(RuntimeError, match="BODACC HTTP 404"):
        await BodaccCollector().collect(_target(siren="542051180"))


async def test_network_error_raises_runtime_error(respx_mock):
    respx_mock.get(url__regex=API).mock(side_effect=httpx.ConnectError("down"))
    with pytest.raises(RuntimeError, match="BODACC unreachable"):
        await BodaccCollector().collect(_target(siren="542051180"))
