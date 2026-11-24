import httpx
import pytest

from core.collectors import PERSON_COLLECTORS
from core.collectors.email_format import (
    EmailFormatCollector, name_parts, parse_dominant_pattern, parse_format,
)
from core.models import Category, OsintPerson, OsintTarget, Severity

URL = "https://www.email-format.com/d/example.com/"


def _page(*formats: tuple[str, int]) -> str:
    """HTML shaped like the real page: one format_score_container per format."""
    blocks = "".join(
        f"<div class=\"format_score_container\">  <div class='format fl'>{label} </div>"
        f"  <div class='score_container fl'><div class='confidence_value fl'>{pct}%</div></div>"
        f"  <div class='format_example fl'>e.g. <a class=\"__cf_email__\">[email&#160;protected]</a></div>"
        f"</div>"
        for label, pct in formats
    )
    return f"<html><body><div id='format_scores_container'>{blocks}</div></body></html>"


@pytest.fixture
def target():
    return OsintTarget(company_name="Acme", domain="example.com")


def _person(name="Jane Doe", email=""):
    return OsintPerson(full_name=name, source="test", email=email)


async def _run(respx_mock, html, person=None, target_=None):
    respx_mock.get(URL).respond(text=html)
    c = EmailFormatCollector()
    p = person or _person()
    t = target_ or OsintTarget(company_name="Acme", domain="example.com")
    return p, await c.collect_person(p, t)


# ── one test per pattern type ────────────────────────────────────────────────


@pytest.mark.parametrize("label, expected", [
    ("first_name  . last_name", "jane.doe@example.com"),       # first.last
    ("first_initial  last_name", "jdoe@example.com"),           # flast
    ("first_name", "jane@example.com"),                          # first
    ("first_initial  . last_name", "j.doe@example.com"),        # f.last
    ("first_name  _ last_name", "jane_doe@example.com"),        # first_last
    ("last_name  . first_name", "doe.jane@example.com"),        # last.first
    ("first_name  - last_name", "jane-doe@example.com"),
    ("first_name  last_initial", "janed@example.com"),
    ("last_name", "doe@example.com"),
])
async def test_each_pattern(respx_mock, label, expected):
    _, result = await _run(respx_mock, _page((label, 80)))
    assert [f.affected_asset for f in result.findings] == [expected]


async def test_finding_fields(respx_mock):
    person, result = await _run(respx_mock, _page(("first_name  . last_name", 62)))
    f = result.findings[0]
    assert (f.title, f.severity, f.source) == ("Email pattern candidate", Severity.INFO, "EmailFormat")
    assert f.category is Category.COMPANY_INFO                 # a guess is not a discovered EMAIL asset
    assert f.description.startswith(
        "jane.doe@example.com — pattern: {first}.{last} (confidence: 62%)")
    assert "Jane Doe" in f.description and "example.com" in f.description
    assert f.source_url == URL and f.raw_data["pattern"] == "first.last"
    assert result.persons == []


# ── pattern detection ────────────────────────────────────────────────────────


def test_dominant_pattern_is_the_highest_confidence():
    html = _page(("first_initial  last_name", 21), ("first_name  . last_name", 60))
    assert parse_dominant_pattern(html) == ("{first}.{last}", 60)


def test_unsupported_formats_are_ignored():
    html = _page(("first_name  middle_name", 90), ("first_initial  last_name", 10))
    assert parse_dominant_pattern(html) == ("{f}{last}", 10)


@pytest.mark.parametrize("raw", ["", "foo", "first_name + last_name", "last_name  last_initial x"])
def test_parse_format_rejects_unknown(raw):
    assert parse_format(raw) is None


def test_page_without_any_pattern():
    assert parse_dominant_pattern("<html><body>nothing here</body></html>") is None


# ── person handling ──────────────────────────────────────────────────────────


@pytest.mark.parametrize("name", ["Madonna", "", "   ", "李 雷"])
async def test_single_or_unusable_name_is_skipped(respx_mock, name):
    route = respx_mock.get(URL).respond(text=_page(("first_name  . last_name", 80)))
    person = _person(name)
    result = await EmailFormatCollector().collect_person(person, OsintTarget("Acme", "example.com"))
    assert result.findings == [] and person.email == ""
    assert route.call_count == 0                     # nothing to guess: no HTTP request either


def test_name_normalisation():
    assert name_parts("Jean-Pierre Dupont") == ("jeanpierre", "dupont")
    assert name_parts("Élodie O'Brien") == ("elodie", "obrien")
    assert name_parts("Marie de la Tour") == ("marie", "tour")
    assert name_parts("Solo") is None


async def test_person_email_is_never_set(respx_mock):
    person, result = await _run(respx_mock, _page(("first_name  . last_name", 80)))
    assert len(result.findings) == 1
    assert person.email == ""                                   # the guess stays out of the pivot chain

    known, _ = await _run(respx_mock, _page(("first_name  . last_name", 80)),
                          person=_person(email="real@example.com"))
    assert known.email == "real@example.com"                    # and a known address is untouched


async def test_guess_is_kept_for_display_but_never_in_email(respx_mock):
    person, _ = await _run(respx_mock, _page(("first_name  . last_name", 80)))
    assert person.email == "" and person.email_guess == "jane.doe@example.com"


async def test_no_guess_recorded_below_threshold(respx_mock):
    person, _ = await _run(respx_mock, _page(("first_name  . last_name", 45)))
    assert person.email_guess == ""


async def test_confidence_below_threshold_returns_empty(respx_mock):
    person, result = await _run(respx_mock, _page(("first_name  . last_name", 45)))
    assert result.findings == [] and result.persons == [] and person.email == ""


async def test_confidence_above_threshold_emits_finding_without_setting_email(respx_mock):
    person, result = await _run(respx_mock, _page(("first_name  . last_name", 55)))
    assert [f.affected_asset for f in result.findings] == ["jane.doe@example.com"]
    assert person.email == ""


def test_threshold_boundary_is_inclusive():
    from core.collectors.email_format import MIN_CONFIDENCE
    assert MIN_CONFIDENCE == 50


async def test_confidence_exactly_at_threshold_is_kept(respx_mock):
    _, result = await _run(respx_mock, _page(("first_name  . last_name", 50)))
    assert len(result.findings) == 1


async def test_domain_is_looked_up_once_for_all_persons(respx_mock, target):
    route = respx_mock.get(URL).respond(text=_page(("first_name  . last_name", 80)))
    c = EmailFormatCollector()
    for name in ("Jane Doe", "John Smith", "Ann Lee"):
        await c.collect_person(_person(name), target)
    assert route.call_count == 1


# ── failures: empty result, never an exception ───────────────────────────────


@pytest.mark.parametrize("status", [403, 404, 500, 302])
async def test_http_error_returns_empty(respx_mock, target, status, caplog):
    respx_mock.get(URL).respond(status)
    person = _person()
    with caplog.at_level("WARNING", logger="core.collectors.email_format"):
        result = await EmailFormatCollector().collect_person(person, target)
    assert result.findings == [] and result.persons == [] and person.email == ""
    assert f"HTTP {status}" in caplog.text                       # logged, not silent


async def test_connection_error_returns_empty(respx_mock, target, caplog):
    respx_mock.get(URL).mock(side_effect=httpx.ConnectError("down"))
    with caplog.at_level("WARNING", logger="core.collectors.email_format"):
        result = await EmailFormatCollector().collect_person(_person(), target)
    assert result.findings == []
    assert "ConnectError" in caplog.text


async def test_no_pattern_found_returns_empty(respx_mock, target):
    respx_mock.get(URL).respond(text="<html><body>Domain not found</body></html>")
    assert (await EmailFormatCollector().collect_person(_person(), target)).findings == []


async def test_invalid_domain_never_reaches_the_url(respx_mock):
    route = respx_mock.route().respond(200)
    bad = OsintTarget(company_name="x", domain="evil.com/../x?y=1")
    assert (await EmailFormatCollector().collect_person(_person(), bad)).findings == []
    assert route.call_count == 0


# ── metadata ─────────────────────────────────────────────────────────────────


def test_metadata_and_registration():
    c = EmailFormatCollector()
    assert (c.name, c.tier, c.requires_api_key, c.request_delay) == ("EmailFormat", 1, False, 1.0)
    assert c.is_available() is True
    assert [p.name for p in PERSON_COLLECTORS] == ["GitHub", "GitHub Colleagues", "EmailFormat", "GitLeak", "WhatsMyName"]
