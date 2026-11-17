import re

import httpx
import pytest

from core.collectors import PERSON_COLLECTORS
from core.collectors.github_gitleak import GitLeakCollector, is_real_email
from core.models import Category, OsintPerson, OsintTarget, Severity


@pytest.fixture(autouse=True)
def setup(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.setattr(GitLeakCollector, "request_delay", 0)


@pytest.fixture
def target():
    return OsintTarget(company_name="Acme", domain="acme.fr")


@pytest.fixture
def person():
    return OsintPerson(full_name="Jane Doe", source="GitHub Org", github_login="jdoe")


def _commit(email, url="https://github.com/jdoe/r1/commit/abc"):
    return [{"html_url": url, "commit": {"author": {"name": "Jane", "email": email}}}]


def _site(respx_mock, repos, commits=None, statuses=None):
    """Fake GitHub. `commits` maps repo → JSON list; `statuses` maps repo → HTTP status."""
    commits, statuses, seen = commits or {}, statuses or {}, []

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        seen.append((path, dict(request.url.params)))
        if path == "/users/jdoe/repos":
            return httpx.Response(200, json=[{"name": r} for r in repos])
        if m := re.fullmatch(r"/repos/jdoe/([^/]+)/commits", path):
            if m[1] in statuses:
                return httpx.Response(statuses[m[1]], json={"message": "x"})
            return httpx.Response(200, json=commits.get(m[1], []))
        return httpx.Response(404)

    respx_mock.route().mock(side_effect=handler)
    return seen


# ── the 4 requested tests ────────────────────────────────────────────────────


async def test_gitleak_finds_email(respx_mock, person, target):
    seen = _site(respx_mock, ["r1"], {"r1": _commit("jane@acme.fr")})
    result = await GitLeakCollector().collect_person(person, target)

    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.severity is Severity.MEDIUM and f.title == "Real email found in public commits"
    assert f.description == "jane@acme.fr — found in commit history of jdoe"
    assert f.affected_asset == "jane@acme.fr" and f.source == "GitLeak"
    assert f.category is Category.EMAIL                       # a real address, unlike EmailFormat
    assert f.source_url == "https://github.com/jdoe/r1/commit/abc"
    assert person.email == "jane@acme.fr"                     # confirmed: stored on the person
    assert result.persons == []
    assert seen[0] == ("/users/jdoe/repos", {"sort": "pushed", "per_page": "5"})
    assert seen[1] == ("/repos/jdoe/r1/commits", {"author": "jdoe", "per_page": "1"})


async def test_gitleak_skips_noreply(respx_mock, person, target):
    _site(respx_mock, ["r1"], {"r1": _commit("12345+jdoe@users.noreply.github.com")})
    result = await GitLeakCollector().collect_person(person, target)
    assert result.findings == [] and person.email == ""


async def test_gitleak_skips_no_login(respx_mock, target):
    route = respx_mock.route().respond(200, json=[])
    for login in ("", "   "):
        p = OsintPerson(full_name="Jane Doe", github_login=login)
        result = await GitLeakCollector().collect_person(p, target)
        assert result.findings == [] and p.email == ""
    assert route.call_count == 0                              # no API call at all


async def test_gitleak_no_commits(respx_mock, person, target):
    _site(respx_mock, [])                                      # no repos
    assert (await GitLeakCollector().collect_person(person, target)).findings == []

    _site(respx_mock, ["r1", "r2"], {})                        # repos, but no commit by the author
    assert (await GitLeakCollector().collect_person(person, target)).findings == []
    assert person.email == ""


# ── more behaviour ───────────────────────────────────────────────────────────


async def test_stops_at_the_first_real_email(respx_mock, person, target):
    seen = _site(respx_mock, ["r1", "r2", "r3", "r4", "r5"], {
        "r1": _commit("1+jdoe@users.noreply.github.com"),
        "r2": _commit("jane@acme.fr"),
        "r3": _commit("other@acme.fr"),
    })
    result = await GitLeakCollector().collect_person(person, target)
    assert person.email == "jane@acme.fr"
    commit_calls = [p for p, _ in seen if p.endswith("/commits")]
    assert commit_calls == ["/repos/jdoe/r1/commits", "/repos/jdoe/r2/commits"]   # r3.. never asked
    assert result.findings[0].raw_data["repo"] == "r2"


async def test_at_most_five_repos(respx_mock, person, target):
    seen = _site(respx_mock, [f"r{i}" for i in range(8)], {})
    await GitLeakCollector().collect_person(person, target)
    assert sum(p.endswith("/commits") for p, _ in seen) == 5


@pytest.mark.parametrize("status", [404, 409, 451])
async def test_empty_missing_or_blocked_repo_is_skipped(respx_mock, person, target, status):
    _site(respx_mock, ["empty", "r2"], {"r2": _commit("jane@acme.fr")}, statuses={"empty": status})
    result = await GitLeakCollector().collect_person(person, target)
    assert len(result.findings) == 1 and person.email == "jane@acme.fr"


async def test_unknown_user_returns_empty(respx_mock, person, target, caplog):
    respx_mock.route().respond(404)
    with caplog.at_level("WARNING", logger="core.collectors.github_gitleak"):
        result = await GitLeakCollector().collect_person(person, target)
    assert result.findings == [] and "jdoe" in caplog.text


@pytest.mark.parametrize("status", [403, 429])
async def test_rate_limit_raises(respx_mock, person, target, status):
    respx_mock.route().respond(status)
    with pytest.raises(RuntimeError, match="GitHub rate limit exceeded"):
        await GitLeakCollector().collect_person(person, target)


async def test_server_error_and_connection_error_raise(respx_mock, person, target):
    respx_mock.route().respond(500)
    with pytest.raises(RuntimeError, match="GitHub API error 500"):
        await GitLeakCollector().collect_person(person, target)

    respx_mock.route().mock(side_effect=httpx.ConnectError("down"))
    with pytest.raises(RuntimeError, match="GitLeak unreachable: ConnectError"):
        await GitLeakCollector().collect_person(person, target)


async def test_token_is_read_per_call_and_sent(monkeypatch, respx_mock, person, target):
    c = GitLeakCollector()                                     # built BEFORE the token exists
    route = respx_mock.route().respond(200, json=[])
    await c.collect_person(person, target)
    assert "authorization" not in route.calls[0].request.headers
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_x")
    await c.collect_person(person, target)
    assert route.calls[-1].request.headers["authorization"] == "token ghp_x"


@pytest.mark.parametrize("email, real", [
    ("jane@acme.fr", True), (" Jane@Acme.FR ", True),
    ("12345+jdoe@users.noreply.github.com", False), ("JDOE@USERS.NOREPLY.GITHUB.COM", False),
    ("noreply@github.com", False), ("", False), (None, False),
    ("jane@localhost", False), ("jane@MacBook-Pro.local", False),
    ("jane@host.localdomain", False), ("not-an-email", False), ("a@b", False),
])
def test_is_real_email(email, real):
    assert is_real_email(email) is real


def test_metadata_and_registration(monkeypatch):
    monkeypatch.undo()                                          # drop the autouse request_delay=0
    c = GitLeakCollector()
    assert (c.name, c.tier, c.requires_api_key, c.request_delay) == ("GitLeak", 1, False, 0.5)
    assert c.skip_without_pivot is True and c.is_available() is True
    assert [p.name for p in PERSON_COLLECTORS][2:4] == ["GitLeak", "WhatsMyName"]
