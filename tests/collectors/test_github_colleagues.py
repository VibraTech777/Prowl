import httpx
import pytest

from core.collectors import PERSON_COLLECTORS
from core.collectors.github_colleagues import GitHubColleaguesCollector
from core.collectors.github_person import GitHubPersonCollector
from core.models import Category, OsintPerson, OsintTarget, Severity


@pytest.fixture(autouse=True)
def setup(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_test_token_not_real")
    monkeypatch.setattr(GitHubColleaguesCollector, "request_delay", 0)


@pytest.fixture
def target():
    return OsintTarget(company_name="Acme", domain="acme.fr", pivot_depth=2)


@pytest.fixture
def person():
    return OsintPerson(full_name="Jane Doe", source="GitHub Org", github_login="jdoe", depth_found=1)


def _user(login, name="", company=None, kind="User"):
    return {"login": login, "name": name, "company": company, "type": kind,
            "html_url": f"https://github.com/{login}"}


def _github(respx_mock, *, orgs=("acme",), org_blog="https://acme.fr", members=(), contributors=(),
            users=None, forks=()):
    """Fake GitHub. `users` maps login → profile; returns the list of requested paths."""
    users = users or {}
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        seen.append(path)
        if path == "/users/jdoe/orgs":
            return httpx.Response(200, json=[{"login": o} for o in orgs])
        if path.startswith("/orgs/") and path.count("/") == 2:
            return httpx.Response(200, json={"login": path.split("/")[2], "blog": org_blog})
        if path.endswith("/public_members"):
            return httpx.Response(200, json=[{"login": m, "type": "User"} for m in members])
        if path.endswith("/repos") and path.startswith("/orgs/"):
            return httpx.Response(200, json=[{"name": "core", "fork": False}]
                                  + [{"name": f, "fork": True} for f in forks])
        if path.endswith("/contributors"):
            return httpx.Response(200, json=[{"login": c, "type": "User"} for c in contributors])
        if path.startswith("/users/"):
            profile = users.get(path.split("/")[2])
            return httpx.Response(200, json=profile) if profile else httpx.Response(404)
        return httpx.Response(404)

    respx_mock.route().mock(side_effect=handler)
    return seen


async def _run(person, target, **kw):
    c = GitHubColleaguesCollector()
    c.is_known = kw.get("is_known", lambda name: False)
    return await c.collect_person(person, target)


# ── when it runs ─────────────────────────────────────────────────────────────


def test_registered_after_github_person_and_needs_a_token(monkeypatch):
    names = [c.name for c in PERSON_COLLECTORS]
    assert names.index("GitHub Colleagues") == names.index("GitHub") + 1
    c = GitHubColleaguesCollector()
    assert c.is_available()
    monkeypatch.delenv("GITHUB_TOKEN")
    assert not c.is_available()


def test_applies_only_to_a_confirmed_account_whose_results_can_be_pivoted(person, target):
    c = GitHubColleaguesCollector()
    assert c.applies_to(person, target)
    assert not c.applies_to(OsintPerson(full_name="No Login", depth_found=1), target)      # unconfirmed
    assert not c.applies_to(person, OsintTarget(company_name="A", domain="acme.fr", pivot_depth=1))
    assert not c.applies_to(person, OsintTarget(company_name="A", domain="acme.fr", pivot_depth=0))
    deeper = OsintPerson(full_name="Level Two", github_login="x", depth_found=2)
    assert not c.applies_to(deeper, target) and c.applies_to(deeper, OsintTarget(
        company_name="A", domain="acme.fr", pivot_depth=3))


# ── colleagues ───────────────────────────────────────────────────────────────


async def test_members_of_a_domain_confirmed_org_become_colleagues(respx_mock, person, target):
    _github(respx_mock, members=["jdoe", "bsmith", "nobody"],
            users={"bsmith": _user("bsmith", "bob smith"), "nobody": _user("nobody", "")})
    result = await _run(person, target)

    (colleague,) = result.persons
    assert (colleague.full_name, colleague.github_login, colleague.github_org) == ("Bob Smith", "bsmith", "acme")
    assert colleague.depth_found == 2 and colleague.source == "GitHub Colleagues"
    assert colleague.role == "colleague (public member of GitHub org acme)"
    (f,) = result.findings
    assert f.title == "GitHub colleague: Bob Smith (@bsmith)" and f.severity is Severity.INFO
    assert f.category is Category.COMPANY_INFO and f.source_url == "https://github.com/bsmith"
    assert "found through Jane Doe (@jdoe)" in f.description and f.mitre_attack == "T1589.003"
    # the person themself and a member without a real name are not colleagues


async def test_an_org_that_is_not_confirmed_by_the_domain_is_never_expanded(respx_mock, person, target):
    seen = _github(respx_mock, org_blog="https://evil-acme.fr", members=["bsmith"],
                   users={"bsmith": _user("bsmith", "Bob Smith")})
    result = await _run(person, target)
    assert result.persons == [] and result.findings == []
    assert not any("public_members" in p for p in seen)                  # members of a stranger: never read


async def test_a_known_org_is_used_without_listing_the_persons_orgs(respx_mock, target):
    seen = _github(respx_mock, members=["bsmith"], users={"bsmith": _user("bsmith", "Bob Smith")})
    p = OsintPerson(full_name="Jane Doe", github_login="jdoe", github_org="acme", depth_found=1)
    assert [x.full_name for x in (await _run(p, target)).persons] == ["Bob Smith"]
    assert "/users/jdoe/orgs" not in seen


async def test_contributors_count_only_when_their_company_names_the_target(respx_mock, person, target):
    _github(respx_mock, contributors=["staff", "community", "nameless"],
            users={"staff": _user("staff", "Sam Staff", company="@acme"),
                   "community": _user("community", "Cleo Community", company="Somewhere Else"),
                   "nameless": _user("nameless", "", company="Acme")})
    result = await _run(person, target)
    assert [p.full_name for p in result.persons] == ["Sam Staff"]
    assert result.persons[0].role == "colleague (contributor of acme/core)"


async def test_people_already_found_elsewhere_are_skipped(respx_mock, person, target):
    _github(respx_mock, members=["bsmith", "cnew"],
            users={"bsmith": _user("bsmith", "Bob Smith"), "cnew": _user("cnew", "Cara New")})
    result = await _run(person, target, is_known=lambda name: name == "Bob Smith")
    assert [p.full_name for p in result.persons] == ["Cara New"]


async def test_bots_and_forks_are_ignored(respx_mock, person, target):
    seen = _github(respx_mock, contributors=["dependabot"], forks=["forked"],
                   users={"dependabot": _user("dependabot", "Dependabot", company="Acme", kind="Bot")})
    result = await _run(person, target)
    assert result.persons == [] and not any("forked" in p for p in seen)


async def test_the_number_of_new_colleagues_is_capped(respx_mock, person, target):
    logins = [f"m{i:02d}" for i in range(30)]
    _github(respx_mock, members=logins, users={l: _user(l, f"Member Number{chr(65 + i)}") for i, l in enumerate(logins)})
    assert len((await _run(person, target)).persons) == 10


async def test_findings_are_streamed_as_found(respx_mock, person, target):
    _github(respx_mock, members=["bsmith"], users={"bsmith": _user("bsmith", "Bob Smith")})
    c = GitHubColleaguesCollector()
    events = []
    c.on_progress = lambda message, finding=None: events.append(finding or message)
    result = await c.collect_person(person, target)
    assert events[0].startswith("[GitHub Colleagues] Looking for colleagues of Jane Doe")
    assert events[1] is result.findings[0]


# ── failures ─────────────────────────────────────────────────────────────────


async def test_rate_limit_is_an_error_and_a_closed_door_is_not(respx_mock, person, target):
    respx_mock.route().respond(403, headers={"x-ratelimit-remaining": "0"})
    with pytest.raises(RuntimeError, match="rate limit"):
        await _run(person, target)


async def test_network_error_message_has_the_type_only(respx_mock, person, target):
    respx_mock.route().mock(side_effect=httpx.ConnectError("secret detail"))
    with pytest.raises(RuntimeError, match="GitHub unreachable: ConnectError") as exc:
        await _run(person, target)
    assert "secret" not in str(exc.value)


async def test_only_the_github_api_is_contacted(respx_mock, person, target):
    seen = _github(respx_mock, members=["bsmith"], users={"bsmith": _user("bsmith", "Bob Smith")})
    await _run(person, target)
    assert seen and all(not p.startswith("//") for p in seen)


# ── GitHub Person feeds it ───────────────────────────────────────────────────


async def test_a_company_match_name_hit_is_remembered_as_the_confirmed_login(respx_mock, target):
    respx_mock.get("https://api.github.com/search/users").respond(
        200, json={"items": [{"login": "jane-d"}]})
    respx_mock.get("https://api.github.com/users/jane-d").respond(
        200, json={"login": "jane-d", "company": "@acme", "public_repos": 3, "followers": 1,
                   "html_url": "https://github.com/jane-d"})
    respx_mock.get("https://api.github.com/users/jane-d/repos").respond(200, json=[])
    p = OsintPerson(full_name="Jane Doe", source="Wayback Machine", depth_found=1)
    c = GitHubPersonCollector()
    result = await c.collect_person(p, target)
    assert p.github_login == "jane-d"                                   # ← what Colleagues builds on
    assert [f.severity for f in result.findings if "profile" in f.title] == [Severity.INFO]   # still unconfirmed


async def test_a_name_hit_without_company_match_is_not_remembered(respx_mock, target):
    respx_mock.get("https://api.github.com/search/users").respond(200, json={"items": [{"login": "homonym"}]})
    respx_mock.get("https://api.github.com/users/homonym").respond(
        200, json={"login": "homonym", "company": "Elsewhere", "public_repos": 1, "followers": 0})
    respx_mock.get("https://api.github.com/users/homonym/repos").respond(200, json=[])
    p = OsintPerson(full_name="Jane Doe", depth_found=1)
    await GitHubPersonCollector().collect_person(p, target)
    assert p.github_login == ""
