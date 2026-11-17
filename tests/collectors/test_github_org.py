import re

import httpx
import pytest

from core.collectors.github_org import GitHubOrgCollector
from core.models import OsintTarget, Severity


@pytest.fixture(autouse=True)
def setup(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.setattr(GitHubOrgCollector, "request_delay", 0)


@pytest.fixture
def target():
    return OsintTarget(company_name="", domain="zed.dev")


def _site(respx_mock, *, orgs=None, members=None, users=None):
    """Fake GitHub. `orgs`/`users` map login → JSON; unknown org → 404. Returns requested paths."""
    orgs, members, users, seen = orgs or {}, members or {}, users or {}, []

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        seen.append(path)
        if m := re.fullmatch(r"/orgs/([^/]+)/public_members", path):
            return httpx.Response(200, json=members.get(m[1], []))
        if m := re.fullmatch(r"/orgs/([^/]+)", path):
            return (httpx.Response(200, json=orgs[m[1]]) if m[1] in orgs
                    else httpx.Response(404))
        if m := re.fullmatch(r"/users/([^/]+)", path):
            return (httpx.Response(200, json=users[m[1]]) if m[1] in users
                    else httpx.Response(404))
        return httpx.Response(404)

    respx_mock.route().mock(side_effect=handler)
    return seen


ZED = {"login": "zed-industries", "public_repos": 40, "blog": "https://zed.dev"}


# ── the 3 requested tests ────────────────────────────────────────────────────


async def test_org_found_members_returned(respx_mock, target):
    _site(respx_mock,
          orgs={"zed": {**ZED, "login": "zed"}},
          members={"zed": [{"login": "nathansobo", "type": "User"},
                           {"login": "maxbrunsfeld", "type": "User"}]},
          users={"nathansobo": {"login": "nathansobo", "name": "Nathan Sobo",
                                "html_url": "https://github.com/nathansobo"},
                 "maxbrunsfeld": {"login": "maxbrunsfeld", "name": "max brunsfeld"}})
    result = await GitHubOrgCollector().collect(target)

    assert [(p.full_name, p.role, p.email, p.source, p.depth_found) for p in result.persons] == [
        ("Nathan Sobo", "employee", "", "GitHub Org", 1),
        ("Max Brunsfeld", "employee", "", "GitHub Org", 1),
    ]
    assert [p.github_login for p in result.persons] == ["nathansobo", "maxbrunsfeld"]
    assert {p.github_org for p in result.persons} == {"zed"}               # the confirmed org
    member = next(f for f in result.findings if "Nathan Sobo" in f.title)
    assert "URL: https://github.com/nathansobo." in member.description
    other = next(f for f in result.findings if "Max Brunsfeld" in f.title)
    assert "URL: https://github.com/maxbrunsfeld." in other.description     # built from the login
    titles = [f.title for f in result.findings]
    assert titles[0] == "GitHub org: zed — 40 public repos, 2 members"
    assert "GitHub org member: Nathan Sobo (@nathansobo)" in titles
    assert all(f.severity is Severity.INFO and f.mitre_attack == "T1596"
               and f.affected_asset == "zed.dev" and f.source == "GitHub Org"
               for f in result.findings)
    assert result.findings[0].description.startswith(
        "GitHub organization matching 'zed.dev'. URL: https://github.com/zed.")


async def test_all_candidates_404(respx_mock):
    seen = _site(respx_mock)
    target = OsintTarget(company_name="Zed Industries", domain="zed.dev")
    result = await GitHubOrgCollector().collect(target)

    assert result.findings == [] and result.persons == []
    assert seen == ["/orgs/zed", "/orgs/zed-industries", "/orgs/zedhq", "/orgs/zed-inc",
                    "/orgs/zed-labs", "/orgs/zedapp", "/orgs/getzed", "/orgs/zedio"]   # all 8 tried


async def test_null_name_uses_login(respx_mock, target):
    _site(respx_mock, orgs={"zed": {**ZED, "login": "zed"}},
          members={"zed": [{"login": "ghost42", "type": "User"}]},
          users={"ghost42": {"login": "ghost42", "name": None}})
    result = await GitHubOrgCollector().collect(target)

    member = result.findings[1]
    assert member.title == "GitHub org member: ghost42 (@ghost42) (username only)"
    assert result.persons == []                  # a bare username is not a person to pivot on


# ── more behaviour ───────────────────────────────────────────────────────────


async def test_first_200_wins_and_stops(respx_mock):
    seen = _site(respx_mock, orgs={"zed-industries": ZED}, members={"zed-industries": []})
    target = OsintTarget(company_name="Zed Industries", domain="zed.dev")
    result = await GitHubOrgCollector().collect(target)

    assert seen[:2] == ["/orgs/zed", "/orgs/zed-industries"]           # "zed" 404, 2nd wins
    assert "/orgs/zedindustries" not in seen
    assert result.findings[0].title.startswith("GitHub org: zed-industries")


async def test_candidates_are_sanitised():
    c = GitHubOrgCollector._candidates
    # characters that are not valid in a GitHub login never reach the URL path
    assert "acme-co-x" in c(OsintTarget("Acme & Co/../x", "acme.com"))           # slug: specials → "-"
    for cand in c(OsintTarget("Acme & Co/../x", "acme.com")):
        assert re.fullmatch(r"[a-z0-9-]+", cand)
    assert c(OsintTarget("", "my_site.com"))[0] == "mysite"                      # "_" stripped
    assert c(OsintTarget("", "-.com")) == []


def test_candidates_include_suffixes():
    assert GitHubOrgCollector._candidates(OsintTarget("", "zed.dev")) == [
        "zed", "zed-industries", "zedhq", "zed-inc", "zed-labs", "zedapp", "getzed", "zedio"]


def test_company_name_slug_added():
    cands = GitHubOrgCollector._candidates(OsintTarget("Acme Robotics", "zed.dev"))
    assert cands[:2] == ["zed", "acme-robotics"]            # slug right after the domain base
    assert len(cands) == 8 and len(set(cands)) == 8         # cap holds, no duplicates
    assert "zed-industries" in GitHubOrgCollector._candidates(OsintTarget("Zed Industries", "zed.dev"))


def test_dedup_candidates():
    cands = GitHubOrgCollector._candidates(OsintTarget("Zed", "zed.dev"))
    assert cands.count("zed") == 1 and len(cands) == len(set(cands))
    # "Zed Industries" slug equals the "{base}-industries" suffix: listed once
    both = GitHubOrgCollector._candidates(OsintTarget("Zed Industries", "zed.dev"))
    assert both.count("zed-industries") == 1 and len(both) == len(set(both))


def test_candidates_capped_at_8_and_invalid_logins_dropped():
    cands = GitHubOrgCollector._candidates(OsintTarget("A Very Long Company Name Inc", "zed.dev"))
    assert len(cands) == 8
    long_base = "x" * 40
    assert all(len(c) <= 39 for c in GitHubOrgCollector._candidates(OsintTarget("", f"{long_base}.com")))


async def test_stops_after_confirmed_org(respx_mock):
    seen = _site(respx_mock, orgs={"zed-industries": ZED, "zedhq": {**ZED, "login": "zedhq"}},
                 members={"zed-industries": []})
    target = OsintTarget(company_name="Zed Industries", domain="zed.dev")
    result = await GitHubOrgCollector().collect(target)

    assert result.findings[0].title.startswith("GitHub org: zed-industries")
    assert [p for p in seen if p.startswith("/orgs/") and "/" not in p[6:]] == [
        "/orgs/zed", "/orgs/zed-industries"]                 # nothing after the confirmed org
    assert "/orgs/zedhq" not in seen


async def test_unconfirmed_org_does_not_stop_the_search(respx_mock):
    """`zed` exists but belongs to someone else: keep looking, and pivot on the confirmed one."""
    _site(respx_mock,
          orgs={"zed": {**ZED, "login": "zed", "blog": "https://unrelated.io"},
                "zed-labs": {**ZED, "login": "zed-labs"}},
          members={"zed-labs": [{"login": "alice", "type": "User"}], "zed": []},
          users={"alice": {"login": "alice", "name": "Alice A"}})
    result = await GitHubOrgCollector().collect(OsintTarget("", "zed.dev"))

    assert result.findings[0].title.startswith("GitHub org: zed-labs")
    assert [p.full_name for p in result.persons] == ["Alice A"]


async def test_unconfirmed_org_is_a_fallback_without_persons(respx_mock):
    seen = _site(respx_mock,
                 orgs={"zedio": {**ZED, "login": "zedio", "blog": ""}},
                 members={"zedio": [{"login": "alice", "type": "User"}]},
                 users={"alice": {"login": "alice", "name": "Alice A"}})
    result = await GitHubOrgCollector().collect(OsintTarget("", "zed.dev"))

    assert len(result.findings) == 1                                      # org only, no members
    assert result.findings[0].title.startswith("GitHub org: zedio")
    assert "name only" in result.findings[0].description
    assert result.persons == []
    assert "/orgs/zedio" in seen and "/users/alice" not in seen


async def test_delay_between_org_candidates(respx_mock, monkeypatch):
    sleeps = []

    async def fake_sleep(delay):
        sleeps.append(delay)

    monkeypatch.setattr("core.collectors.github_org.asyncio.sleep", fake_sleep)
    monkeypatch.setattr(GitHubOrgCollector, "request_delay", 2.5)
    _site(respx_mock)                                                     # every org → 404
    await GitHubOrgCollector().collect(OsintTarget("", "zed.dev"))
    assert sleeps == [2.5] * 7                                            # 8 candidates → 7 pauses


async def test_only_user_members_are_listed(respx_mock, target):
    _site(respx_mock, orgs={"zed": {**ZED, "login": "zed"}},
          members={"zed": [{"login": "alice", "type": "User"},
                           {"login": "ci-bot", "type": "Bot"},
                           {"login": "some-org", "type": "Organization"}]},
          users={"alice": {"login": "alice", "name": "Alice A"}})
    result = await GitHubOrgCollector().collect(target)
    assert [p.full_name for p in result.persons] == ["Alice A"]
    assert not any("ci-bot" in f.title or "some-org" in f.title for f in result.findings)


async def test_members_are_capped_at_20(respx_mock, target):
    logins = [f"user{i:02d}" for i in range(30)]
    seen = _site(respx_mock, orgs={"zed": {**ZED, "login": "zed"}},
                 members={"zed": [{"login": l, "type": "User"} for l in logins]},
                 users={l: {"login": l, "name": l.upper()} for l in logins})
    result = await GitHubOrgCollector().collect(target)
    assert len(result.persons) == 20
    assert sum(p.startswith("/users/") for p in seen) == 20
    assert result.findings[0].title.endswith("20 members")


async def test_uses_public_members_endpoint(respx_mock, target):
    seen = _site(respx_mock, orgs={"zed": {**ZED, "login": "zed"}}, members={"zed": []})
    await GitHubOrgCollector().collect(target)
    assert "/orgs/zed/public_members" in seen and "/orgs/zed/members" not in seen


async def test_domain_confirmation_note(respx_mock, target):
    _site(respx_mock, orgs={"zed": {**ZED, "login": "zed", "blog": "https://zed.dev"}},
          members={"zed": []})
    confirmed = (await GitHubOrgCollector().collect(target)).findings[0]
    assert "Domain confirmed" in confirmed.description and confirmed.raw_data["domain_confirmed"]

    _site(respx_mock, orgs={"zed": {**ZED, "login": "zed", "blog": "https://other.io"}},
          members={"zed": []})
    unverified = (await GitHubOrgCollector().collect(target)).findings[0]
    assert "name only" in unverified.description and not unverified.raw_data["domain_confirmed"]


async def test_token_is_read_per_call(monkeypatch, respx_mock, target):
    collector = GitHubOrgCollector()                       # built BEFORE the token exists
    route = respx_mock.get(url__regex=r"https://api\.github\.com/orgs/.*").respond(404)

    await collector.collect(target)
    assert "authorization" not in route.calls[0].request.headers

    monkeypatch.setenv("GITHUB_TOKEN", "ghp_x")             # what load_dotenv() does later
    await collector.collect(target)
    assert route.calls[-1].request.headers["authorization"] == "token ghp_x"
    assert collector.requires_api_key is False


async def test_unconfirmed_org_emits_only_the_org_finding(respx_mock, target):
    seen = _site(respx_mock, orgs={"zed": {**ZED, "login": "zed", "blog": "", "email": ""}},
                 members={"zed": [{"login": "alice", "type": "User"}]},
                 users={"alice": {"login": "alice", "name": "Alice A"}})
    result = await GitHubOrgCollector().collect(target)

    assert result.persons == []
    assert [f.title for f in result.findings] == ["GitHub org: zed — 40 public repos"]
    assert result.findings[0].description.endswith(" Matched by name only — verify manually.")
    assert not result.findings[0].raw_data["domain_confirmed"]
    # members are not even requested: no profile of a possibly unrelated org's people
    assert not any("public_members" in p or p.startswith("/users/") for p in seen)


@pytest.mark.parametrize("blog, email, expected", [
    ("https://zed.dev", None, True),
    ("zed.dev/about", None, True),                    # no scheme
    ("https://www.zed.dev", None, True),              # subdomain
    ("", "team@zed.dev", True),
    ("https://evilzed.dev", None, False),             # substring, not the domain
    ("https://zed.dev.evil.org", None, False),
    ("https://other.io/?ref=zed.dev", None, False),
    ("", "x@evilzed.dev", False),
    (None, None, False),
])
def test_domain_confirmed_matches_hosts_not_substrings(blog, email, expected):
    org = {"blog": blog, "email": email}
    assert GitHubOrgCollector._domain_confirmed(org, "zed.dev") is expected


async def test_confirmed_description_wording(respx_mock, target):
    _site(respx_mock, orgs={"zed": {**ZED, "login": "zed"}}, members={"zed": []})
    f = (await GitHubOrgCollector().collect(target)).findings[0]
    assert f.description.endswith(" Domain confirmed via org profile.")


@pytest.mark.parametrize("status", [403, 429])
async def test_rate_limit_raises(respx_mock, target, status):
    respx_mock.route().respond(status)
    with pytest.raises(RuntimeError, match="GitHub rate limit exceeded"):
        await GitHubOrgCollector().collect(target)


async def test_other_http_error_raises(respx_mock, target):
    respx_mock.route().respond(500)
    with pytest.raises(RuntimeError, match="GitHub API error 500"):
        await GitHubOrgCollector().collect(target)


async def test_connection_error_raises(respx_mock, target):
    respx_mock.route().mock(side_effect=httpx.ConnectError("down"))
    with pytest.raises(RuntimeError, match="GitHub Org unreachable: ConnectError"):
        await GitHubOrgCollector().collect(target)
