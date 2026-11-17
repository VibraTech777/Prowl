import re

import httpx
import pytest

from core.collectors.github_person import GitHubPersonCollector, repo_name_severity
from core.models import Category, OsintPerson, OsintTarget, Severity

SEARCH = r"https://api\.github\.com/search/users.*"


@pytest.fixture(autouse=True)
def no_token(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)


@pytest.fixture
def target():
    return OsintTarget(company_name="Acme", domain="acme.fr")


@pytest.fixture
def person():
    return OsintPerson(full_name="Jane Doe", role="CEO", source="Annuaire Entreprises")


@pytest.fixture
def member():
    """Same person, but known to be the public member `jdoe` of the target's GitHub org."""
    return OsintPerson(full_name="Jane Doe", role="employee", source="GitHub Org",
                       github_login="jdoe", github_org="acme-inc")


def _site(respx_mock, *, search_items=(), profiles=None, repos=None, not_found=()):
    """Fake GitHub. Returns the list of (path, query) requests received."""
    profiles, repos, seen = profiles or {}, repos or {}, []

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        seen.append((path, dict(request.url.params)))
        if path == "/search/users":
            q = request.url.params["q"]
            items = search_items(q) if callable(search_items) else search_items
            return httpx.Response(200, json={"items": items})
        if m := re.fullmatch(r"/users/([^/]+)/repos", path):
            return httpx.Response(200, json=repos.get(m[1], []))
        if m := re.fullmatch(r"/users/([^/]+)", path):
            if m[1] in not_found:
                return httpx.Response(404, json={"message": "Not Found"})
            return httpx.Response(200, json=profiles.get(m[1], {"login": m[1]}))
        return httpx.Response(404)

    respx_mock.route().mock(side_effect=handler)
    return seen


PROFILE = {"login": "jdoe", "html_url": "https://github.com/jdoe",
           "public_repos": 2, "followers": 10, "company": "@Acme"}


async def test_found_by_name(respx_mock, member, target):
    seen = _site(
        respx_mock,
        search_items=[{"login": "jdoe"}],
        profiles={"jdoe": PROFILE},
        repos={"jdoe": [
            {"name": "website", "language": "Python"},
            {"name": "tools", "language": "Go"},
            {"name": "notes", "language": None},
        ]},
    )
    result = await GitHubPersonCollector().collect_person(member, target)
    by_title = {f.title: f for f in result.findings}

    profile = next(f for t, f in by_title.items() if t.startswith("GitHub profile: jdoe"))
    assert profile.title == (
        "GitHub profile: jdoe (https://github.com/jdoe) — "
        "2 public repos, 10 followers [company match]"
    )
    assert profile.severity is Severity.MEDIUM              # company matches → upgraded
    assert profile.mitre_attack == "T1596"
    assert profile.affected_asset == "Jane Doe"
    assert "confidence" not in profile.raw_data              # severity alone carries the signal

    stack = by_title["GitHub tech stack for jdoe: Python, Go"]
    assert stack.severity is Severity.INFO and stack.mitre_attack == "T1592"
    assert stack.category is Category.TECH_EXPOSURE

    assert not any(f.severity is Severity.HIGH for f in result.findings)
    assert result.persons == []
    assert [path for path, _ in seen] == ["/users/jdoe", "/users/jdoe/repos"]   # no search
    assert ("/users/jdoe/repos", {"per_page": "30", "sort": "updated"}) in seen


@pytest.mark.parametrize("company, marker", [
    ("Other Corp", "[org member]"),           # no company match: still a confirmed member
    (None, "[org member]"),
    ("", "[org member]"),
    ("@Acme", "[company match]"),             # leading @ stripped, name match
    ("@ACME-labs", "[company match]"),        # case-insensitive substring
    ("works at acme.fr", "[company match]"),  # domain match
    ("  @acme.fr ", "[company match]"),       # whitespace + @
    ("@acme-inc", "[company match]"),         # the confirmed GitHub org itself
])
async def test_confirmed_member_is_always_medium(respx_mock, member, target, company, marker):
    """Membership of the target's org is the evidence: the company field is only a detail."""
    _site(respx_mock, search_items=[{"login": "jdoe"}],
          profiles={"jdoe": {**PROFILE, "company": company}})
    profile = (await GitHubPersonCollector().collect_person(member, target)).findings[0]
    assert profile.severity is Severity.MEDIUM
    assert profile.title.endswith(marker)
    assert "No company match" not in profile.description and "namesake" not in profile.description
    assert "Confirmed public member of the target's GitHub org (acme-inc)." in profile.description


async def test_company_field_naming_the_org_matches_even_without_domain_or_company_name(
        respx_mock, member):
    """zed.dev vs "@zed-industries": neither the domain nor the company name appears in it."""
    target = OsintTarget(company_name="", domain="zed.dev")
    zed = OsintPerson(full_name="Jane Doe", github_login="jdoe", github_org="zed-industries")
    _site(respx_mock, profiles={"jdoe": {**PROFILE, "company": "@zed-industries"}})
    profile = (await GitHubPersonCollector().collect_person(zed, target)).findings[0]
    assert profile.severity is Severity.MEDIUM and profile.title.endswith("[company match]")
    assert GitHubPersonCollector._company_matches("@zed-industries", target) is False   # old rule
    assert GitHubPersonCollector._company_matches("@zed-industries", target, "zed-industries")


async def test_member_without_a_known_org_name_still_has_a_clean_description(respx_mock, target):
    m = OsintPerson(full_name="Jane Doe", github_login="jdoe")             # github_org unset
    _site(respx_mock, profiles={"jdoe": PROFILE})
    profile = (await GitHubPersonCollector().collect_person(m, target)).findings[0]
    assert "Confirmed public member of the target's GitHub org." in profile.description


async def test_blank_company_name_never_matches(respx_mock, person):
    target = OsintTarget(company_name="", domain="acme.fr")
    _site(respx_mock, search_items=[{"login": "jdoe"}],
          profiles={"jdoe": {**PROFILE, "company": "anything"}})
    result = await GitHubPersonCollector().collect_person(person, target)
    assert result.findings[0].severity is Severity.INFO     # "" must not match every company


async def test_suspicious_repo(respx_mock, member, target):
    _site(respx_mock, search_items=[{"login": "jdoe"}], profiles={"jdoe": PROFILE},
          repos={"jdoe": [
              {"name": "acme-BACKUP", "language": None, "html_url": "https://github.com/jdoe/acme-BACKUP"},
              {"name": "website", "language": None},
              {"name": "prod.env-files", "language": None},
          ]})
    result = await GitHubPersonCollector().collect_person(member, target)
    sus = [f for f in result.findings if f.severity is Severity.HIGH]

    assert {f.title for f in sus} == {
        "Suspicious repo name on GitHub: jdoe/acme-BACKUP",
        "Suspicious repo name on GitHub: jdoe/prod.env-files",
    }
    assert all(f.mitre_attack == "T1552" and f.category is Category.CODE_LEAK for f in sus)
    assert not any(f.title.startswith("GitHub tech stack") for f in result.findings)


async def test_not_found(respx_mock, person, target):
    seen = _site(respx_mock, search_items=[])
    result = await GitHubPersonCollector().collect_person(person, target)
    assert result.findings == [] and result.persons == []
    assert [p for p, _ in seen] == ["/search/users"]          # nothing else requested


@pytest.mark.parametrize("status", [403, 429])
async def test_rate_limit(respx_mock, person, target, status):
    respx_mock.get(url__regex=SEARCH).respond(status)
    with pytest.raises(RuntimeError, match="GitHub rate limit exceeded"):
        await GitHubPersonCollector().collect_person(person, target)


async def test_unprocessable_returns_empty_result(respx_mock, person, target):
    respx_mock.get(url__regex=SEARCH).respond(422, json={"message": "Validation Failed"})
    result = await GitHubPersonCollector().collect_person(person, target)
    assert result.findings == [] and result.persons == []


async def test_other_http_error(respx_mock, person, target):
    respx_mock.get(url__regex=SEARCH).respond(500)
    with pytest.raises(RuntimeError, match="GitHub API error 500"):
        await GitHubPersonCollector().collect_person(person, target)


async def test_connection_error(respx_mock, person, target):
    respx_mock.get(url__regex=SEARCH).mock(side_effect=httpx.ConnectError("down"))
    with pytest.raises(RuntimeError, match="GitHub unreachable: ConnectError"):
        await GitHubPersonCollector().collect_person(person, target)


async def test_no_token_still_available_and_sends_no_auth(respx_mock, person, target):
    assert GitHubPersonCollector().is_available() is True
    route = respx_mock.get(url__regex=SEARCH).respond(json={"items": []})
    await GitHubPersonCollector().collect_person(person, target)
    headers = route.calls[0].request.headers
    assert "authorization" not in headers
    assert headers["accept"] == "application/vnd.github+json"
    assert headers["x-github-api-version"] == "2022-11-28"


async def test_token_is_sent_when_set(monkeypatch, respx_mock, person, target):
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_abc")
    route = respx_mock.get(url__regex=SEARCH).respond(json={"items": []})
    await GitHubPersonCollector().collect_person(person, target)
    assert route.calls[0].request.headers["authorization"] == "token ghp_abc"


async def test_with_email_searches_again_and_skips_known_logins(monkeypatch, respx_mock, target):
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_x")          # email search is token-only
    person = OsintPerson(full_name="Jane Doe", email="jane@acme.fr")

    def search(q):
        if q.endswith("in:email"):
            return [{"login": "jdoe"}, {"login": "jane-d"}]     # jdoe already found by name
        return [{"login": "jdoe"}]

    seen = _site(respx_mock, search_items=search,
                 profiles={"jdoe": PROFILE, "jane-d": {**PROFILE, "login": "jane-d",
                                                       "html_url": "https://github.com/jane-d"}})
    result = await GitHubPersonCollector().collect_person(person, target)

    queries = [(q["q"], q["per_page"]) for p, q in seen if p == "/search/users"]
    assert queries == [("Jane Doe type:user", "5"), ("jane@acme.fr in:email", "3")]
    profiles = [f.title.split()[2] for f in result.findings if f.title.startswith("GitHub profile")]
    assert profiles == ["jdoe", "jane-d"]                          # jdoe reported once


async def test_email_search_422_keeps_name_results(monkeypatch, respx_mock, target):
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_x")
    person = OsintPerson(full_name="Jane Doe", email="jane@acme.fr")

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/search/users":
            if "in:email" in request.url.params["q"]:
                return httpx.Response(422)
            return httpx.Response(200, json={"items": [{"login": "jdoe"}]})
        if request.url.path.endswith("/repos"):
            return httpx.Response(200, json=[])
        return httpx.Response(200, json=PROFILE)

    respx_mock.route().mock(side_effect=handler)
    result = await GitHubPersonCollector().collect_person(person, target)
    assert len(result.findings) == 1


def test_request_delay_is_adaptive(monkeypatch):
    collector = GitHubPersonCollector()
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    assert collector.request_delay == 6.0            # stays under 10 searches/min unauthenticated
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_abc")
    assert collector.request_delay == 1.5
    monkeypatch.setenv("GITHUB_TOKEN", "   ")
    assert collector.request_delay == 6.0            # blank token = no token


def test_delay_follows_a_token_loaded_after_instantiation(monkeypatch):
    """Collectors are built at import, before cli.main calls load_dotenv()."""
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    collector = GitHubPersonCollector()
    assert collector.request_delay == 6.0
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_from_dotenv")       # what load_dotenv() does later
    assert collector.request_delay == 1.5


async def test_no_token_skips_email_search(respx_mock, target, caplog):
    """Without GITHUB_TOKEN: name search only, even when the person has an email."""
    person = OsintPerson(full_name="Jane Doe", email="jane@acme.fr")
    seen = _site(respx_mock, search_items=[{"login": "jdoe"}], profiles={"jdoe": PROFILE})

    with caplog.at_level("DEBUG", logger="core.collectors.github_person"):
        result = await GitHubPersonCollector().collect_person(person, target)

    queries = [q["q"] for path, q in seen if path == "/search/users"]
    assert queries == ["Jane Doe type:user"]                       # the email search never happens
    assert not any("in:email" in q or "jane@acme.fr" in q for q in queries)
    assert len(result.findings) >= 1                               # name results still reported
    assert "email search skipped for Jane Doe" in caplog.text      # explained in the debug log


async def test_token_enables_email_search(monkeypatch, respx_mock, target):
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_x")
    person = OsintPerson(full_name="Jane Doe", email="jane@acme.fr")
    seen = _site(respx_mock, search_items=[], profiles={})
    await GitHubPersonCollector().collect_person(person, target)
    queries = [q["q"] for path, q in seen if path == "/search/users"]
    assert queries == ["Jane Doe type:user", "jane@acme.fr in:email"]


async def test_no_token_and_no_email_is_unchanged(respx_mock, person, target):
    seen = _site(respx_mock, search_items=[])
    await GitHubPersonCollector().collect_person(person, target)
    assert [q["q"] for path, q in seen if path == "/search/users"] == ["Jane Doe type:user"]


# ── suspicious repo names: whole words / compound terms only ─────────────────


async def _high_findings(respx_mock, member, target, repo_name):
    _site(respx_mock, search_items=[{"login": "jdoe"}], profiles={"jdoe": PROFILE},
          repos={"jdoe": [{"name": repo_name, "language": None}]})
    result = await GitHubPersonCollector().collect_person(member, target)
    return [f for f in result.findings if f.severity is Severity.HIGH]


async def test_no_false_positive_hotkeys(respx_mock, member, target):
    assert await _high_findings(respx_mock, member, target, "stimulus-hotkeys") == []


async def test_suspicious_api_keys(respx_mock, member, target):
    high = await _high_findings(respx_mock, member, target, "my-api-keys-backup")
    assert [f.title for f in high] == ["Suspicious repo name on GitHub: jdoe/my-api-keys-backup"]


async def test_password_alone_is_medium_not_high(respx_mock, member, target):
    _site(respx_mock, search_items=[{"login": "jdoe"}], profiles={"jdoe": PROFILE},
          repos={"jdoe": [{"name": "Random-Password-Generator", "language": None},
                          {"name": "dumb-password-rules", "language": None},
                          {"name": "prod-credentials", "language": None}]})
    result = await GitHubPersonCollector().collect_person(member, target)
    sev = {f.affected_asset: f.severity for f in result.findings if f.category is Category.CODE_LEAK}
    assert sev == {"jdoe/Random-Password-Generator": Severity.MEDIUM,
                   "jdoe/dumb-password-rules": Severity.MEDIUM,
                   "jdoe/prod-credentials": Severity.HIGH}


@pytest.mark.parametrize("name", [
    "password-manager-internal", "passwords", "my_password_store", "credentials-prod",
    "secret-manager", "secrets", "api-keys", "my-api-key-rotation", "private-key",
    "project.env-prod", "backup-2024", "db-backup", "ghp-token-dump", "token-leak",
    "leaked-db", "mysql-dumper", "dump", "exploit-db", "MY-API-KEYS-BACKUP",
])
def test_suspicious_names_match(name):
    assert repo_name_severity(name) is not None, name


@pytest.mark.parametrize("name", [
    "stimulus-hotkeys", "monkey", "monkey-patch", "keyboard", "keys", "turkey-recipes",
    "secretariat", "secret", "tokenizer", "token", "backups", "dumpster", "leakage",
    "exploitation-guide", "passwordless-login", "credentialing", "website", "dotfiles",
])
def test_normal_names_do_not_match(name):
    assert repo_name_severity(name) is None, name


# ── name-only matches: homonyms are never more than INFO ─────────────────────

NOTE = "Name search only — may be homonym. Verify manually."
SUSPECT_REPOS = [{"name": "prod-credentials", "language": None},
                 {"name": "Password-Generator", "language": None}]


async def _scan(respx_mock, person, target, login="jdoe", company="@Acme"):
    _site(respx_mock, search_items=[{"login": login}],
          profiles={login: {**PROFILE, "login": login, "company": company}},
          repos={login: SUSPECT_REPOS})
    return (await GitHubPersonCollector().collect_person(person, target)).findings


async def test_name_only_match_is_info_even_with_company_match_and_suspicious_repos(
        respx_mock, person, target):
    findings = await _scan(respx_mock, person, target)

    assert findings, "findings are still reported"
    assert all(f.severity is Severity.INFO for f in findings)           # no MEDIUM, no HIGH
    profile, repos = findings[0], [f for f in findings if f.category is Category.CODE_LEAK]
    assert "[company match]" in profile.title                           # the signal stays visible
    assert len(repos) == 2
    for f in (profile, *repos):
        assert f.description.endswith(NOTE)


async def test_member_is_looked_up_directly_so_a_namesake_never_appears(respx_mock, member, target):
    """The search would have returned `jdoe2003`: it is never even asked for."""
    seen = _site(respx_mock, search_items=[{"login": "jdoe2003"}], profiles={"jdoe": PROFILE})
    findings = (await GitHubPersonCollector().collect_person(member, target)).findings
    assert "jdoe2003" not in " ".join(f.title for f in findings)
    assert [path for path, _ in seen] == ["/users/jdoe", "/users/jdoe/repos"]


async def test_confirmed_member_is_unchanged(respx_mock, member, target):
    findings = await _scan(respx_mock, member, target)
    profile = findings[0]
    assert profile.severity is Severity.MEDIUM and NOTE not in profile.description
    sev = {f.affected_asset: f.severity for f in findings if f.category is Category.CODE_LEAK}
    assert sev == {"jdoe/prod-credentials": Severity.HIGH,
                   "jdoe/Password-Generator": Severity.MEDIUM}
    assert all(NOTE not in f.description for f in findings)


async def test_login_confirmation_is_case_insensitive(respx_mock, target):
    m = OsintPerson(full_name="Jane Doe", source="GitHub Org", github_login="JDoe")
    _site(respx_mock, profiles={"JDoe": PROFILE}, repos={"jdoe": SUSPECT_REPOS})   # answers "jdoe"
    findings = (await GitHubPersonCollector().collect_person(m, target)).findings
    assert findings[0].severity is Severity.MEDIUM


def test_repo_name_severity_levels():
    from core.collectors.github_person import repo_name_severity as sev

    for name in ("credentials-prod", "my-secrets", "api-keys", "private_key", "private-keys",
                 "ssh-key", "ssh-keys", ".env", "prod.env-files", "db-backup", "backup-2024",
                 "token-leak", "leak", "dump", "exploit-db"):
        assert sev(name) is Severity.HIGH, name
    for name in ("password", "passwords", "Random-Password-Generator", "dumb-password-rules"):
        assert sev(name) is Severity.MEDIUM, name
    for name in ("token", "jwt-token", "backup", "website", ".envoy", "dotenv", "passwordless-login"):
        assert sev(name) is None, name
    assert sev("password-leak") is Severity.HIGH                # HIGH pattern wins



# ── direct lookup (known github_login) vs name search ────────────────────────


async def test_known_login_single_direct_call_no_search(respx_mock, member, target, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_x")                        # token + email: still no search
    member.email = "jane@acme.fr"
    seen = _site(respx_mock, profiles={"jdoe": PROFILE},
                 repos={"jdoe": [{"name": "website", "language": "Go"}]})
    result = await GitHubPersonCollector().collect_person(member, target)

    paths = [p for p, _ in seen]
    assert paths == ["/users/jdoe", "/users/jdoe/repos"]               # 1 profile call (+ its repos)
    assert "/search/users" not in paths
    assert result.findings[0].severity is Severity.MEDIUM              # confirmed: full severity


async def test_unknown_login_falls_back_to_name_search_info_only(respx_mock, person, target):
    assert person.github_login == ""
    seen = _site(respx_mock, search_items=[{"login": "jdoe"}], profiles={"jdoe": PROFILE},
                 repos={"jdoe": SUSPECT_REPOS})
    findings = (await GitHubPersonCollector().collect_person(person, target)).findings

    assert seen[0][0] == "/search/users" and seen[0][1]["q"] == "Jane Doe type:user"
    assert findings and all(f.severity is Severity.INFO for f in findings)
    assert findings[0].description.endswith(NOTE)


async def test_direct_lookup_404_returns_empty(respx_mock, member, target, caplog):
    seen = _site(respx_mock, not_found={"jdoe"})
    with caplog.at_level("WARNING", logger="core.collectors.github_person"):
        result = await GitHubPersonCollector().collect_person(member, target)    # no exception
    assert result.findings == [] and result.persons == []
    assert [p for p, _ in seen] == ["/users/jdoe"]                     # no repos, no search fallback
    assert "jdoe" in caplog.text                                       # logged, not silent


@pytest.mark.parametrize("status", [403, 429])
async def test_direct_lookup_rate_limit_raises(respx_mock, member, target, status):
    respx_mock.route().respond(status)
    with pytest.raises(RuntimeError, match="GitHub rate limit exceeded"):
        await GitHubPersonCollector().collect_person(member, target)


async def test_direct_lookup_connection_error_raises(respx_mock, member, target):
    respx_mock.route().mock(side_effect=httpx.ConnectError("down"))
    with pytest.raises(RuntimeError, match="GitHub unreachable: ConnectError"):
        await GitHubPersonCollector().collect_person(member, target)


async def test_profile_description_shows_the_github_url(respx_mock, member, target):
    _site(respx_mock, profiles={"jdoe": PROFILE})
    profile = (await GitHubPersonCollector().collect_person(member, target)).findings[0]
    assert "URL: https://github.com/jdoe." in profile.description
    assert profile.description.startswith("GitHub account matching 'Jane Doe'. URL:")
