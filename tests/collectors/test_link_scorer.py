import pytest

from core.crawler.link_scorer import score_url


@pytest.mark.parametrize("url, expected", [
    ("https://example.com/.env", 100),
    ("https://example.com/.git/HEAD", 100),
    ("https://example.com/wp-admin/", 85),
    ("https://example.com/admin/users", 80),
    ("https://example.com/api/v1", 50),
    ("https://example.com/login", 50),
    ("https://example.com/staging", 40),
    ("https://example.com/about", 0),
    ("https://example.com/", 0),
    ("https://example.com/db/dump.sql", 90),
    ("https://example.com/files/site.bak", 90),
    ("https://example.com/server.pem", 100),
])
def test_score_url(url, expected):
    assert score_url(url) == expected


def test_score_is_case_insensitive_and_capped():
    assert score_url("https://EXAMPLE.com/ADMIN") == 80
    assert 0 <= score_url("https://example.com/.env/key.pem") <= 100

    # a keyword is a path segment (optionally with a file extension), never part of a longer word
    for path, expected in [
        ("/admin", 80), ("/admin/", 80), ("/admin/panel", 80), ("/admin?foo=bar", 80),
        ("/admin.php", 80), ("/x/y/admin/users", 80), ("/administrator/", 80), ("/wp-admin/", 85),
        ("/blog/cloud/administrating-the-administrator-an-oci-identity-domains-permission-bypass/", 0),
        ("/administration/users", 0), ("/administrators", 0),
        ("/developers", 0), ("/testimonials", 0), ("/devices", 0), ("/loginhelp", 0),
        ("/configuration/guide", 0), ("/installation/docs", 0), ("/debugging-tips", 0),
        ("/apple", 0), ("/apis/overview", 0), ("/.github/CODEOWNERS", 0),
        ("/.git", 100), ("/.git/HEAD", 100), ("/.env.local", 100), ("/api", 50), ("/api/v1", 50),
        ("/api-docs", 65), ("/swagger/index.html", 65), ("/.well-known/security.txt", 20),
    ]:
        assert score_url(f"https://example.com{path}") == expected, path
