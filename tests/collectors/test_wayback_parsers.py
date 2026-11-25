import json

import pytest

from core.crawler import wayback as w

CDX = json.dumps([["timestamp", "original", "mimetype"],
                  ["20190101000000", "http://www.example.com:80/team", "text/html"],
                  ["bad", "http://x/", ""], ["20200101000000", "ftp://example.com/x", ""], ["2020"]])


def cap(ts, url, mime="text/html"):
    return w.Capture(ts, url, mime)


def test_parse_cdx_keeps_only_well_formed_rows():
    (c,) = w.parse_cdx(CDX)
    assert (c.timestamp, c.year, c.host, c.path) == ("20190101000000", "2019", "www.example.com", "/team")
    for junk in ("", "   ", "not json", "{}", "[]", '[["timestamp","original"]]', "[1, 2]"):
        assert w.parse_cdx(junk) == []


def test_archive_url():
    c = cap("20190101000000", "https://example.com/a?b=1")
    assert w.archive_url(c) == "https://web.archive.org/web/20190101000000/https://example.com/a?b=1"
    assert w.archive_url(c, raw=True) == "https://web.archive.org/web/20190101000000id_/https://example.com/a?b=1"


def test_helpers():
    assert [w.extension(p) for p in ("/a/b.PDF", "/.env", "/dir/", "/a.b/c", "/x.tar.gz")] == ["pdf", "env", "", "", "gz"]
    assert w.in_scope("a.example.com", "example.com") and w.in_scope("example.com", "example.com")
    assert not w.in_scope("evilexample.com", "example.com") and not w.in_scope("example.com.evil.org", "example.com")
    assert w.pick_spread(list(range(10)), 4) == [0, 3, 6, 9]
    assert w.pick_spread([1, 2], 5) == [1, 2] and w.pick_spread([], 3) == []
    assert w.pick_spread(list(range(100)), 2) == [0, 99]
    assert w.fold("  José   DE la Tour ") == "jose de la tour"


def test_inventory():
    caps = [
        cap("20150101000000", "http://old.example.com/"), cap("20180101000000", "https://old.example.com/x"),
        cap("20190101000000", "https://www.example.com/"), cap("20190101000000", "https://example.com/"),
        cap("20200101000000", "https://evilexample.com/"), cap("20200101000000", "https://example.com.evil.org/"),
        cap("20170101000000", "https://api.example.com/api/v1/users/42"),
        cap("20180101000000", "https://api.example.com/api/v1/orders"),
        cap("20160101000000", "https://example.com/rest/items/7"), cap("20160101000000", "https://example.com/v2/x"),
        cap("20140101000000", "https://example.com/db/dump.sql"), cap("20190101000000", "https://example.com/db/dump.sql"),
        cap("20170101000000", "https://example.com/files/report.pdf"), cap("20170101000000", "https://example.com/about"),
    ]
    inv = w.build_inventory(caps, "example.com")
    assert {h: c.year for h, c in inv.subdomains.items()} == {"old.example.com": "2018", "api.example.com": "2018"}
    assert {k: c.year for k, c in inv.api_paths.items()} == {
        "api.example.com/api/v1/": "2018", "example.com/rest/items/": "2016", "example.com/v2/": "2016"}
    assert [(c.original, c.year) for c in inv.sensitive_files] == [("https://example.com/db/dump.sql", "2019")]   # newest
    assert [c.original for c in inv.documents] == ["https://example.com/files/report.pdf"]


def test_filters_have_the_expected_shape():
    assert "pdf" in w.FILES_API_FILTER and "sql" in w.FILES_API_FILTER and "/api/" in w.FILES_API_FILTER
    assert w.TEAM_PATH_RE.match("/team") and w.TEAM_PATH_RE.match("/About-Us/") and not w.TEAM_PATH_RE.match("/team/john")


@pytest.mark.parametrize("text, expected", [
    ("Jane Doe", True), ("Jean-Pierre Dupont", True), ("Marie de la Tour", True), ("JOHN DOE", True),
    ("J. R. Smith", True), ("Zoë O'Brien", True), ("Élodie Martin", True),
    ("Our Team", False), ("Learn More", False), ("Get Started", False), ("Chief Executive Officer", False),
    ("Acme Inc", False), ("Contact Us", False), ("Join the team", False), ("New York", False),
    ("Kima Ventures", False), ("Acme Capital", False), ("john doe", False), ("Jane", False), ("A B C D E", False), ("Jane Doe 3rd", False),
    ("jane@doe.com", False), ("https://x.test", False), ("", False), ("Vice President Sales", False),
])
def test_looks_like_name(text, expected):
    assert w.looks_like_name(text) is expected, text


def test_extract_people_from_structured_data_and_team_blocks():
    html = """
    <html><head><script type="application/ld+json">
      {"@type": "Organization", "employee": [{"@type": "Person", "name": "Ada Lovelace", "jobTitle": "CTO"}],
       "founder": {"@type": ["Person"], "name": "Grace Hopper"}}
    </script></head><body>
      <nav class="menu"><h3>Our Team</h3></nav>
      <div itemscope itemtype="https://schema.org/Person"><span itemprop="name">Alan Turing</span>
        <span itemprop="jobTitle">Researcher</span></div>
      <section class="team-grid">
        <div class="team-member"><h3>Linus Torvalds</h3><p>Kernel Lead</p></div>
        <div class="team-member"><h4>Margaret Hamilton</h4><span>Head of Software</span></div>
        <div class="team-member"><h3>Join The Team</h3></div>
        <div class="team-member"><strong>Open Positions</strong></div>
      </section>
      <footer><h3>Jane Outsider</h3></footer>
    </body></html>"""
    got = {p.name: p.role for p in w.extract_people(html)}
    assert got == {"Ada Lovelace": "CTO", "Grace Hopper": "", "Alan Turing": "Researcher",
                   "Linus Torvalds": "Kernel Lead", "Margaret Hamilton": "Head of Software"}   # not the footer


def test_extract_people_handles_empty_and_script_only_pages():
    assert w.extract_people("") == []
    assert w.extract_people("<html><body><div id='root'></div><script src='app.js'></script></body></html>") == []
    assert w.extract_people("<script type='application/ld+json'>{not json</script>") == []
    assert w.extract_people("https://example.com/team") == []                    # looks like a URL, not markup


def test_extract_tech():
    html = ('<html><head><meta name="Generator" content="WordPress 4.2"></head><body>'
            '<link href="/wp-content/themes/x/style.css"><script src="/js/jquery-1.11.3.min.js"></script>'
            '<script src="bootstrap-3.3.7.min.js"></script><div data-reactroot></div></body></html>')
    headers = {"X-Archive-Orig-Server": "Apache/2.2.22", "x-archive-orig-x-powered-by": "PHP/5.3.10",
               "Content-Type": "text/html"}
    hints = w.extract_tech(headers, html)
    assert hints[:3] == ["server: Apache/2.2.22", "x-powered-by: PHP/5.3.10", "generator: WordPress 4.2"]
    assert {"WordPress", "React", "jQuery 1.11.3", "Bootstrap 3.3.7"} <= set(hints)
    assert len(hints) == len(set(hints))
    assert w.extract_tech({}, "") == []


def test_investors_and_advisors_are_not_listed_as_staff():
    html = ("<section class='team'>"
            "<div class='team-member'><h3>Jane Doe</h3><p>CTO</p></div>"
            "<div class='team-member'><h3>Sam Angel</h3><p>The most active Angel investor in the world</p></div>"
            "<div class='team-member'><h3>Lee Wong</h3><p>Advisor</p></div>"
            "<div class='team-member'><h3>Ray Moss</h3><p>Former COO OpenDNS</p></div>"
            "<div class='team-member'><h3>Bo Stone</h3><p>Managing Director eLab Ventures</p></div>"
            "<div class='team-member'><h3>Ava Park</h3><p>VP Security Engineering at Google</p></div>"
            "<div class='team-member'><h3>Pat Roe</h3><p>Director of Sales</p></div></section>")
    # an investor is never staff; "VP … at Google" is kept: it may well be a former employee who moved on
    assert [p.name for p in w.extract_people(html)] == ["Jane Doe", "Ava Park", "Pat Roe"]


def test_static_asset_version_folders_are_not_api_families():
    caps = [w.Capture("20180101000000", "https://example.com/assets/v1/app.js", "text/javascript"),
            w.Capture("20190101000000", "https://example.com/hubfs/v2/x.css", "text/css"),
            w.Capture("20190101000000", "https://example.com/api/v1/users", "application/json")]
    assert list(w.build_inventory(caps, "example.com").api_paths) == ["example.com/api/v1/"]


@pytest.mark.parametrize("url, port", [
    ("https://example.com/", None), ("http://example.com:80/", None), ("https://example.com:443/x", None),
    ("http://example.com:8080/", 8080), ("https://admin.example.com:8443/login", 8443),
    ("http://example.com:443/", 443),            # the default of https, not of http
    ("http://example.com:99999/", None),         # not a valid port: ignored, never an exception
])
def test_capture_port_is_only_a_non_default_one(url, port):
    assert w.Capture("20190101000000", url).port == port


def test_inventory_lists_non_standard_ports_with_their_newest_capture():
    caps = [w.Capture("20170101000000", "http://example.com:8080/a"),
            w.Capture("20200101000000", "http://example.com:8080/b"),
            w.Capture("20180101000000", "https://admin.example.com:8443/"),
            w.Capture("20190101000000", "https://example.com/"),
            w.Capture("20190101000000", "http://evil.org:8080/"),              # out of scope
            w.Capture("20190101000000", "http://example.com:80/")]
    inv = w.build_inventory(caps, "example.com")
    assert {k: c.timestamp for k, c in inv.ports.items()} == {
        "example.com:8080": "20200101000000", "admin.example.com:8443": "20180101000000"}


def test_the_files_query_also_catches_urls_with_a_port():
    import re
    rx = re.compile(w.FILES_API_FILTER.removeprefix("original:"))
    assert rx.fullmatch("http://example.com:8080/") and rx.fullmatch("https://a.example.com:8443")
    assert not rx.fullmatch("https://example.com/about")
