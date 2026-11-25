"""
core/crawler/wayback.py — Reading what the Wayback Machine remembers about a domain.

Pure functions (no network): parse CDX answers, sort captured URLs into subdomains / old API paths /
old files / team pages, pull people's names out of an archived "team" page, and the technology
fingerprint out of an archived homepage. The collector (collectors/wayback.py) does the fetching.

Everything here reads UNTRUSTED text written by whoever ran the site years ago: it is only parsed
(HTML with BeautifulSoup, never executed) and every result is a hint, not a fact.
"""

from __future__ import annotations

import json
import re
import unicodedata
import warnings
from dataclasses import dataclass, field
from urllib.parse import urlparse

from bs4 import BeautifulSoup, MarkupResemblesLocatorWarning

# ── what we look for ─────────────────────────────────────────────────────────

DOC_EXTS = frozenset({"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "csv"})
SENSITIVE_EXTS = frozenset({
    "sql", "bak", "old", "swp", "env", "ini", "cfg", "conf", "config", "log", "key", "pem",
    "zip", "tar", "gz", "tgz", "7z", "rar", "dump",
})
# server-side CDX filter (Java regex): files OR API-looking paths, one request for both
FILES_API_FILTER = (
    r"original:.*(\.(" + "|".join(sorted(DOC_EXTS | SENSITIVE_EXTS)) + r")(\?.*)?$"
    r"|/api/|/v[0-9]+/|/graphql|/rest/|/wp-json|/swagger|/openapi|/oauth"
    r"|://[^/]*:[0-9]+(/|$)).*"            # an explicit port: a service on a non-standard port
)
TEAM_QUERY_PATHS = ("team", "our-team", "about", "about-us", "leadership", "people", "company", "equipe",
                    "a-propos", "management", "staff", "who-we-are")

# Ports that usually mean a management, data or developer service, not a second website.
NOTABLE_PORTS = {
    2375: "Docker API", 2376: "Docker API (TLS)", 3000: "Grafana / dev server", 5000: "dev server",
    5601: "Kibana", 8086: "InfluxDB", 8161: "ActiveMQ console", 8500: "Consul", 8888: "Jupyter",
    9000: "SonarQube / Portainer", 9090: "Prometheus", 9200: "Elasticsearch", 10000: "Webmin",
    15672: "RabbitMQ management",
}

_API_PATH_RE = re.compile(r"/(api|rest|graphql|wp-json|swagger|openapi|oauth)(/|$)|/v\d+(/|$)", re.I)
TEAM_PATH_RE = re.compile(
    r"^/(team|our-team|the-team|equipe|notre-equipe|about|about-us|a-propos|qui-sommes-nous|people|"
    r"leadership|management|staff|company|who-we-are)/?$", re.I)


@dataclass(frozen=True)
class Capture:
    timestamp: str          # YYYYMMDDhhmmss
    original: str
    mimetype: str = ""

    @property
    def year(self) -> str:
        return self.timestamp[:4]

    @property
    def host(self) -> str:
        return (urlparse(self.original).hostname or "").lower()

    @property
    def path(self) -> str:
        return urlparse(self.original).path or "/"

    @property
    def port(self) -> int | None:
        """The explicit port of the URL when it is NOT the scheme's default (80 / 443), else None."""
        parsed = urlparse(self.original)
        try:
            port = parsed.port
        except ValueError:
            return None
        default = 443 if parsed.scheme == "https" else 80
        return port if port is not None and port != default else None


def parse_cdx(text: str) -> list[Capture]:
    """Rows of a CDX `output=json` answer (first row = field names). Garbage in → []."""
    try:
        rows = json.loads(text) if text.strip() else []
    except ValueError:
        return []
    if not isinstance(rows, list) or len(rows) < 2 or not isinstance(rows[0], list):
        return []
    names = rows[0]
    captures: list[Capture] = []
    for row in rows[1:]:
        if not isinstance(row, list) or len(row) != len(names):
            continue
        item = dict(zip(names, row))
        ts, original = str(item.get("timestamp", "")), str(item.get("original", ""))
        if re.fullmatch(r"\d{4,14}", ts) and original.startswith(("http://", "https://")):
            captures.append(Capture(ts, original, str(item.get("mimetype", ""))))
    return captures


def archive_url(capture: Capture, raw: bool = False) -> str:
    """The page of the capture in the Wayback Machine (`raw`: the original bytes, no banner)."""
    return f"https://web.archive.org/web/{capture.timestamp}{'id_' if raw else ''}/{capture.original}"


def extension(path: str) -> str:
    last = path.rsplit("/", 1)[-1]
    return last.rsplit(".", 1)[-1].lower() if "." in last else ""


def in_scope(host: str, domain: str) -> bool:
    return host == domain or host.endswith("." + domain)


def pick_spread(items: list, n: int) -> list:
    """At most n items spread evenly over the list, always keeping the first and the last."""
    if len(items) <= n:
        return list(items)
    step = (len(items) - 1) / (n - 1)
    return [items[round(i * step)] for i in range(n)]


# ── sorting captured URLs ────────────────────────────────────────────────────


@dataclass
class Inventory:
    subdomains: dict[str, Capture] = field(default_factory=dict)   # host → its newest capture
    api_paths: dict[str, Capture] = field(default_factory=dict)    # "host/api/v1/" → newest capture
    sensitive_files: list[Capture] = field(default_factory=list)   # newest capture per URL
    documents: list[Capture] = field(default_factory=list)
    ports: dict[str, Capture] = field(default_factory=dict)        # "host:8443" → newest capture


def build_inventory(captures: list[Capture], domain: str) -> Inventory:
    inv = Inventory()
    newest: dict[str, Capture] = {}
    for c in captures:
        host = c.host
        if not in_scope(host, domain):
            continue
        if host not in (domain, "www." + domain):
            _keep_newest(inv.subdomains, host, c)
        if (port := c.port) is not None:
            _keep_newest(inv.ports, f"{host}:{port}", c)
        if _API_PATH_RE.search(c.path) and c.path.lstrip("/").split("/", 1)[0].lower() not in _STATIC_SEGMENTS:
            _keep_newest(inv.api_paths, host + _api_root(c.path), c)
        ext = extension(c.path)
        if ext in SENSITIVE_EXTS or ext in DOC_EXTS:
            if c.original not in newest or c.timestamp > newest[c.original].timestamp:
                newest[c.original] = c
    for c in newest.values():
        (inv.sensitive_files if extension(c.path) in SENSITIVE_EXTS else inv.documents).append(c)
    inv.sensitive_files.sort(key=lambda c: c.original)
    inv.documents.sort(key=lambda c: c.original)
    return inv


def _keep_newest(table: dict[str, Capture], key: str, capture: Capture) -> None:
    if key not in table or capture.timestamp > table[key].timestamp:
        table[key] = capture


def _api_root(path: str) -> str:
    """The endpoint family: "/api/v1/users/42" → "/api/v1/", "/api/users/42" → "/api/users/"."""
    parts = [p for p in path.split("/") if p]
    for i, part in enumerate(parts[:3]):
        if re.fullmatch(r"v\d+", part, re.I):
            return "/" + "/".join(parts[: i + 1]) + "/"
    return "/" + "/".join(parts[:2]) + "/" if parts else "/"


# ── people on an archived team page ──────────────────────────────────────────

# Words that mean "this heading is not a person" (matched on every token, lower-case).
_NOT_A_NAME = frozenset("""
team our about us contact careers career join leadership management board directors director advisors
advisory advisor investors investor partners partner press news blog jobs job meet the and we who are what
why how company mission values history services solutions products product customers customer resources
privacy policy terms legal copyright rights reserved read more learn see view apply now home menu search
login sign up get started free trial demo request download subscribe follow share linkedin facebook twitter
instagram youtube github email phone address ceo cto cfo coo cmo cio founder founders co-founder president
vice manager head chief officer engineer engineering developer designer sales marketing support security
research product operations finance people culture benefits open positions position role roles work working
life diversity inclusion global office offices location locations new york london paris san francisco
view all show hide next previous back top bottom left right click here page pages site map sitemap
cookie cookies settings accept decline close open email us call join talk help center docs documentation
pricing platform enterprise business technology technologies group inc ltd llc gmbh corp corporation
ventures venture capital partners fund funds labs holdings investors investor angel
""".split())
# investors, advisors, board members and people whose role is a PAST job elsewhere ("Former COO …")
# appear on team pages without being employees
_NON_EMPLOYEE_ROLE = re.compile(r"\b(investors?|angel|advis[eo]rs?|ventures?|capital|board member|mentor|partner at|former|ex-)\b", re.I)
_STATIC_SEGMENTS = frozenset("assets static dist build public css js img images fonts vendor _next wp-content "
                             "wp-includes hubfs cdn media".split())      # "/assets/v1/" is a cache-busting folder
_PARTICLES = frozenset("de del della di da van von der den le la du des bin al el dos das y".split())
_NAME_TOKEN = re.compile(r"^[A-ZÀ-ÖØ-Þ][A-Za-zÀ-ÖØ-öø-ÿ'’.-]*$")


def looks_like_name(text: str) -> bool:
    """2–4 capitalised words, no digits, no UI / job-title vocabulary."""
    text = re.sub(r"\s+", " ", text).strip(" ,;:-–—|")
    if not 5 <= len(text) <= 40 or re.search(r"[\d@/\\:]|https?", text):
        return False
    tokens = text.split(" ")
    if not 2 <= len(tokens) <= 4:
        return False
    names = 0
    for tok in tokens:
        low = tok.lower().strip(".,")
        if low in _NOT_A_NAME:
            return False
        if low in _PARTICLES and names:
            continue
        if not _NAME_TOKEN.match(tok):
            return False
        names += 1
    return names >= 2


@dataclass(frozen=True)
class PersonHit:
    name: str
    role: str = ""


_TEAM_CONTAINER = re.compile(
    r"team|member|staff|person|people|employee|leadership|founder|bio|profile|executive|equipe", re.I)


def _soup(html: str) -> BeautifulSoup:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", MarkupResemblesLocatorWarning)
        return BeautifulSoup(html, "lxml")


def extract_people(html: str) -> list[PersonHit]:
    """Names found on a team / about page: structured data first, then team-looking containers."""
    soup = _soup(html)
    found: dict[str, str] = {}

    def add(name: str, role: str = "") -> None:
        name = re.sub(r"\s+", " ", name).strip()
        if looks_like_name(name) and not _NON_EMPLOYEE_ROLE.search(role):
            found.setdefault(name, re.sub(r"\s+", " ", role).strip()[:60])

    for script in soup.find_all("script", type="application/ld+json"):
        try:
            data = json.loads(script.string or "")
        except ValueError:
            continue
        stack = [data]
        while stack:
            node = stack.pop()
            if isinstance(node, list):
                stack.extend(node)
            elif isinstance(node, dict):
                kind = node.get("@type")
                if (kind == "Person" or (isinstance(kind, list) and "Person" in kind)) and isinstance(node.get("name"), str):
                    add(node["name"], str(node.get("jobTitle") or ""))
                stack.extend(v for v in node.values() if isinstance(v, (list, dict)))

    for el in soup.find_all(attrs={"itemtype": re.compile(r"schema\.org/Person", re.I)}):
        name, role = el.find(attrs={"itemprop": "name"}), el.find(attrs={"itemprop": "jobTitle"})
        if name:
            add(name.get_text(" ", strip=True), role.get_text(" ", strip=True) if role else "")

    containers = soup.find_all(True, class_=_TEAM_CONTAINER) + soup.find_all(True, id=_TEAM_CONTAINER)
    for box in containers:
        for head in box.find_all(["h2", "h3", "h4", "h5", "strong", "b"]):
            text = head.get_text(" ", strip=True)
            if looks_like_name(text):
                nxt = head.find_next_sibling(["p", "span", "div", "h5", "h6", "em", "small"])
                # the job title sits under the name; a sibling of the SAME tag is the next person
                role = nxt.get_text(" ", strip=True) if nxt is not None and nxt.name != head.name else ""
                add(text, role)
    return [PersonHit(n, r) for n, r in found.items()]


def fold(name: str) -> str:
    """Comparison key for a name: accent-free, lower-case, single-spaced."""
    plain = "".join(c for c in unicodedata.normalize("NFKD", name) if not unicodedata.combining(c))
    return re.sub(r"\s+", " ", plain).strip().lower()


# ── technology fingerprint of an archived homepage ───────────────────────────

_HEADERS = ("server", "x-powered-by", "x-generator", "x-aspnet-version", "x-drupal-cache", "via")
_MARKERS = (
    ("wp-content", "WordPress"), ("/sites/default/files", "Drupal"), ("com_content", "Joomla"),
    ("cdn.shopify", "Shopify"), ("wixstatic", "Wix"), ("squarespace", "Squarespace"),
    ("hs-scripts", "HubSpot"), ("__next_data__", "Next.js"), ("data-reactroot", "React"),
    ("ng-version", "Angular"), ("ng-app", "AngularJS"), ("data-v-", "Vue.js"), ("googletagmanager", "Google Tag Manager"),
)


def extract_tech(headers: dict[str, str], html: str) -> list[str]:
    """Header values (the archive keeps the original ones as x-archive-orig-*), generator, markers."""
    lower = {k.lower(): v for k, v in headers.items()}
    hints = [f"{h}: {lower['x-archive-orig-' + h]}" for h in _HEADERS if lower.get("x-archive-orig-" + h)]
    body = html[:400_000]
    meta = _soup(body).find("meta", attrs={"name": re.compile("^generator$", re.I)})
    if meta and meta.get("content"):
        hints.append(f"generator: {str(meta['content'])[:60]}")
    low = body.lower()
    hints += [label for marker, label in _MARKERS if marker in low]
    for lib, pattern in (("jQuery", r"jquery[-.]v?(\d+\.\d+(?:\.\d+)?)"), ("Bootstrap", r"bootstrap[-./@]v?(\d+\.\d+(?:\.\d+)?)")):
        if m := re.search(pattern, low):
            hints.append(f"{lib} {m.group(1)}")
    return list(dict.fromkeys(hints))
