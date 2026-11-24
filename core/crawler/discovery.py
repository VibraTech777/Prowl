"""
core/crawler/discovery.py — The "discovery files" a site publishes about itself.

sitemap.xml, security.txt, OpenID Connect configuration, Android / Apple app-link files,
humans.txt, crossdomain.xml, clientaccesspolicy.xml. Like robots.txt, they hand a recon the
site's structure, contacts, auth endpoints and mobile apps for the price of one GET each.

Pure functions: text in, a small summary out, no network. Every parser returns None when the
text is not that kind of file: a single-page app answers 200 with its index.html for ANY path,
so a 200 alone proves nothing. XML is read with regular expressions, never an XML parser
(nothing to exploit with entity expansion, and a sitemap can be tens of megabytes).

The caller (collectors/web_crawl.py) fetches the files — robots.txt applies to each of them —
and turns the summaries into findings with `build_finding()`.
"""

from __future__ import annotations

import html
import json
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlparse

from core.crawler.link_scorer import score_url
from core.models import Category, Finding, OsintTarget, Severity

# kind → paths tried, in order (a later path is skipped once an earlier one gave a finding)
DISCOVERY_PATHS: dict[str, tuple[str, ...]] = {
    "sitemap": ("/sitemap.xml",),
    "security": ("/.well-known/security.txt", "/security.txt"),
    "openid": ("/.well-known/openid-configuration",),
    "assetlinks": ("/.well-known/assetlinks.json",),
    "aasa": ("/.well-known/apple-app-site-association",),
    "humans": ("/humans.txt",),
    "crossdomain": ("/crossdomain.xml",),
    "clientaccess": ("/clientaccesspolicy.xml",),
}

MAX_BYTES = 2 * 1024 * 1024         # a sitemap can be huge; the first 2 MB are plenty
SENSITIVE_URL_SCORE = 70            # a URL in a sitemap scoring this much (admin, backup…) → MEDIUM
_MAX_LOCS = 20_000                  # URLs kept from one sitemap
_RAW_URLS = 500                     # URLs kept in raw_data
_LISTED = 10                        # items spelled out in a description

_LOC_RE = re.compile(r"<loc>\s*(.*?)\s*</loc>", re.IGNORECASE | re.DOTALL)
_CDATA_RE = re.compile(r"^<!\[CDATA\[(.*?)\]\]>$", re.DOTALL)


# ── parsers ──────────────────────────────────────────────────────────────────


@dataclass
class SitemapInfo:
    is_index: bool
    locs: list[str] = field(default_factory=list)      # page URLs, or child sitemaps for an index
    truncated: bool = False


def parse_sitemap(text: str) -> SitemapInfo | None:
    head = text[:4096].lower()
    if "<urlset" not in head and "<sitemapindex" not in head:
        return None
    locs: list[str] = []
    truncated = False
    for m in _LOC_RE.finditer(text):
        value = html.unescape(m.group(1).strip())
        if cdata := _CDATA_RE.match(value):
            value = cdata.group(1).strip()
        if value:
            if len(locs) >= _MAX_LOCS:
                truncated = True
                break
            locs.append(value)
    return SitemapInfo(is_index="<sitemapindex" in head, locs=locs, truncated=truncated)


def parse_security_txt(text: str) -> dict[str, list[str]] | None:
    """RFC 9116 fields (lower-cased names → values). Needs at least one Contact."""
    fields: dict[str, list[str]] = {}
    for line in text.splitlines():
        if not line or line.startswith(("#", "-----")):          # comments, PGP clearsign armor
            continue
        name, sep, value = line.partition(":")
        name = name.strip().lower()
        if sep and re.fullmatch(r"[a-z-]{3,25}", name) and value.strip():
            fields.setdefault(name, []).append(value.strip())
    return fields if fields.get("contact") else None


def parse_openid_config(text: str) -> dict | None:
    try:
        data = json.loads(text)
    except ValueError:
        return None
    return data if isinstance(data, dict) and isinstance(data.get("issuer"), str) else None


def parse_assetlinks(text: str) -> list[dict] | None:
    """Digital Asset Links: [{relation, target: {namespace, package_name, sha256_cert_fingerprints}}]."""
    try:
        data = json.loads(text)
    except ValueError:
        return None
    if not isinstance(data, list):
        return None
    targets = [s["target"] for s in data
               if isinstance(s, dict) and isinstance(s.get("target"), dict)
               and s["target"].get("namespace")]
    return targets or None


def parse_aasa(text: str) -> list[str] | None:
    """Apple app-site-association: the app IDs (TEAMID.bundle.id) it lists."""
    try:
        data = json.loads(text)
    except ValueError:
        return None
    if not isinstance(data, dict) or not {"applinks", "webcredentials", "appclips"} & set(data):
        return None
    ids: list[str] = []

    def add(value):
        if isinstance(value, str) and value not in ids:
            ids.append(value)

    applinks = data.get("applinks") or {}
    for detail in applinks.get("details", []) if isinstance(applinks, dict) else []:
        if isinstance(detail, dict):
            add(detail.get("appID"))
            for app_id in detail.get("appIDs", []) or []:
                add(app_id)
    for key in ("webcredentials", "appclips"):
        section = data.get(key) or {}
        for app_id in (section.get("apps") if isinstance(section, dict) else None) or []:
            add(app_id)
    return ids


def parse_humans(text: str) -> str | None:
    body = text.strip()
    if not body or re.search(r"<\s*(!doctype|html|head|body)\b", body[:500], re.IGNORECASE):
        return None                                              # an HTML page, not a text file
    return body


def parse_crossdomain(text: str) -> list[str] | None:
    """Flash cross-domain policy: the domains allowed to read this site's data."""
    if "<cross-domain-policy" not in text[:4096].lower():
        return None
    return re.findall(r"<allow-access-from\b[^>]*\bdomain\s*=\s*[\"']([^\"']*)[\"']", text, re.I)


def parse_clientaccess(text: str) -> list[str] | None:
    """Silverlight client access policy: the origins allowed to call this site."""
    if "<access-policy" not in text[:4096].lower():
        return None
    return re.findall(r"<domain\b[^>]*\buri\s*=\s*[\"']([^\"']*)[\"']", text, re.I)


PARSERS = {
    "sitemap": parse_sitemap, "security": parse_security_txt, "openid": parse_openid_config,
    "assetlinks": parse_assetlinks, "aasa": parse_aasa, "humans": parse_humans,
    "crossdomain": parse_crossdomain, "clientaccess": parse_clientaccess,
}


# ── findings ─────────────────────────────────────────────────────────────────


def build_finding(kind: str, parsed, url: str, target: OsintTarget, source: str) -> Finding | None:
    """One finding for a parsed discovery file (None if there is nothing worth reporting)."""
    built = _BUILDERS[kind](parsed, urlparse(url).path or "/", target.domain)
    if built is None:
        return None
    severity, title, description, raw = built
    return Finding(
        id="", severity=severity, category=Category.WEB_FINDING, title=title,
        description=description, affected_asset=target.domain, source=source, source_url=url,
        mitre_attack="T1594",                      # Search Victim-Owned Websites
        raw_data=raw,
    )


def _join(items, limit: int = _LISTED) -> str:
    items = list(items)
    more = f" … and {len(items) - limit} more" if len(items) > limit else ""
    return ", ".join(items[:limit]) + more


def _sitemap(info: SitemapInfo, path: str, domain: str):
    n = len(info.locs)
    plus = "+" if info.truncated else ""
    if info.is_index:
        return (Severity.INFO, f"Sitemap index {path}: {n}{plus} child sitemaps",
                f"Sitemap index listing {n}{plus} sitemaps: {_join(info.locs)}.",
                {"sitemaps": info.locs[:_RAW_URLS]})
    sensitive = [u for u in info.locs if score_url(u) >= SENSITIVE_URL_SCORE]
    hosts = Counter((urlparse(u).hostname or "").lower() for u in info.locs)
    own = {domain.lower(), "www." + domain.lower()}            # www is the same site, not a find
    others = [h for h in hosts if h and h not in own]
    sections = Counter(
        "/" + seg if (seg := urlparse(u).path.strip("/").split("/")[0]) else "/"
        for u in info.locs)
    title = f"Sitemap {path}: {n}{plus} URLs"
    if sensitive:
        title += " — sensitive: " + ", ".join(urlparse(u).path or u for u in sensitive[:3])
    description = (
        f"Sitemap listing {n}{plus} URLs. Top sections: "
        + ", ".join(f"{s} ({c})" for s, c in sections.most_common(8)) + "."
    )
    if others:
        description += f" Other hosts referenced: {_join(others)}."
    if sensitive:
        description += f" Sensitive-looking URLs: {_join(sensitive)}."
    return (Severity.MEDIUM if sensitive else Severity.INFO, title, description,
            {"urls": info.locs[:_RAW_URLS], "total": n, "sensitive": sensitive,
             "hosts": list(hosts), "truncated": info.truncated})


def _security_txt(fields: dict[str, list[str]], path: str, domain: str):
    expired = False
    expires = (fields.get("expires") or [""])[0]
    try:
        stamp = datetime.fromisoformat(expires.replace("Z", "+00:00"))
        expired = (stamp if stamp.tzinfo else stamp.replace(tzinfo=timezone.utc)) < datetime.now(timezone.utc)
    except ValueError:
        pass
    contact = fields["contact"]
    title = f"security.txt published — contact: {contact[0]}"
    parts = [f"Contact: {_join(contact)}"]
    for key, label in (("policy", "Policy"), ("encryption", "Encryption"),
                       ("acknowledgments", "Acknowledgments"), ("hiring", "Hiring"),
                       ("canonical", "Canonical")):
        if fields.get(key):
            parts.append(f"{label}: {_join(fields[key], 3)}")
    if expired:
        title = f"security.txt expired ({expires}) — contact: {contact[0]}"
        parts.append(f"Expires: {expires} (in the past: the file is stale)")
    elif expires:
        parts.append(f"Expires: {expires}")
    return (Severity.LOW if expired else Severity.INFO, title, "security.txt — " + ". ".join(parts) + ".",
            {"fields": fields, "expired": expired})


def _openid(config: dict, path: str, domain: str):
    grants = config.get("grant_types_supported") or []
    open_registration = bool(config.get("registration_endpoint"))
    password_grant = "password" in grants
    parts = [f"issuer {config['issuer']}"]
    for key in ("authorization_endpoint", "token_endpoint", "userinfo_endpoint", "jwks_uri",
                "registration_endpoint"):
        if config.get(key):
            parts.append(f"{key} {config[key]}")
    if grants:
        parts.append("grant types " + _join(map(str, grants)))
    if config.get("scopes_supported"):
        parts.append(f"{len(config['scopes_supported'])} scopes")
    notes = []
    if open_registration:
        notes.append("dynamic client registration is advertised")
    if password_grant:
        notes.append("the password grant is enabled")
    description = "OpenID Connect discovery document: " + "; ".join(parts) + "."
    if notes:
        description += " Worth checking: " + " and ".join(notes) + "."
    return (Severity.MEDIUM if notes else Severity.INFO,
            f"OpenID Connect configuration exposed: {config['issuer']}", description,
            {"issuer": config["issuer"], "endpoints": {k: v for k, v in config.items()
                                                       if k.endswith(("_endpoint", "_uri"))}})


def _assetlinks(targets: list[dict], path: str, domain: str):
    packages = [t["package_name"] for t in targets if t.get("package_name")]
    sites = [t["site"] for t in targets if t.get("site")]
    prints = sum(len(t.get("sha256_cert_fingerprints") or []) for t in targets)
    label = _join(packages, 3) if packages else f"{len(targets)} asset link(s)"
    return (Severity.INFO, f"Android app links (assetlinks.json): {label}",
            "Digital Asset Links statements tie this site to its apps. "
            + (f"Android packages: {_join(packages)}. " if packages else "")
            + (f"Linked sites: {_join(sites)}. " if sites else "")
            + f"{prints} certificate fingerprint(s).",
            {"packages": packages, "sites": sites})


def _aasa(app_ids: list[str], path: str, domain: str):
    if not app_ids:
        return None
    return (Severity.INFO, f"Apple app-site-association: {_join(app_ids, 3)}",
            f"iOS apps linked to this site ({len(app_ids)}): {_join(app_ids)}.", {"app_ids": app_ids})


def _humans(body: str, path: str, domain: str):
    excerpt = re.sub(r"\s+", " ", body)[:400]
    return (Severity.INFO, "humans.txt published",
            f"humans.txt credits the people or team behind the site: {excerpt}"
            + (" …" if len(body) > 400 else ""), {"text": body[:2000]})


def _wildcard_policy(domains: list[str], path: str):
    wildcard = any(d.strip() == "*" for d in domains)
    if wildcard:
        return (Severity.MEDIUM, f"{path} allows access from any domain",
                f"{path} grants cross-domain access to '*' (any origin): data this site serves "
                "to a logged-in user can be read by a hostile page.", {"domains": domains})
    if not domains:
        return None
    return (Severity.INFO, f"{path} lists {len(domains)} allowed domain(s)",
            f"{path} allows cross-domain access from: {_join(domains)}.", {"domains": domains})


def _crossdomain(domains: list[str], path: str, domain: str):
    return _wildcard_policy(domains, path)


def _clientaccess(domains: list[str], path: str, domain: str):
    return _wildcard_policy(domains, path)


_BUILDERS = {
    "sitemap": _sitemap, "security": _security_txt, "openid": _openid, "assetlinks": _assetlinks,
    "aasa": _aasa, "humans": _humans, "crossdomain": _crossdomain, "clientaccess": _clientaccess,
}
