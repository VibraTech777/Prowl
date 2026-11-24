"""
core/collectors/__init__.py

Import all concrete collectors here so the runner can discover them
with a single import.
"""

from core.collectors.annuaire_entreprises import AnnuaireEntreprisesCollector
from core.collectors.base import BasePersonCollector
from core.collectors.bodacc import BodaccCollector
from core.collectors.crtsh import CrtshCollector
from core.collectors.dns_lookup import DnsCollector
from core.collectors.dnsdumpster import DnsDumpsterCollector
from core.collectors.email_format import EmailFormatCollector
from core.collectors.github_colleagues import GitHubColleaguesCollector
from core.collectors.github_gitleak import GitLeakCollector
from core.collectors.github_org import GitHubOrgCollector
from core.collectors.github_person import GitHubPersonCollector
from core.collectors.google_dorks import GoogleDorksCollector
from core.collectors.hunter_io import HunterCollector
from core.collectors.opencorporates import OpenCorporatesCollector
from core.collectors.pappers import PappersCollector
from core.collectors.wayback import WaybackCollector
from core.collectors.web_crawl import WebCrawlCollector
from core.collectors.whatsmyname import WhatsMyNameCollector
from core.collectors.whois_lookup import WhoisCollector

# ALL_COLLECTORS — instantiated list used by the runner.
# Order here determines display order when severities are equal.
ALL_COLLECTORS = [
    DnsCollector(),
    WhoisCollector(),
    CrtshCollector(),
    DnsDumpsterCollector(),           # passive subdomain enumeration (HackerTarget)
    GoogleDorksCollector(),           # site:/filetype:/inurl: dorks via SerpAPI (needs SERPAPI_API_KEY)
    GitHubOrgCollector(),             # company GitHub org public members → person pivot
    OpenCorporatesCollector(),        # global company officers (needs OPENCORPORATES_API_TOKEN)
    BodaccCollector(),                # french_only — skipped unless --french
    PappersCollector(),               # french_only + API key
    WebCrawlCollector(),              # requires_crawl — skipped unless --crawl
    AnnuaireEntreprisesCollector(),   # french_only — skipped unless --french
    HunterCollector(),                # needs HUNTER_API_KEY; feeds the person pivot
    WaybackCollector(),               # LAST: a person also confirmed above (GitHub Org…) keeps that record
]

# PERSON_COLLECTORS — phase 2 (--pivot): investigate each person found in phase 1.
PERSON_COLLECTORS: list[BasePersonCollector] = [
    GitHubPersonCollector(),
    GitHubColleaguesCollector(),     # --pivot 2+: colleagues of a GitHub-confirmed person
    EmailFormatCollector(),          # guesses addresses from the company's email format
    GitLeakCollector(),              # real address from the person's public commits
    WhatsMyNameCollector(),          # same username on social / coding / tech platforms
]
