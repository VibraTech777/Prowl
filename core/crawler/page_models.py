"""
core/crawler/page_models.py — Dataclasses for crawl results.
"""

from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class FormInfo:
    action: str           # resolved absolute URL
    method: str           # GET or POST
    input_names: list[str] = field(default_factory=list)
    has_password_field: bool = False


@dataclass
class PageAnalysis:
    url: str
    status_code: int
    title: str
    links: list[str]           # absolute in-scope URLs
    emails: list[str]
    forms: list[FormInfo]
    server_header: str         # from Server: response header
    tech_hints: list[str]      # headers, meta tags, script paths
    interesting_score: int     # 0–100 from link_scorer
    depth: int                 # crawl level (0 = seed)
