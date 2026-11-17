"""
core/crawler/link_scorer.py — Score a URL by how interesting it is for recon.

Higher score = more interesting. Paths that suggest admin panels, exposed
credentials, debug endpoints or sensitive files get the highest scores.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

# path-segment prefix → score. A fragment matches only as a whole path segment (optionally with
# a file extension: /admin, /admin/, /admin/panel, /admin.php) — never inside a longer word:
# "/administrating-the-administrator…" (a blog post) must not look like "/admin".
INTERESTING_PATHS: dict[str, int] = {
    "/.git":          100,
    "/.env":          100,
    "/.htpasswd":     100,
    "/backup":        90,
    "/dump":          90,
    "/phpmyadmin":    90,
    "/wp-admin":      85,
    "/wp-login":      80,
    "/admin":         80,
    "/administrator": 80,
    "/_debug":        80,
    "/debug":         75,
    "/console":       75,
    "/actuator":      75,
    "/swagger":       65,
    "/api-docs":      65,
    "/openapi":       65,
    "/graphql":       60,
    "/api":           50,
    "/login":         50,
    "/signin":        50,
    "/config":        70,
    "/setup":         65,
    "/install":       65,
    "/test":          40,
    "/dev":           40,
    "/staging":       40,
    "/.well-known":   20,
}

# The fragment, then the end of the segment: "/", a file extension ".", or the end of the path.
_PATH_PATTERNS = [
    (re.compile(re.escape(fragment) + r"(?=/|\.|$)"), pts)
    for fragment, pts in INTERESTING_PATHS.items()
]

# File extension bonus
INTERESTING_EXTENSIONS: dict[str, int] = {
    ".sql":  90,
    ".bak":  90,
    ".zip":  70,
    ".tar":  70,
    ".gz":   70,
    ".log":  60,
    ".conf": 60,
    ".cfg":  60,
    ".xml":  30,
    ".json": 30,
    ".yaml": 40,
    ".yml":  40,
    ".env":  100,
    ".key":  100,
    ".pem":  100,
}


def score_url(url: str) -> int:
    """Return an interest score 0-100 for the given URL."""
    parsed = urlparse(url.lower())
    path = parsed.path

    score = 0

    for pattern, pts in _PATH_PATTERNS:
        if pattern.search(path):
            score = max(score, pts)
            break

    # Check extension
    if "." in path.split("/")[-1]:
        ext = "." + path.rsplit(".", 1)[-1].split("?")[0]
        score = max(score, INTERESTING_EXTENSIONS.get(ext, 0))

    return min(score, 100)
