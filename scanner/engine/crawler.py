"""Same-origin crawling helpers: turn a single seed URL into the set of reachable pages so the
scanner tests the whole application surface, not only the page it was handed.

The engine follows `<a href>` links, GET `<form action>` targets and same-origin redirects that
stay on the pinned host and port (scope is still enforced centrally by SafetyController — this
module only decides what is *worth* enqueueing). Navigation is deliberately read-only:

* links that look like logout / sign-out are never followed, so an authenticated session
  survives the crawl instead of being torn down halfway through;
* links carrying a state-changing action (delete, remove, drop, ...) are never followed, so the
  crawler itself triggers no destructive side effect even when scanning an authenticated area;
* static assets (images, CSS, JS, fonts, archives) are skipped — they are not HTML surfaces.

Pages are collapsed by *signature* — path plus the set of query-parameter names, ignoring their
values — so `/product?id=1` and `/product?id=2` count as one page. One representative is enough
to discover the `id` input point, and this keeps a large catalog from exploding the crawl.
"""
from __future__ import annotations
import re
from html.parser import HTMLParser
from urllib.parse import parse_qs, urldefrag, urljoin, urlparse

# Links we must never follow: they would destroy the very session we are scanning with, or
# mutate server state simply by being requested (a GET that deletes is still a delete).
LOGOUT_PATTERN = re.compile(r"(?i)(logout|log-out|log_off|logoff|signout|sign-out|sign_out|sair|encerrar-sessao|deslogar|desconectar)")
DESTRUCTIVE_QUERY = re.compile(
    r"(?i)(?:^|&)(?:action|op|do|cmd|task)=(?:delete|remove|drop|destroy|del|erase|logout|signout)"
    r"|(?:^|&)(?:delete|remove|destroy|drop|erase)=")
# Non-document responses not worth fetching and parsing as HTML pages.
SKIP_EXTENSIONS = re.compile(
    r"(?i)\.(png|jpe?g|gif|svg|ico|bmp|webp|css|js|mjs|map|woff2?|ttf|otf|eot|"
    r"pdf|zip|gz|tar|rar|7z|mp4|webm|mp3|wav|avi|mov|doc|docx|xls|xlsx|ppt|pptx)(?:$|\?)")


class _LinkParser(HTMLParser):
    """Collects <a href> targets and the (action, method) of every <form>."""

    def __init__(self) -> None:
        super().__init__()
        self.hrefs: list[str] = []
        self.forms: list[tuple[str, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        pairs = {key.lower(): (value or "") for key, value in attrs}
        if tag == "a" and pairs.get("href"):
            self.hrefs.append(pairs["href"])
        elif tag == "form":
            self.forms.append((pairs.get("action", ""), pairs.get("method", "get").lower()))


def extract_links(base_url: str, body: str) -> list[str]:
    """Absolute, de-fragmented URLs worth crawling from one HTML document.

    Anchor targets are always collected. Form actions are collected only for GET forms — a POST
    form is a state-changing submission, not a navigable page, and its fields are already probed
    in place by the active plugins on the page where the form lives.
    """
    parser = _LinkParser()
    try:
        parser.feed(body)
    except Exception:
        return []
    out: list[str] = []
    seen: set[str] = set()
    candidates = list(parser.hrefs)
    candidates += [action for action, method in parser.forms if method == "get" and action]
    for href in candidates:
        if href.strip().lower().startswith(("javascript:", "mailto:", "tel:", "data:", "#")):
            continue
        absolute, _ = urldefrag(urljoin(base_url, href))
        if absolute not in seen:
            seen.add(absolute)
            out.append(absolute)
    return out


def same_scope(url: str, host: str, port: int) -> bool:
    """True when `url` targets the pinned host and port over HTTP(S) — the only surface the
    crawler is allowed to expand into. SafetyController re-checks this on every request; the
    duplicate here just avoids enqueueing URLs that would only be rejected later."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return False
    url_port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return parsed.hostname == host and url_port == port


def is_followable(url: str) -> bool:
    """Read-only navigation filter: skip logout, state-changing and non-HTML links."""
    parsed = urlparse(url)
    if SKIP_EXTENSIONS.search(parsed.path):
        return False
    if LOGOUT_PATTERN.search(url):
        return False
    if DESTRUCTIVE_QUERY.search(parsed.query):
        return False
    return True


def page_signature(url: str) -> str:
    """Collapse URLs that are the same page for scanning purposes: identical path and the same
    *set* of query-parameter names, regardless of their values."""
    parsed = urlparse(url)
    keys = ",".join(sorted(parse_qs(parsed.query, keep_blank_values=True)))
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{keys}"
