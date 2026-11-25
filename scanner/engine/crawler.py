"""Same-origin crawling helpers: turn a single seed URL into the set of reachable pages so the
scanner tests the whole application surface, not only the page it was handed.

Where links come from
    `<a href>` targets, GET `<form action>` targets and same-origin redirects, plus URLs written
    in JavaScript: inline `<script>` blocks, `on*` handlers, `data-url`/`data-href` attributes and
    the page's own same-origin script files (`fetch('api/orders.php?id=' + id)`,
    `location.href = 'index.php?p=3'`). Scope is still enforced centrally by SafetyController —
    this module only decides what is *worth* enqueueing. Nothing is guessed: a page that no other
    page or script points to is not discovered.

Navigation is deliberately read-only:

* links that look like logout / sign-out are never followed, so an authenticated session
  survives the crawl instead of being torn down halfway through;
* links whose query or last path segments name a state-changing action (`?action=delete`,
  `/user/delete/5`, `delete_user_ajax.php`) are never followed, so the crawler itself triggers
  no destructive side effect even when scanning an authenticated area;
* static assets (images, CSS, JS, fonts, archives) are not pages — they are skipped (scripts are
  only read for the URLs they contain, never scanned).

Two identities per URL
    `page_signature` is the exact page (path plus every query name *and value*), so
    `index.php?p=12` and `index.php?p=14` — two screens of an application that routes by
    parameter — are two pages. `page_shape` ignores the values (`index.php?p`); the runner uses it
    to recognise a *template*: when the variants of one shape keep producing the same page
    structure (`/product?id=1`, `?id=2`, …) the remaining variants are skipped, so a large catalog
    still costs only a few requests. `page_structure`/`same_template` implement that comparison.
"""
from __future__ import annotations
import json
import re
from collections import Counter, deque
from html.parser import HTMLParser
from urllib.parse import parse_qs, parse_qsl, urldefrag, urlencode, urljoin, urlparse
from .models import PageStructure, ShapeState

# Links we must never follow: they would destroy the very session we are scanning with, or
# mutate server state simply by being requested (a GET that deletes is still a delete).
LOGOUT_PATTERN = re.compile(r"(?i)(logout|log-out|log_off|logoff|signout|sign-out|sign_out|sair|encerrar-sessao|deslogar|desconectar)")
DESTRUCTIVE_QUERY = re.compile(
    r"(?i)(?:^|&)(?:action|op|do|cmd|task)=(?:delete|remove|drop|destroy|del|erase|logout|signout)"
    r"|(?:^|&)(?:delete|remove|destroy|drop|erase)=")
DESTRUCTIVE_PATH = re.compile(r"(?i)(?:^|[/_.\-])(?:delete|remove|destroy|drop|erase|excluir|apagar|remover|deletar)(?=[/_.\-]|$)")
# Non-document responses not worth fetching and parsing as HTML pages.
SKIP_EXTENSIONS = re.compile(
    r"(?i)\.(png|jpe?g|gif|svg|ico|bmp|webp|css|js|mjs|map|woff2?|ttf|otf|eot|"
    r"pdf|zip|gz|tar|rar|7z|mp4|webm|mp3|wav|avi|mov|doc|docx|xls|xlsx|ppt|pptx)(?:$|\?)")

# --- URLs written in JavaScript ---------------------------------------------------------------
# A quoted literal (single, double or template quotes) on one line.
JS_STRING = re.compile(r"""(["'`])([^"'`\r\n]{1,400}?)\1""")
# `${expression}` inside a template literal: replaced by a neutral value so the URL stays usable.
JS_TEMPLATE_EXPRESSION = re.compile(r"\$\{[^}]*\}")
# A literal is taken as an endpoint only when it clearly is one: a server-side script, or a path
# under an `api/` segment. Free text, CSS selectors and file names of assets are left alone.
JS_ENDPOINT = re.compile(r"(?i)^(?:https?://[^/\s]+)?(?:\.{0,2}/)?(?:[\w~%.\-]+/)*(?:[\w~%.\-]+\.(?:php|aspx?|jsp|jspx|do|action|cfm|cgi|pl)|api(?:/[\w~%.\-]*)*)(?:\?[^\s#]*)?$")
# Explicit navigation: `location = '…'`, `location.href = '…'`, `location.assign('…')`.
JS_NAVIGATION = re.compile(r"""location(?:\.href)?\s*=\s*(["'`])([^"'`\r\n]{1,400}?)\1|location\.(?:assign|replace)\(\s*(["'`])([^"'`\r\n]{1,400}?)\3""")
# Query names worth keeping from a JavaScript URL (drops the `1` left by `?${params}`).
QUERY_NAME = re.compile(r"^[A-Za-z_][\w\-\[\].]{0,79}$")
# Value used for a parameter whose value is computed at runtime (`'?id=' + id`, `?id=${id}`).
RUNTIME_VALUE = "1"
# Third-party libraries served from the application's own origin: large, and they never contain
# the application's endpoints, so they are not worth a request.
VENDOR_SCRIPT = re.compile(r"(?i)(jquery|bootstrap|popper|datatables?|chart(?:\.js)?|moment|lodash|vendor|polyfill|fontawesome|select2|sweetalert|toastr|axios|vue|react|angular)[^/]*\.js(?:$|\?)")

# --- Page structure ------------------------------------------------------------------------------
# Structural tokens kept per page. Bounded so a huge page cannot make the comparison expensive.
MAX_STRUCTURE_TOKENS = 5000
# Text that identifies *which screen* a page is (column headers, field labels, buttons, legends)
# rather than which record it shows (titles, prices, descriptions).
LABEL_TAGS = frozenset({"th", "label", "legend", "button"})
# Two variants with the same identity are one template when their layouts (weighted Jaccard over
# token trigrams) are at least this similar...
TEMPLATE_SIMILARITY = 0.8
# ...or, when neither page has any identity at all (no labels, fields or scripts), only when the
# layouts are practically identical — a shared menu alone must not make two screens "the same".
TEMPLATE_SIMILARITY_WITHOUT_IDENTITY = 0.97


class _LinkParser(HTMLParser):
    """Collects link targets, GET form actions, script sources and inline JavaScript."""

    def __init__(self) -> None:
        super().__init__()
        self.hrefs: list[str] = []
        self.forms: list[tuple[str, str]] = []
        self.script_sources: list[str] = []
        self.inline_scripts: list[str] = []
        self._in_inline_script = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        pairs = {key.lower(): (value or "") for key, value in attrs}
        if tag == "a" and pairs.get("href"):
            self.hrefs.append(pairs["href"])
        elif tag == "form":
            self.forms.append((pairs.get("action", ""), pairs.get("method", "get").lower()))
        elif tag == "script":
            if pairs.get("src"):
                self.script_sources.append(pairs["src"])
            else:
                self._in_inline_script = True
        for name, value in pairs.items():
            if name.startswith("on") and value:
                self.inline_scripts.append(value)
            elif name in ("data-url", "data-href", "data-link") and value:
                self.hrefs.append(value)

    def handle_endtag(self, tag: str) -> None:
        if tag == "script":
            self._in_inline_script = False

    def handle_data(self, data: str) -> None:
        if self._in_inline_script:
            self.inline_scripts.append(data)


def _parse(body: str) -> _LinkParser | None:
    parser = _LinkParser()
    try:
        parser.feed(body)
    except Exception:
        return None
    return parser


def _absolute(base_url: str, href: str) -> str | None:
    if href.strip().lower().startswith(("javascript:", "mailto:", "tel:", "data:", "#")):
        return None
    absolute, _ = urldefrag(urljoin(base_url, href.strip()))
    return absolute


def _unique(urls: list[str | None]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for url in urls:
        if url and url not in seen:
            seen.add(url)
            out.append(url)
    return out


def extract_links(base_url: str, body: str) -> list[str]:
    """Absolute, de-fragmented URLs worth crawling from one HTML document.

    Anchor targets and `data-url`/`data-href` attributes are always collected. Form actions are
    collected only for GET forms — a POST form is a state-changing submission, not a navigable
    page, and its fields are already probed in place by the active plugins on the page where the
    form lives. URLs written in inline scripts and `on*` handlers are added (see
    `urls_from_javascript`); external script files are listed by `extract_script_sources`.
    """
    parser = _parse(body)
    if parser is None:
        return []
    candidates = list(parser.hrefs)
    candidates += [action for action, method in parser.forms if method == "get" and action]
    out = [_absolute(base_url, href) for href in candidates]
    for script in parser.inline_scripts:
        out += urls_from_javascript(base_url, script)
    return _unique(out)


def extract_script_sources(base_url: str, body: str) -> list[str]:
    """Absolute URLs of the external scripts a page loads, minus well-known libraries."""
    parser = _parse(body)
    if parser is None:
        return []
    return _unique([
        _absolute(base_url, src) for src in parser.script_sources if not VENDOR_SCRIPT.search(src)
    ])


def urls_from_javascript(base_url: str, source: str) -> list[str]:
    """Endpoint and navigation URLs written in JavaScript source, resolved against `base_url`.

    `base_url` must be the URL of the page that runs the script, not of the script file: a
    relative `fetch('api/x.php')` is resolved by the browser against the document. Values computed
    at runtime (`'?id=' + id`, `?id=${id}`) become `1`, so the parameter is still discovered and
    can be tested.
    """
    literals = [match.group(2) for match in JS_STRING.finditer(source)]
    navigation = [match.group(2) or match.group(4) for match in JS_NAVIGATION.finditer(source)]
    out: list[str | None] = []
    for literal in literals + navigation:
        candidate = JS_TEMPLATE_EXPRESSION.sub(RUNTIME_VALUE, literal).strip()
        is_navigation = literal in navigation
        if not candidate or " " in candidate:
            continue
        if not is_navigation and not JS_ENDPOINT.match(candidate):
            continue
        absolute = _absolute(base_url, candidate)
        out.append(_fill_runtime_values(absolute) if absolute else None)
    return _unique(out)


def _fill_runtime_values(url: str) -> str:
    """Drop query names that are not names and give empty values the neutral runtime value."""
    parsed = urlparse(url)
    if not parsed.query:
        return url
    pairs = [(name, value or RUNTIME_VALUE)
             for name, value in parse_qsl(parsed.query, keep_blank_values=True)
             if QUERY_NAME.match(name)]
    return parsed._replace(query=urlencode(pairs)).geturl()


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
    if DESTRUCTIVE_PATH.search(parsed.path):
        return False
    return True


def page_signature(url: str) -> str:
    """The exact page: path plus every query name and value, in a stable order.

    `index.php?p=12` and `index.php?p=14` are different pages — in an application that routes by
    parameter they are different screens.
    """
    parsed = urlparse(url)
    pairs = sorted(parse_qsl(parsed.query, keep_blank_values=True))
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(pairs)}"


def page_shape(url: str) -> str:
    """The page *ignoring query values*: path plus the set of query names. All variants of one
    shape (`/product?id=1`, `?id=2`) are candidates for being one template."""
    parsed = urlparse(url)
    keys = ",".join(sorted(parse_qs(parsed.query, keep_blank_values=True)))
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{keys}"


class _StructureParser(HTMLParser):
    """Reduces an HTML document to its layout tokens and to the tokens that identify the screen."""

    def __init__(self) -> None:
        super().__init__()
        self.tokens: list[str] = []
        self.identity: set[str] = set()
        self._label: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        pairs = {key.lower(): (value or "") for key, value in attrs}
        if tag in ("input", "select", "textarea") and pairs.get("name"):
            self.identity.add(f"field:{pairs['name']}")
        elif tag == "form":
            self.identity.add(f"form:{urlparse(pairs.get('action', '')).path}")
        elif tag == "script" and pairs.get("src"):
            self.identity.add(f"script:{urlparse(pairs['src']).path}")
        self._label = tag if tag in LABEL_TAGS else None
        if len(self.tokens) < MAX_STRUCTURE_TOKENS:
            token = tag
            for name in ("id", "name", "type"):
                if pairs.get(name):
                    token += f"[{name}={pairs[name]}]"
            self.tokens.append(token)

    def handle_endtag(self, tag: str) -> None:
        self._label = None

    def handle_data(self, data: str) -> None:
        text = " ".join(data.split())
        if self._label and text:
            self.identity.add(f"{self._label}:{text[:60].lower()}")


def _json_keys(value: object, prefix: str = "") -> list[str]:
    if isinstance(value, dict):
        out: list[str] = []
        for key, item in value.items():
            out.append(f"{prefix}.{key}")
            out += _json_keys(item, f"{prefix}.{key}")
        return out
    if isinstance(value, list) and value:
        return _json_keys(value[0], prefix + "[]")
    return []


def _trigrams(tokens: list[str]) -> Counter:
    if len(tokens) < 3:
        return Counter(tokens)
    return Counter("|".join(tokens[i:i + 3]) for i in range(len(tokens) - 2))


def page_structure(body: str, content_type: str = "text/html") -> PageStructure:
    """What a page is, separated from the data it shows.

    HTML: the identity is the set of label, column-header, legend and button texts, form field
    names, form actions and script sources — what tells two screens apart; the layout is the
    sequence of tags with their id/name/type. The remaining text (titles, prices, descriptions)
    is dropped: it is what changes between two records shown by one template. JSON: the key
    paths are both identity and layout. Anything else is summarised by its content type.
    """
    kind = content_type.lower()
    if "json" in kind:
        try:
            tokens = _json_keys(json.loads(body))
        except ValueError:
            tokens = ["json:invalid"]
        return PageStructure(frozenset(tokens), _trigrams(tokens))
    if "html" in kind or not kind:
        parser = _StructureParser()
        try:
            parser.feed(body)
        except Exception:
            pass
        return PageStructure(frozenset(parser.identity), _trigrams(parser.tokens))
    media_type = kind.split(";")[0].strip()
    return PageStructure(frozenset({media_type}), Counter({media_type: 1}))


def layout_similarity(first: Counter, second: Counter) -> float:
    """Weighted Jaccard similarity of two layouts, from 0.0 to 1.0."""
    if not first and not second:
        return 1.0
    shared = sum((first & second).values())
    total = sum((first | second).values())
    return shared / total if total else 0.0


def same_template(first: PageStructure, second: PageStructure) -> bool:
    """True when two variants of a page shape are one template filled with different data."""
    if first.identity != second.identity:
        return False
    threshold = TEMPLATE_SIMILARITY if first.identity else TEMPLATE_SIMILARITY_WITHOUT_IDENTITY
    return layout_similarity(first.layout, second.layout) >= threshold


# Consecutive variants of one shape that repeat a known template before the shape is considered
# a template and its remaining variants are skipped without a request.
TEMPLATE_STREAK_LIMIT = 3


class CrawlFrontier:
    """The breadth-first frontier of a crawl.

    Pages of a shape not seen before are visited first; further variants of a known shape
    (`index.php?p=14` after `?p=12`) wait in a second queue. A variant whose structure repeats a
    template already analysed for its shape is not analysed again, and after
    TEMPLATE_STREAK_LIMIT such repeats in a row the shape's remaining variants are skipped. The
    frontier also remembers what could not be visited, so the scan can report it.

    Deques, not lists: both queues are consumed from the front (see
    evaluation/benchmark_structures.py); `enqueued` is a set because it is asked once per link.
    """

    def __init__(self, seed_url: str, max_depth: int, duplicate_budget: int) -> None:
        self.max_depth = max_depth
        self.duplicate_budget = duplicate_budget
        self.fresh: deque[tuple[str, int]] = deque([(seed_url, 0)])
        self.variants: deque[tuple[str, int]] = deque()
        self.enqueued: set[str] = {page_signature(seed_url)}
        self.queued_shapes: set[str] = {page_shape(seed_url)}
        self.shapes: dict[str, ShapeState] = {}
        self.beyond_depth: list[str] = []
        self.out_of_budget: list[str] = []
        self.template_variants_skipped = 0
        self.duplicates_fetched = 0

    def state(self, url: str) -> ShapeState:
        return self.shapes.setdefault(page_shape(url), ShapeState())

    def offer(self, url: str, depth: int) -> None:
        """Queue a discovered URL (already checked for scope and read-only navigation)."""
        signature = page_signature(url)
        if signature in self.enqueued:
            return
        self.enqueued.add(signature)
        if depth > self.max_depth:
            self.beyond_depth.append(url)
            return
        shape = page_shape(url)
        if shape in self.queued_shapes:
            self.variants.append((url, depth))
        else:
            self.queued_shapes.add(shape)
            self.fresh.append((url, depth))

    def pop(self) -> tuple[str, int] | None:
        """The next page worth fetching, or None when nothing is left."""
        while self.fresh or self.variants:
            url, depth = (self.fresh or self.variants).popleft()
            state = self.state(url)
            if state.saturated:
                self.template_variants_skipped += 1
                continue
            if state.structures and self.duplicates_fetched >= self.duplicate_budget:
                # Not known to repeat a template — only out of budget to find out: report it.
                self.out_of_budget.append(url)
                continue
            return url, depth
        return None

    def repeats_template(self, url: str, structure: PageStructure) -> bool:
        """Record a fetched page's structure; True when it repeats a template already analysed
        for its shape (the page is then not analysed again)."""
        state = self.state(url)
        if any(same_template(structure, known) for known in state.structures):
            state.streak += 1
            state.saturated = state.streak >= TEMPLATE_STREAK_LIMIT
            self.template_variants_skipped += 1
            self.duplicates_fetched += 1
            return True
        state.streak = 0
        state.structures.append(structure)
        return False

    def not_visited(self) -> list[str]:
        """In-scope pages that were discovered but not analysed: left in the queues when a limit
        was reached, skipped when the budget for repeated templates ran out, or beyond the
        maximum depth. Variants of a shape known to be a template are not listed."""
        queued = [url for url, _ in list(self.fresh) + list(self.variants)
                  if not self.state(url).saturated]
        return queued + self.out_of_budget + self.beyond_depth
