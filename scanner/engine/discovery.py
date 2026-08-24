"""Input-surface discovery: turns a URL and an HTML document into InputPoint objects."""
from __future__ import annotations
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urlparse
from .models import InputPoint

def from_query_string(url: str) -> list[InputPoint]:
    query = urlparse(url).query
    return [InputPoint("query", name, value) for name, value in parse_qsl(query, keep_blank_values=True)]

class _FormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.inputs: list[InputPoint] = []
        self._in_form = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        pairs = {key.lower(): (value or "") for key, value in attrs}
        if tag == "form":
            self._in_form = True
        elif self._in_form and tag in ("input", "textarea", "select") and pairs.get("name"):
            data_type = pairs.get("type", "text") if tag == "input" else tag
            self.inputs.append(InputPoint("form", pairs["name"], pairs.get("value", ""), data_type))

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._in_form = False

def from_html_forms(body: str) -> list[InputPoint]:
    parser = _FormParser()
    try:
        parser.feed(body)
    except Exception:
        return []
    return parser.inputs

def discover(url: str, body: str = "") -> list[InputPoint]:
    seen: dict[str, InputPoint] = {}
    for point in from_query_string(url) + from_html_forms(body):
        seen.setdefault(point.identifier, point)
    return list(seen.values())
