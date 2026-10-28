#!/usr/bin/env python3
"""System (end-to-end) and failure-injection tests for SentinelScope.

Implements the ST-xx and FI-xx cases of docs/TEST_PLAN.md. The expected result asserted for each
case is the one written in the plan before execution; this driver only automates the steps and
the comparison, and records what it observed.

It drives the real application through HTTP — Apache + PHP + MariaDB + the Python engine — as a
browser would, against the laboratory target in lab_target.py. The database is read only to
confirm what the interface shows (and, in FI cases, to break and restore the environment).

    python tests/e2e/run_system_tests.py                      # both suites
    python tests/e2e/run_system_tests.py --suite system       # ST cases only
    python tests/e2e/run_system_tests.py --suite browser      # MT-01..03 in headless Chrome/Edge
    python tests/e2e/run_system_tests.py --only ST-13 ST-14   # selected cases

Results are written to docs/test-evidence/<run>/results.json and results.md, next to the raw
evidence (lab request logs, JSON exports) each case produced.
"""
from __future__ import annotations

import argparse
import html
import http.cookiejar
import json
import os
import pathlib
import re
import socket
import subprocess
import sys
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timezone

ROOT = pathlib.Path(__file__).resolve().parents[2]
LAB_SCRIPT = ROOT / "tests" / "e2e" / "lab_target.py"
ENV_FILE = ROOT / ".env"

SEVERITY_WEIGHT = {"critical": 30, "high": 15, "medium": 7, "low": 2}
SEVERITY_LABEL = {"critical": "CRÍTICO", "high": "ALTO", "medium": "MÉDIO", "low": "BAIXO"}

# ---------------------------------------------------------------------------------------------
# Infrastructure helpers
# ---------------------------------------------------------------------------------------------


class Response:
    def __init__(self, status: int, headers, body: bytes, elapsed_ms: float) -> None:
        self.status = status
        self.headers = headers
        self.raw = body
        self.text = body.decode("utf-8", "replace")
        self.elapsed_ms = elapsed_ms

    @property
    def location(self) -> str:
        return self.headers.get("Location", "") if self.headers else ""

    @property
    def plain(self) -> str:
        """The body with HTML entities decoded, for 'the page says X' checks."""
        return html.unescape(self.text)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # observe 302 instead of following it
        return None


class Web:
    """A browser-like client of the application: keeps the session cookie, never follows redirects."""

    def __init__(self, base_url: str) -> None:
        self.base = base_url
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar), NoRedirect())

    def request(self, query: str, data: dict | None = None, timeout: float = 900) -> Response:
        url = self.base + "index.php" + (("?" + query) if query else "")
        body = urllib.parse.urlencode(data).encode() if data is not None else None
        started = time.perf_counter()
        try:
            with self.opener.open(urllib.request.Request(url, data=body), timeout=timeout) as reply:
                payload = reply.read()
                status, headers = reply.status, reply.headers
        except urllib.error.HTTPError as error:
            payload, status, headers = error.read(), error.code, error.headers
        return Response(status, headers, payload, (time.perf_counter() - started) * 1000)

    def get(self, query: str = "", timeout: float = 900) -> Response:
        return self.request(query, None, timeout)

    def csrf(self) -> str:
        match = re.search(r'name="csrf" value="([0-9a-f]+)"', self.get("page=add").text)
        if not match:
            raise RuntimeError("no CSRF token on the add page")
        return match.group(1)

    def register(self, name: str, url: str, authorized: bool = True, csrf: str | None = None) -> Response:
        data = {"csrf": self.csrf() if csrf is None else csrf, "name": name, "url": url}
        if authorized:
            data["authorized"] = "1"
        return self.request("page=create", data)

    def run(self, application_id: int, active: bool = False, authorized_active: bool | None = None,
            cookie: str = "", csrf: str | None = None) -> Response:
        data = {"csrf": self.csrf() if csrf is None else csrf, "application_id": str(application_id),
                "session_cookie": cookie}
        if active:
            data["mode_active"] = "1"
        if active if authorized_active is None else authorized_active:
            data["authorized_active"] = "1"
        return self.request("page=run", data)


class Database:
    """Read access (and, for FI cases, administrative access) through the mysql client."""

    def __init__(self, mysql: str, name: str = "sentinelscope") -> None:
        self.mysql = mysql
        self.name = name

    def query(self, sql: str, database: bool = True) -> list[list[str]]:
        args = [self.mysql, "-u", "root", "-N", "-B", "--default-character-set=utf8mb4", "-e", sql]
        if database:
            args.append(self.name)
        out = subprocess.run(args, capture_output=True, timeout=120)
        if out.returncode != 0:
            raise RuntimeError(out.stderr.decode("utf-8", "replace").strip())
        text = out.stdout.decode("utf-8", "replace")
        return [line.split("\t") for line in text.splitlines() if line]

    def scalar(self, sql: str):
        rows = self.query(sql)
        return rows[0][0] if rows else None

    def application_id(self, name: str) -> int | None:
        value = self.scalar(f"SELECT id FROM applications WHERE HEX(name)='{name.encode().hex().upper()}' "
                            "ORDER BY id DESC LIMIT 1")
        return int(value) if value else None

    def analysis(self, analysis_id: int) -> dict:
        rows = self.query("SELECT status, IFNULL(error_message,''), IFNULL(security_score,''), "
                          f"IFNULL(checks_run,'') FROM analyses WHERE id={int(analysis_id)}")
        if not rows:
            return {}
        status, error, score, checks = rows[0]
        return {"status": status, "error": error, "score": score, "checks_run": checks}

    def count(self, table: str, where: str = "1=1") -> int:
        return int(self.scalar(f"SELECT COUNT(*) FROM {table} WHERE {where}"))


def port_open(port: int) -> bool:
    with socket.socket() as probe:
        probe.settimeout(0.3)
        return probe.connect_ex(("127.0.0.1", port)) == 0


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class Lab:
    """Starts and stops the laboratory target as a separate process, one log file per start."""

    def __init__(self, port: int, evidence: pathlib.Path) -> None:
        self.port = port
        self.evidence = evidence
        self.process: subprocess.Popen | None = None
        self.log_path: pathlib.Path | None = None
        self.url = f"http://127.0.0.1:{port}/"

    def start(self, variant: str, label: str, delay: float = 0.0, secret: str = "lab-secret") -> "Lab":
        self.stop()
        self.log_path = self.evidence / f"lab-{label}.jsonl"
        self.log_path.unlink(missing_ok=True)
        self.process = subprocess.Popen(
            [sys.executable, str(LAB_SCRIPT), "--port", str(self.port), "--variant", variant,
             "--log", str(self.log_path), "--delay", str(delay), "--secret", secret],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        deadline = time.time() + 10
        while not port_open(self.port):
            if time.time() > deadline:
                raise RuntimeError("laboratory target did not start")
            time.sleep(0.1)
        return self

    def stop(self) -> None:
        if self.process and self.process.poll() is None:
            self.process.terminate()
            self.process.wait(timeout=10)
        self.process = None

    def requests(self) -> list[dict]:
        if not self.log_path or not self.log_path.exists():
            return []
        return [json.loads(line) for line in self.log_path.read_text(encoding="utf-8").splitlines() if line]


@contextmanager
def env_override(**values: str):
    """Temporarily rewrite keys of .env (the application re-reads it on every request)."""
    original = ENV_FILE.read_text(encoding="utf-8")
    lines = original.splitlines()
    for key, value in values.items():
        lines = [line for line in lines if not line.startswith(key + "=")] + [f"{key}={value}"]
    ENV_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")
    try:
        yield
    finally:
        ENV_FILE.write_text(original, encoding="utf-8")


def file_tail_since(path: pathlib.Path, offset: int) -> str:
    if not path.exists():
        return ""
    with open(path, "rb") as handle:
        handle.seek(offset)
        return handle.read().decode("utf-8", "replace")


def file_size(path: pathlib.Path) -> int:
    return path.stat().st_size if path.exists() else 0


# ---------------------------------------------------------------------------------------------
# Page readers — what the interface shows
# ---------------------------------------------------------------------------------------------

def analysis_id_from(response: Response) -> int | None:
    match = re.search(r"page=result&id=(\d+)", response.location)
    return int(match.group(1)) if match else None


def metric(page: Response, label: str) -> str | None:
    match = re.search(rf"<span>{re.escape(label)}</span><b>([^<]*)</b>", page.text)
    return match.group(1) if match else None


def page_score(page: Response) -> str | None:
    match = re.search(r'<div class="score"><strong>([^<]*)</strong>', page.text)
    return match.group(1) if match else None


def comparison_sections(page: Response) -> dict[str, str]:
    """Maps each comparison column ('new', 'same', 'fixed') to the decoded text of its entries."""
    sections: dict[str, list[str]] = {"new": [], "same": [], "fixed": []}
    for kind, inner in re.findall(r'<div class="compare (new|same|fixed)">(.*?)</div>', page.text, re.S):
        sections[kind].append(html.unescape(re.sub(r"<[^>]+>", " ", inner)))
    return {kind: "\n".join(entries) for kind, entries in sections.items()} | {
        kind + "_count": len(entries) for kind, entries in sections.items()}


def error_message(page: Response) -> str:
    match = re.search(r'<div class="error">(.*?)</div>', page.text, re.S)
    return html.unescape(re.sub(r"<[^>]+>", " ", match.group(1))).strip() if match else ""


# ---------------------------------------------------------------------------------------------
# Case framework
# ---------------------------------------------------------------------------------------------


class Checks:
    def __init__(self) -> None:
        self.items: list[tuple[str, bool, str]] = []

    def that(self, label: str, condition: bool, observed: object = "") -> bool:
        self.items.append((label, bool(condition), str(observed)))
        return bool(condition)

    def equal(self, label: str, actual, expected) -> bool:
        return self.that(label, actual == expected, f"expected {expected!r}, got {actual!r}")

    @property
    def passed(self) -> bool:
        return all(ok for _, ok, _ in self.items)


CASES: list[tuple[str, str, str, object]] = []


def case(case_id: str, suite: str, title: str):
    def register(function):
        CASES.append((case_id, suite, title, function))
        return function
    return register


class Context:
    def __init__(self, args, evidence: pathlib.Path) -> None:
        self.args = args
        self.evidence = evidence
        self.web = Web(args.app_url)
        self.db = Database(args.mysql)
        self.lab = Lab(args.lab_port, evidence)
        self.tag = datetime.now().strftime("%H%M%S")
        self.state: dict = {}

    def save(self, name: str, content) -> str:
        path = self.evidence / name
        if isinstance(content, (dict, list)):
            path.write_text(json.dumps(content, ensure_ascii=False, indent=2), encoding="utf-8")
        else:
            path.write_text(str(content), encoding="utf-8")
        return path.name

    def export(self, analysis_id: int) -> dict:
        reply = self.web.get(f"page=export&id={analysis_id}")
        return json.loads(reply.text)

    def new_application(self, label: str, url: str | None = None) -> int:
        name = f"{label} {self.tag}"
        reply = self.web.register(name, url or self.lab.url)
        if reply.status != 302:
            raise RuntimeError(f"registration of {name!r} failed with HTTP {reply.status}")
        return self.db.application_id(name)

    def analyse(self, application_id: int, **kwargs) -> tuple[int, Response]:
        reply = self.web.run(application_id, **kwargs)
        analysis_id = analysis_id_from(reply)
        if analysis_id is None:
            raise RuntimeError(f"run did not redirect to a result (HTTP {reply.status}): {error_message(reply)}")
        return analysis_id, reply


# ---------------------------------------------------------------------------------------------
# 4.1 Registration and input validation
# ---------------------------------------------------------------------------------------------


@case("ST-01", "system", "Register a valid application")
def st01(ctx: Context, c: Checks):
    name = f"ST-01 Loja de laboratório {ctx.tag}"
    reply = ctx.web.register(name, ctx.lab.url)
    c.equal("HTTP status", reply.status, 302)
    c.equal("redirect target", reply.location, "index.php")
    dashboard = ctx.web.get()
    c.that("notice shown", "Aplicação registrada." in dashboard.plain)
    c.that("card shows the name", html.escape(name, quote=False) in dashboard.text or name in dashboard.plain)
    c.that("card shows the URL", ctx.lab.url in dashboard.plain)
    application_id = ctx.db.application_id(name)
    c.that("row persisted", application_id is not None, application_id)
    confirmed = ctx.db.scalar(f"SELECT authorization_confirmed_at FROM applications WHERE id={application_id or 0}")
    c.that("authorization_confirmed_at recorded", confirmed not in (None, "NULL"), confirmed)
    ctx.state["app"] = application_id


@case("ST-02", "system", "Registration without authorization is refused")
def st02(ctx: Context, c: Checks):
    before = ctx.db.count("applications")
    reply = ctx.web.register(f"ST-02 {ctx.tag}", ctx.lab.url, authorized=False)
    c.equal("HTTP status", reply.status, 400)
    c.that("message", "Confirme que você possui autorização para analisar este alvo." in reply.plain, error_message(reply))
    c.equal("rows created", ctx.db.count("applications") - before, 0)


@case("ST-03", "system", "Invalid URLs are refused")
def st03(ctx: Context, c: Checks):
    inputs = {
        "": ["Informe a URL da aplicação."],
        "ftp://example.com/": ["A URL deve usar o esquema HTTP ou HTTPS."],
        "javascript:alert(1)": ["A URL deve usar o esquema HTTP ou HTTPS.", "Informe uma URL válida."],
        "http://user:pw@example.com/": ["A URL não pode conter credenciais embutidas."],
        "nota-uma-url": ["Informe uma URL válida."],
    }
    before = ctx.db.count("applications")
    for url, messages in inputs.items():
        reply = ctx.web.register(f"ST-03 {ctx.tag}", url)
        c.equal(f"HTTP status for {url!r}", reply.status, 400)
        c.that(f"message for {url!r}", any(m in reply.plain for m in messages), error_message(reply))
    c.equal("rows created", ctx.db.count("applications") - before, 0)


@case("ST-04", "system", "Invalid names are refused")
def st04(ctx: Context, c: Checks):
    before = ctx.db.count("applications")
    for label, name in (("empty", ""), ("spaces", "    "), ("121 characters", "n" * 121)):
        reply = ctx.web.register(name, ctx.lab.url)
        c.equal(f"HTTP status for {label} name", reply.status, 400)
        c.that(f"an explanation for {label} name", error_message(reply) != "", error_message(reply))
    c.equal("rows created", ctx.db.count("applications") - before, 0)


@case("ST-05", "system", "POST without a valid CSRF token is refused")
def st05(ctx: Context, c: Checks):
    message = "Seu token de sessão expirou. Atualize a página e tente novamente."
    apps, analyses = ctx.db.count("applications"), ctx.db.count("analyses")
    for label, token in (("missing", ""), ("wrong", "0" * 64)):
        reply = ctx.web.register(f"ST-05 {ctx.tag}", ctx.lab.url, csrf=token)
        c.equal(f"create with {label} token: status", reply.status, 400)
        c.that(f"create with {label} token: message", message in reply.plain, error_message(reply))
        reply = ctx.web.run(ctx.state.get("app") or 1, csrf=token)
        c.equal(f"run with {label} token: status", reply.status, 400)
        c.that(f"run with {label} token: message", message in reply.plain, error_message(reply))
    c.equal("applications created", ctx.db.count("applications") - apps, 0)
    c.equal("analyses created", ctx.db.count("analyses") - analyses, 0)


# ---------------------------------------------------------------------------------------------
# 4.2 Analysis
# ---------------------------------------------------------------------------------------------


@case("ST-06", "system", "Passive analysis of the vulnerable laboratory")
def st06(ctx: Context, c: Checks):
    ctx.lab.start("vulnerable", "st06")
    analysis_id, reply = ctx.analyse(ctx.state["app"])
    c.equal("redirects to the result", reply.status, 302)
    page = ctx.web.get(f"page=result&id={analysis_id}")
    c.equal("status", ctx.db.analysis(analysis_id).get("status"), "completed")
    c.equal("checks run shown", metric(page, "Verificações executadas"), "34")
    requests = ctx.lab.requests()
    per_path = Counter(r["path"] for r in requests if r["method"] == "GET")
    for path in ("/", "/search?q=livros", "/profile?name=ana", "/about"):
        c.equal(f"baseline GETs to {path}", per_path.get(path, 0), 2)
    forbidden = [r["path"] for r in requests if r["path"].startswith(("/logout", "/item"))]
    c.equal("requests to logout/destructive links", forbidden, [])
    export = ctx.export(analysis_id)
    fingerprints = {f["fingerprint"] for f in export["findings"]}
    c.that("headers.csp_missing reported", "headers.csp_missing" in fingerprints, sorted(fingerprints))
    c.that("no xss finding in passive mode", not any(f.startswith("xss.") for f in fingerprints), sorted(fingerprints))
    ctx.state["passive"] = analysis_id
    ctx.save("ST-06-export.json", export)


@case("ST-07", "system", "Active analysis without the active authorization is refused")
def st07(ctx: Context, c: Checks):
    application = ctx.state["app"]
    before = ctx.db.count("analyses", f"application_id={application}")
    reply = ctx.web.run(application, active=True, authorized_active=False)
    c.equal("HTTP status", reply.status, 400)
    c.that("message", "Autorize o envio de payloads de teste ativos para usar a análise completa." in reply.plain,
           error_message(reply))
    c.equal("analyses created", ctx.db.count("analyses", f"application_id={application}") - before, 0)


@case("ST-08", "system", "Active analysis of the vulnerable laboratory")
def st08(ctx: Context, c: Checks):
    ctx.lab.start("vulnerable", "st08")
    analysis_id, _ = ctx.analyse(ctx.state["app"], active=True)
    page = ctx.web.get(f"page=result&id={analysis_id}")
    c.equal("status", ctx.db.analysis(analysis_id).get("status"), "completed")
    c.equal("checks run shown", metric(page, "Verificações executadas"), "64")
    export = ctx.export(analysis_id)
    xss = [(f["parameter"], urllib.parse.urlsplit(f["affected_url"]).path)
           for f in export["findings"] if f["fingerprint"] == "xss.reflected_html_text"]
    c.that("XSS on /search, parameter q", ("q", "/search") in xss, xss)
    c.that("XSS on /profile, parameter name", ("name", "/profile") in xss, xss)
    forbidden = [r["path"] for r in ctx.lab.requests() if r["path"].startswith(("/logout", "/item"))]
    c.equal("requests to logout/destructive links", forbidden, [])
    ctx.state["active"] = analysis_id
    ctx.state["active_export"] = export
    ctx.save("ST-08-export.json", export)


@case("ST-09", "system", "Every finding carries the minimum information (CA-02)")
def st09(ctx: Context, c: Checks):
    export = ctx.state["active_export"]
    page = ctx.web.get(f"page=result&id={ctx.state['active']}")
    c.that("there are findings to inspect", len(export["findings"]) > 0, len(export["findings"]))
    for f in export["findings"]:
        missing = [k for k in ("severity", "status", "category", "cwe", "owasp", "wstg", "developer_impact",
                               "remediation") if not (f.get(k) or "").strip()]
        confidence_ok = isinstance(f.get("confidence"), int) and 0 <= f["confidence"] <= 100
        evidence_ok = isinstance(f.get("evidence"), dict) and bool(f["evidence"].get("reason"))
        where = f"{f['fingerprint']} @ {f.get('parameter') or '-'}"
        c.that(f"{where}: complete", not missing and confidence_ok and evidence_ok,
               f"missing={missing} confidence={f.get('confidence')} evidence_reason={evidence_ok}")
        c.that(f"{where}: shown with title and severity",
               f["title"] in page.plain and SEVERITY_LABEL[f["severity"]] in page.plain)


@case("ST-10", "system", "Score equals the manual 30/15/7/2 calculation (CA-03)")
def st10(ctx: Context, c: Checks):
    for label in ("passive", "active"):
        analysis_id = ctx.state[label]
        export = ctx.export(analysis_id)
        manual = max(0, min(100, 100 - sum(SEVERITY_WEIGHT[f["severity"]] for f in export["findings"])))
        page = ctx.web.get(f"page=result&id={analysis_id}")
        c.equal(f"{label}: score on the page", page_score(page), str(manual))
        c.equal(f"{label}: score in the export", export["analysis"]["security_score"], manual)


@case("ST-11", "system", "User-supplied and target-supplied content is escaped (NFR-02)")
def st11(ctx: Context, c: Checks):
    raw = '<script>alert("st11")</script>'
    reply = ctx.web.register(raw, ctx.lab.url)
    c.equal("registered", reply.status, 302)
    dashboard = ctx.web.get()
    c.that("raw tag absent from dashboard", raw not in dashboard.text)
    c.that("escaped form present", "&lt;script&gt;alert(" in dashboard.text)
    result = ctx.web.get(f"page=result&id={ctx.state['active']}")
    c.that("no raw probe tag on the result page", "<sszz" not in result.text,
           re.findall(r"<sszz[^>]*>", result.text)[:3])


@case("ST-12", "system", "History lists every analysis, most recent first (FR-06)")
def st12(ctx: Context, c: Checks):
    dashboard = ctx.web.get().text
    application = ctx.state["app"]
    card = dashboard[dashboard.find(f'name="application_id" value="{application}"'):]
    card = card[:card.find("</section>")]
    rows = re.findall(r'page=result&id=(\d+)">#\d+</a></td><td>[^<]*</td><td>([^<]*)</td><td>([^<]*)</td>'
                      r'<td>([^<]*)</td>', card)
    ids = [int(r[0]) for r in rows]
    expected = {ctx.state["passive"], ctx.state["active"]}
    c.that("both analyses listed", expected <= set(ids), ids)
    c.equal("most recent first", ids, sorted(ids, reverse=True))
    for analysis_id, mode, status, score in rows:
        if int(analysis_id) in expected:
            c.that(f"#{analysis_id} shows mode, completed status and score",
                   mode.strip() != "" and status == "completed" and score.strip().isdigit(), (mode, status, score))


@case("ST-19", "system", "Authenticated scan reaches the private area; the credential is never kept (FR-11, NFR-07)")
def st19(ctx: Context, c: Checks):
    secret = f"st19-{ctx.tag}-segredo"
    ctx.lab.start("vulnerable", "st19", secret=secret)
    application = ctx.new_application("ST-19 Área autenticada")
    access_log = pathlib.Path(ctx.args.apache_log)
    php_log = pathlib.Path(ctx.args.php_log)
    access_before, php_before = file_size(access_log), file_size(php_log)
    analysis_id, _ = ctx.analyse(application, cookie=f"lab_session={secret}")
    c.equal("status", ctx.db.analysis(analysis_id).get("status"), "completed")
    notes = [r for r in ctx.lab.requests() if r["path"].startswith("/account/notes")]
    c.that("/account/notes reached", bool(notes), [r["path"] for r in ctx.lab.requests()])
    c.that("cookie sent to the target", any(r["cookie"] == f"lab_session={secret}" for r in notes),
           {r["cookie"] for r in notes})
    dump = subprocess.run([ctx.args.mysqldump, "-u", "root", "sentinelscope"], capture_output=True, timeout=120)
    c.that("database dump obtained", dump.returncode == 0)
    c.that("secret absent from the database", secret.encode() not in dump.stdout)
    c.that("secret absent from the Apache access log", secret not in file_tail_since(access_log, access_before))
    c.that("secret absent from the PHP error log", secret not in file_tail_since(php_log, php_before))


@case("ST-20", "system", "Arguments reach the engine intact (contract R1)")
def st20(ctx: Context, c: Checks):
    secret = "s3cr%3D!x"
    ctx.lab.start("vulnerable", "st20a", secret=secret)
    application = ctx.new_application("ST-20a Cookie com caracteres especiais")
    analysis_id, _ = ctx.analyse(application, cookie=f"lab_session={secret}")
    cookies = {r["cookie"] for r in ctx.lab.requests()}
    c.that("cookie received exactly as typed", f"lab_session={secret}" in cookies, cookies)
    c.that("/account/notes reached with it", any(r["path"].startswith("/account/notes") for r in ctx.lab.requests()))

    ctx.lab.start("vulnerable", "st20b")
    application = ctx.new_application("ST-20b URL percent-encoded", ctx.lab.url + "search?q=a%20b")
    analysis_id, _ = ctx.analyse(application)
    first = ctx.lab.requests()[:1]
    c.equal("first request received", first[0]["path"] if first else None, "/search?q=a%20b")
    c.equal("analysis status", ctx.db.analysis(analysis_id).get("status"), "completed")


# ---------------------------------------------------------------------------------------------
# 4.3 Comparison, history, export, report
# ---------------------------------------------------------------------------------------------


@case("ST-13", "system", "Comparison after a partial fix (CA-04)")
def st13(ctx: Context, c: Checks):
    application = ctx.new_application("ST-13 Comparação")
    ctx.lab.start("vulnerable", "st13-a")
    a, _ = ctx.analyse(application, active=True)
    ctx.lab.start("partial", "st13-b")
    b, _ = ctx.analyse(application, active=True)
    ctx.state.update(compare_app=application, compare_a=a)
    page = ctx.web.get(f"page=compare&old={a}&new={b}")
    ctx.save("ST-13-compare.html", page.text)
    sections = comparison_sections(page)
    title = next(f["title"] for f in ctx.export(a)["findings"] if f["fingerprint"] == "xss.reflected_html_text")
    fixed_xss = [line for line in sections["fixed"].splitlines() if title in line]
    same_xss = [line for line in sections["same"].splitlines() if title in line]
    c.that("XSS of /search is in 'Corrigidos'", any("/search" in line for line in fixed_xss), fixed_xss)
    c.that("XSS of /profile is in 'Ainda presentes'", any("/profile" in line for line in same_xss), same_xss)
    c.equal("'Novos problemas' is empty", sections["new_count"], 0)


@case("ST-14", "system", "Comparison after the complete fix (CA-04)")
def st14(ctx: Context, c: Checks):
    application, a = ctx.state["compare_app"], ctx.state["compare_a"]
    ctx.lab.start("fixed", "st14-c")
    c_id, _ = ctx.analyse(application, active=True)
    page = ctx.web.get(f"page=compare&old={a}&new={c_id}")
    ctx.save("ST-14-compare.html", page.text)
    sections = comparison_sections(page)
    titles = {f["fingerprint"]: f["title"] for f in ctx.export(a)["findings"]}
    xss_fixed = [line for line in sections["fixed"].splitlines() if titles["xss.reflected_html_text"] in line]
    c.equal("both XSS findings in 'Corrigidos'", len(xss_fixed), 2)
    for fingerprint in ("headers.csp_missing", "headers.frame_options_missing", "headers.nosniff_missing",
                        "headers.referrer_policy_missing"):
        c.that(f"{fingerprint} in 'Corrigidos'", titles[fingerprint] in sections["fixed"])
    c.equal("'Novos problemas' is empty", sections["new_count"], 0)
    score_a = int(ctx.db.analysis(a)["score"])
    score_c = int(ctx.db.analysis(c_id)["score"])
    c.that("score improved", score_c > score_a, f"{score_a} -> {score_c}")


@case("ST-15", "system", "Comparison across applications is refused")
def st15(ctx: Context, c: Checks):
    reply = ctx.web.get(f"page=compare&old={ctx.state['active']}&new={ctx.state['compare_a']}")
    c.equal("HTTP status", reply.status, 400)
    c.that("message", "Escolha duas análises da mesma aplicação." in reply.plain, error_message(reply))


@case("ST-16", "system", "JSON export is complete and equal to what is stored and shown (CA-06)")
def st16(ctx: Context, c: Checks):
    analysis_id = ctx.state["active"]
    reply = ctx.web.get(f"page=export&id={analysis_id}")
    c.equal("HTTP status", reply.status, 200)
    c.that("JSON content type", "application/json" in reply.headers.get("Content-Type", ""))
    c.that("downloaded as attachment", "attachment" in reply.headers.get("Content-Disposition", ""))
    document = json.loads(reply.text)
    analysis = document["analysis"]
    c.that("application identified", bool(analysis.get("application")), analysis.get("application"))
    c.that("analysis date present", bool(analysis.get("started_at")), analysis.get("started_at"))
    c.that("score present", isinstance(analysis.get("security_score"), int), analysis.get("security_score"))
    db_fingerprints = Counter(r[0] for r in ctx.db.query(f"SELECT fingerprint FROM findings WHERE analysis_id={analysis_id}"))
    page = ctx.web.get(f"page=result&id={analysis_id}")
    c.equal("count export = database", len(document["findings"]), sum(db_fingerprints.values()))
    c.equal("count export = page", str(len(document["findings"])), metric(page, "Achados"))
    c.equal("fingerprints export = database", Counter(f["fingerprint"] for f in document["findings"]), db_fingerprints)


@case("ST-17", "system", "Printable report (FR-08)")
def st17(ctx: Context, c: Checks):
    export = ctx.state["active_export"]
    report = ctx.web.get(f"page=report&id={ctx.state['active']}")
    c.equal("HTTP status", report.status, 200)
    c.that("application name", export["analysis"]["application"] in report.plain)
    c.equal("score", page_score(report), str(export["analysis"]["security_score"]))
    for label in ("Verificações executadas", "Achados", "Status HTTP", "Duração"):
        c.that(f"metric {label}", metric(report, label) is not None)
    c.that("every finding title and remediation", all(
        f["title"] in report.plain and f["remediation"] in report.plain for f in export["findings"]))
    c.that("print button", "Imprimir / Salvar como PDF" in report.plain)
    c.that("no export link", "Exportar JSON" not in report.plain)


@case("ST-18", "system", "Severity filter counts (FR-12)")
def st18(ctx: Context, c: Checks):
    export = ctx.state["active_export"]
    page = ctx.web.get(f"page=result&id={ctx.state['active']}").text
    chips = dict(re.findall(r'data-filter="(\w+)" class="sev-chip[^"]*">[^<]*<b>(\d+)</b>', page))
    expected = Counter(f["severity"] for f in export["findings"])
    c.equal("'Todos' chip", chips.get("all"), str(len(export["findings"])))
    for severity, count in expected.items():
        c.equal(f"'{severity}' chip", chips.get(severity), str(count))
    c.equal("no chip for absent severities", set(chips) - {"all"}, set(expected))


@case("ST-21", "system", "Unknown identifiers answer 404")
def st21(ctx: Context, c: Checks):
    for query in ("page=result&id=999999", "page=export&id=999999", "page=compare&old=999999&new=999999"):
        reply = ctx.web.get(query)
        c.equal(f"{query}: status", reply.status, 404)
        c.that(f"{query}: message", "Análise não encontrada." in reply.plain, error_message(reply))
    reply = ctx.web.run(999999)
    c.equal("run unknown application: status", reply.status, 404)
    c.that("run unknown application: message", "Aplicação não encontrada." in reply.plain, error_message(reply))


@case("ST-22", "system", "1,000 findings presented in under 3 seconds (CA-05, NFR-01)")
def st22(ctx: Context, c: Checks):
    application = ctx.new_application("ST-22 Volume 1000")
    ids = []
    for offset in (0, 7):  # two analyses whose findings partly overlap, so the comparison has work
        ctx.db.query(f"INSERT INTO analyses(application_id,mode,status,security_score,checks_run,duration_ms,"
                     f"http_status,completed_at) VALUES({application},'safe_active','completed',0,64,1000,200,UTC_TIMESTAMP())")
        analysis_id = int(ctx.db.scalar(f"SELECT MAX(id) FROM analyses WHERE application_id={application}"))
        ctx.db.query(
            "INSERT INTO findings(analysis_id,fingerprint,title,category,cwe,owasp,wstg,severity,confidence,status,"
            "description,evidence_summary,affected_url,method,parameter,parameter_location,evidence,developer_impact,"
            "remediation,manual_review_required,remediation_example_vulnerable,remediation_example_fixed,"
            "remediation_example_language,remediation_example_note) "
            f"SELECT {analysis_id}, CONCAT('perf.check_', MOD(seq + {offset}, 40)), CONCAT('Achado de volume ', seq),"
            " 'Volume', 'CWE-693', 'A02:2025 Security Misconfiguration', 'WSTG-CONF-12',"
            " ELT(MOD(seq,4)+1,'critical','high','medium','low'), 80, 'high_confidence', 'Descrição do achado.',"
            " 'Resumo do que foi observado.', CONCAT('http://127.0.0.1:8765/pagina/', seq + "
            f"{offset}), 'GET', 'q', 'query', '{{\"reason\":\"carga de volume\"}}', 'Impacto para o desenvolvedor.',"
            " 'Como corrigir.', 0, 'echo $_GET[\"q\"];', 'echo htmlspecialchars($_GET[\"q\"]);', 'PHP', 'Nota.'"
            " FROM seq_1_to_1000")
        ids.append(analysis_id)
    c.equal("findings seeded", ctx.db.count("findings", f"analysis_id={ids[0]}"), 1000)
    timings: dict[str, list[float]] = {}
    for label, query in (("result page", f"page=result&id={ids[0]}"), ("report", f"page=report&id={ids[0]}"),
                         ("export", f"page=export&id={ids[0]}"), ("comparison", f"page=compare&old={ids[0]}&new={ids[1]}")):
        timings[label] = []
        for _ in range(5):
            reply = ctx.web.get(query)
            timings[label].append(round(reply.elapsed_ms, 1))
            if label == "result page":
                rendered = reply.text.count('<article class="finding"')
        c.that(f"{label}: 5 runs under 3,000 ms", max(timings[label]) < 3000, timings[label])
    c.equal("result page renders 1,000 findings", rendered, 1000)
    ctx.save("ST-22-timings.json", timings)


@case("ST-23", "system", "Loading indicator is present (roadmap step 23)")
def st23(ctx: Context, c: Checks):
    dashboard = ctx.web.get().text
    c.that("run form marked data-busy", 'class="run-form" data-busy' in dashboard)
    c.that("status element with role=status", 'class="run-status" role="status"' in dashboard)
    script = urllib.request.urlopen(ctx.args.app_url + "assets/app.js", timeout=30).read().decode("utf-8")
    c.that("script handles submit, locks the button and shows the status",
           "form[data-busy]" in script and "button.disabled = true" in script and "status.hidden = false" in script)


@case("ST-24", "system", "Analysis timestamps share one clock (FR-06, CA-06)")
def st24(ctx: Context, c: Checks):
    ctx.lab.start("vulnerable", "st24")
    application = ctx.new_application("ST-24 Relógio")
    before = datetime.now(timezone.utc).replace(tzinfo=None)
    analysis_id, _ = ctx.analyse(application)
    after = datetime.now(timezone.utc).replace(tzinfo=None)
    dashboard = ctx.web.get().text
    match = re.search(rf'page=result&id={analysis_id}">#{analysis_id}</a></td><td>([^<]+)</td>', dashboard)
    shown = datetime.strptime(match.group(1), "%Y-%m-%d %H:%M:%S") if match else None
    c.that("history date (UTC) within the run", shown is not None and
           (before.timestamp() - 5) <= shown.timestamp() <= (after.timestamp() + 5), f"{before} <= {shown} <= {after}")
    analysis = ctx.export(analysis_id)["analysis"]
    started = datetime.strptime(analysis["started_at"], "%Y-%m-%d %H:%M:%S")
    completed = datetime.strptime(analysis["completed_at"], "%Y-%m-%d %H:%M:%S")
    c.that("export: started_at <= completed_at, under 60 s apart",
           0 <= (completed - started).total_seconds() < 60, f"{started} -> {completed}")


def history_ids(dashboard: str, application_id: int) -> list[int]:
    """Analysis ids listed in one application's history card, in the order shown."""
    card = dashboard[dashboard.find(f'name="application_id" value="{application_id}"'):]
    card = card[:card.find("</section>")]
    return [int(i) for i in re.findall(r'page=result&id=(\d+)">#\d+</a>', card)]


@case("ST-25", "system", "History consulted by period (FR-06, Termo item 6)")
def st25(ctx: Context, c: Checks):
    application = ctx.new_application("ST-25 Histórico por período")
    ids = {}
    for label, started in (("jan", "2026-01-10 09:00:00"), ("feb", "2026-02-15 12:30:00"),
                           ("mar", "2026-03-20 18:45:00")):
        ctx.db.query(f"INSERT INTO analyses(application_id,mode,status,security_score,checks_run,duration_ms,"
                     f"http_status,started_at,completed_at) VALUES({application},'passive','completed',80,34,"
                     f"1000,200,'{started}',DATE_ADD('{started}', INTERVAL 5 SECOND))")
        ids[label] = int(ctx.db.scalar(f"SELECT MAX(id) FROM analyses WHERE application_id={application}"))
    every = sorted(ids.values(), reverse=True)
    c.equal("(a) no period: all three", sorted(history_ids(ctx.web.get().text, application), reverse=True), every)
    february = ctx.web.get("from=2026-02-01&to=2026-02-28")
    c.equal("(b) February only", history_ids(february.text, application), [ids["feb"]])
    c.that("(b) the form shows the period applied",
           'name="from" value="2026-02-01"' in february.text and 'name="to" value="2026-02-28"' in february.text)
    c.equal("(c) inclusive ends", history_ids(ctx.web.get("from=2026-02-15&to=2026-03-20").text, application),
            [ids["mar"], ids["feb"]])
    c.equal("(d) open end", history_ids(ctx.web.get("from=2026-02-01").text, application), [ids["mar"], ids["feb"]])
    reversed_period = ctx.web.get("from=2026-03-01&to=2026-02-01")
    c.equal("(e) reversed period: status", reversed_period.status, 400)
    c.that("(e) reversed period: message",
           "A data inicial deve ser anterior ou igual à data final." in reversed_period.plain, error_message(reversed_period))
    malformed = ctx.web.get("from=31/02/2026")
    c.equal("(f) malformed date: status", malformed.status, 400)
    c.that("(f) malformed date: message", "Informe as datas no formato AAAA-MM-DD." in malformed.plain,
           error_message(malformed))


@case("ST-26", "system", "JSON export carries a summary (FR-12, Termo item 8)")
def st26(ctx: Context, c: Checks):
    document = ctx.export(ctx.state["active"])
    summary, findings = document.get("summary", {}), document["findings"]
    c.equal("summary.findings", summary.get("findings"), len(findings))
    expected = {s: sum(f["severity"] == s for f in findings) for s in ("critical", "high", "medium", "low")}
    c.equal("summary.by_severity", summary.get("by_severity"), expected)
    c.equal("summary.security_score", summary.get("security_score"), document["analysis"]["security_score"])
    c.equal("summary.manual_review_required", summary.get("manual_review_required"),
            sum(bool(f["manual_review_required"]) for f in findings))


# ---------------------------------------------------------------------------------------------
# 4.4 Failure injection
# ---------------------------------------------------------------------------------------------

GENERIC_500 = "Ocorreu um erro inesperado. Consulte o log do servidor."
# Strings that only appear in a response when internal detail leaks. ".php" alone is not one of
# them: every page links to index.php.
LEAK_MARKERS = ("SQLSTATE", "Stack trace", "PDOException", "Database.php", "htdocs")


def wait_for(predicate, seconds: float) -> bool:
    deadline = time.time() + seconds
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.5)
    return predicate()


@case("FI-01", "failure", ".env absent")
def fi01(ctx: Context, c: Checks):
    backup = ENV_FILE.with_suffix(".fi01")
    ENV_FILE.rename(backup)
    try:
        reply = ctx.web.get()
    finally:
        backup.rename(ENV_FILE)
    c.equal("HTTP status", reply.status, 503)
    c.that("guidance message",
           "Configuração necessária: copie .env.example para .env e importe database.sql." in reply.plain, reply.plain[:200])


@case("FI-02", "failure", "MariaDB stopped")
def fi02(ctx: Context, c: Checks):
    php_log = pathlib.Path(ctx.args.php_log)
    before = file_size(php_log)
    subprocess.run([ctx.args.mysqladmin, "-u", "root", "shutdown"], capture_output=True, timeout=60)
    try:
        c.that("database stopped", wait_for(lambda: not port_open(3306), 30))
        reply = ctx.web.get()
    finally:
        flags = getattr(subprocess, "DETACHED_PROCESS", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        subprocess.Popen([ctx.args.mysqld, f"--defaults-file={ctx.args.mysql_ini}", "--standalone"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=flags)
        c.that("database restarted", wait_for(lambda: port_open(3306), 60))
    c.equal("HTTP status", reply.status, 500)
    c.that("generic message", GENERIC_500 in reply.plain, error_message(reply))
    c.that("no technical detail in the response", not any(m in reply.text for m in LEAK_MARKERS),
           [m for m in LEAK_MARKERS if m in reply.text])
    logged = file_tail_since(php_log, before)
    c.that("detail logged", "SentinelScope:" in logged, logged[-300:])
    password = next((line.split("=", 1)[1] for line in ENV_FILE.read_text().splitlines()
                     if line.startswith("DB_PASSWORD=")), "")
    c.that("password not logged", password and password not in logged)
    ctx.save("FI-02-response.html", reply.text)


@case("FI-03", "failure", "Wrong database password")
def fi03(ctx: Context, c: Checks):
    php_log = pathlib.Path(ctx.args.php_log)
    before = file_size(php_log)
    wrong = f"senha-errada-fi03-{ctx.tag}"
    with env_override(DB_PASSWORD=wrong):
        reply = ctx.web.get()
    c.equal("HTTP status", reply.status, 500)
    c.that("generic message", GENERIC_500 in reply.plain, error_message(reply))
    c.that("no technical detail in the response", not any(m in reply.text for m in LEAK_MARKERS))
    c.that("wrong password not in the response", wrong not in reply.text)
    c.that("wrong password not logged", wrong not in file_tail_since(php_log, before))


@case("FI-04", "failure", "Target unreachable")
def fi04(ctx: Context, c: Checks):
    application = ctx.new_application("FI-04 Alvo fora do ar", f"http://127.0.0.1:{free_port()}/")
    analysis_id, _ = ctx.analyse(application)
    row = ctx.db.analysis(analysis_id)
    page = ctx.web.get(f"page=result&id={analysis_id}")
    c.equal("status", row.get("status"), "failed")
    c.that("reason recorded and shown", row.get("error") and row["error"] in page.plain, row.get("error"))
    c.equal("findings", ctx.db.count("findings", f"analysis_id={analysis_id}"), 0)


@case("FI-05", "failure", "Loopback target with private targets denied")
def fi05(ctx: Context, c: Checks):
    ctx.lab.start("vulnerable", "fi05")
    application = ctx.new_application("FI-05 Alvo privado")
    with env_override(ALLOW_PRIVATE_TARGETS="false"):
        analysis_id, _ = ctx.analyse(application)
    row = ctx.db.analysis(analysis_id)
    c.equal("status", row.get("status"), "failed")
    c.that("scope reason recorded", bool(row.get("error")), row.get("error"))
    c.equal("requests received by the target", len(ctx.lab.requests()), 0)


@case("FI-06", "failure", "Python binary misconfigured")
def fi06(ctx: Context, c: Checks):
    ctx.lab.start("vulnerable", "fi06")
    application = ctx.new_application("FI-06 Python ausente")
    with env_override(PYTHON_BINARY="python-inexistente-fi06"):
        analysis_id, _ = ctx.analyse(application)
    row = ctx.db.analysis(analysis_id)
    c.equal("status", row.get("status"), "failed")
    c.equal("reason", row.get("error"), "O scanner retornou uma resposta inválida. Verifique a configuração do Python.")


@case("FI-07", "failure", "Engine answers a document that breaks the contract")
def fi07(ctx: Context, c: Checks):
    payload = {"ok": True, "checks_run": 34, "duration_ms": 5, "status_code": 200, "findings": [{
        "fingerprint": "x.y", "title": "Achado fora do contrato", "severity": "info",
        "affected_url": "http://127.0.0.1:8765/", "developer_impact": "i", "remediation": "r"}]}
    stub = ctx.evidence / "fi07_engine_stub.cmd"
    stub.write_text("@echo off\r\necho " + json.dumps(payload) + "\r\n", encoding="ascii")
    application = ctx.new_application("FI-07 Documento inválido")
    with env_override(PYTHON_BINARY=str(stub)):
        analysis_id, _ = ctx.analyse(application)
    row = ctx.db.analysis(analysis_id)
    c.equal("status", row.get("status"), "failed")
    c.equal("reason", row.get("error"), "Severidade desconhecida: info.")
    c.equal("findings", ctx.db.count("findings", f"analysis_id={analysis_id}"), 0)


APP_USERS = ("'sentinelscope_app'@'localhost'", "'sentinelscope_app'@'127.0.0.1'")


@case("FI-08", "failure", "Database refuses the write of findings")
def fi08(ctx: Context, c: Checks):
    ctx.lab.start("vulnerable", "fi08")
    application = ctx.new_application("FI-08 Escrita recusada")
    revoke = " ".join(
        f"REVOKE ALL PRIVILEGES ON sentinelscope.* FROM {u}; "
        f"GRANT SELECT,INSERT,UPDATE,DELETE ON sentinelscope.applications TO {u}; "
        f"GRANT SELECT,INSERT,UPDATE,DELETE ON sentinelscope.analyses TO {u}; "
        f"GRANT SELECT,UPDATE,DELETE ON sentinelscope.findings TO {u};" for u in APP_USERS)
    restore = " ".join(
        f"REVOKE ALL PRIVILEGES ON sentinelscope.applications FROM {u}; "
        f"REVOKE ALL PRIVILEGES ON sentinelscope.analyses FROM {u}; "
        f"REVOKE ALL PRIVILEGES ON sentinelscope.findings FROM {u}; "
        f"GRANT SELECT,INSERT,UPDATE,DELETE ON sentinelscope.* TO {u};" for u in APP_USERS)
    ctx.db.query(revoke + " FLUSH PRIVILEGES;", database=False)
    try:
        reply = ctx.web.run(application)
    finally:
        ctx.db.query(restore + " FLUSH PRIVILEGES;", database=False)
    analysis_id = int(ctx.db.scalar(f"SELECT MAX(id) FROM analyses WHERE application_id={application}") or 0)
    row = ctx.db.analysis(analysis_id)
    c.that("the user gets an answer (error page or result)", reply.status in (302, 500), reply.status)
    c.that("no technical detail in the response", not any(m in reply.text for m in LEAK_MARKERS))
    c.equal("status", row.get("status"), "failed")
    c.that("reason recorded", bool(row.get("error")), row.get("error"))
    c.equal("findings", ctx.db.count("findings", f"analysis_id={analysis_id}"), 0)


@case("FI-09", "failure", "Scan outlives PHP's max_execution_time")
def fi09(ctx: Context, c: Checks):
    ctx.lab.start("vulnerable", "fi09", delay=2.0)
    application = ctx.new_application("FI-09 Alvo lento")
    started = time.time()
    reply = ctx.web.run(application, active=True)
    elapsed = round(time.time() - started, 1)
    analysis_id = int(ctx.db.scalar(f"SELECT MAX(id) FROM analyses WHERE application_id={application}") or 0)
    row = ctx.db.analysis(analysis_id)
    c.that(f"the user gets an answer (after {elapsed} s)", reply.status in (302, 500), reply.status)
    c.that("no technical detail in the response", not any(m in reply.text for m in LEAK_MARKERS),
           re.sub(r"<[^>]+>", " ", reply.text)[:300])
    c.that("analysis not left running", row.get("status") in ("completed", "failed"), row)
    c.that("a failure carries a reason", row.get("status") != "failed" or bool(row.get("error")), row.get("error"))
    ctx.save("FI-09-response.html", reply.text)
    ctx.lab.stop()


@case("FI-10", "failure", "Value longer than its column, strict SQL mode")
def fi10(ctx: Context, c: Checks):
    ctx.lab.start("edge", "fi10")
    application = ctx.new_application("FI-10 Campo longo")
    original = ctx.db.scalar("SELECT @@GLOBAL.sql_mode")
    ctx.db.query("SET GLOBAL sql_mode='STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,"
                 "NO_ENGINE_SUBSTITUTION'", database=False)
    try:
        reply = ctx.web.run(application, active=True)
    finally:
        ctx.db.query(f"SET GLOBAL sql_mode='{original}'", database=False)
    analysis_id = int(ctx.db.scalar(f"SELECT MAX(id) FROM analyses WHERE application_id={application}") or 0)
    row = ctx.db.analysis(analysis_id)
    c.equal("status", row.get("status"), "completed")
    lengths = [int(r[0]) for r in ctx.db.query(
        f"SELECT CHAR_LENGTH(parameter) FROM findings WHERE analysis_id={analysis_id} AND parameter_location='form'")]
    c.that("form finding stored", bool(lengths), lengths)
    c.that("parameter within 180 characters", all(n <= 180 for n in lengths), lengths)


# ---------------------------------------------------------------------------------------------
# 6 Browser cases — a real headless Chrome/Edge driven through the DevTools protocol
# ---------------------------------------------------------------------------------------------


def browser(ctx: Context):
    if "browser" not in ctx.state:
        from cdp import Browser, find_browser
        executable = find_browser()
        if not executable:
            raise RuntimeError("no Chrome or Edge found for the browser cases")
        ctx.state["browser"] = Browser(executable)
    return ctx.state["browser"]


@case("MT-01", "browser", "Double click on 'Executar análise' starts one analysis, with progress shown")
def mt01(ctx: Context, c: Checks):
    ctx.lab.start("vulnerable", "mt01", delay=0.5)  # ~10 requests: the scan lasts several seconds
    application = ctx.new_application("MT-01 Clique duplo")
    page = browser(ctx)
    page.open(ctx.args.app_url + "index.php")
    page.evaluate(f"document.querySelector('input[name=application_id][value=\"{application}\"]')"
                  ".form.querySelector('button').id = 'mt01-run'")
    # Once the form is submitted, DevTools only answers after the next page has loaded, so the
    # state of the button is recorded from inside the page, on every change, in sessionStorage —
    # which survives the navigation — and read back afterwards.
    page.evaluate("(() => { const b = document.getElementById('mt01-run'), s = b.form.querySelector('.run-status');"
                  " const record = () => sessionStorage.setItem('mt01', JSON.stringify({disabled: b.disabled,"
                  " text: b.textContent, statusShown: !s.hidden, busy: b.form.getAttribute('aria-busy')}));"
                  " const watch = {attributes: true, childList: true, characterData: true, subtree: true};"
                  " new MutationObserver(record).observe(b, watch); new MutationObserver(record).observe(s, watch);"
                  " sessionStorage.removeItem('mt01'); })()")
    page.click("#mt01-run", count=2)
    page.wait_for("location.href.includes('page=result') && document.readyState === 'complete'", 180)
    recorded = page.evaluate("sessionStorage.getItem('mt01')")
    state = json.loads(recorded) if recorded else None
    c.that("button disabled", bool(state) and state["disabled"], state)
    c.that("button says 'Analisando…'", bool(state) and state["text"] == "Analisando…", state)
    c.that("progress message visible", bool(state) and state["statusShown"], state)
    c.that("result page reached", page.wait_for("location.href.includes('page=result')", 180))
    analysis_id = int(re.search(r"id=(\d+)", page.evaluate("location.href")).group(1))
    c.equal("analyses created by the double click", ctx.db.count("analyses", f"application_id={application}"), 1)
    ctx.state["mt_analysis"] = analysis_id
    ctx.state["mt_application"] = f"MT-01 Clique duplo {ctx.tag}"


@case("MT-02", "browser", "Severity chips filter the findings")
def mt02(ctx: Context, c: Checks):
    page = browser(ctx)
    page.open(ctx.args.app_url + f"index.php?page=result&id={ctx.state['mt_analysis']}")
    counts = page.evaluate("(() => { const n = {}; document.querySelectorAll('.finding[data-severity]')"
                           ".forEach(e => n[e.dataset.severity] = (n[e.dataset.severity] || 0) + 1); return n; })()")
    total = sum(counts.values())
    c.that("at least two severities to filter", len(counts) >= 2, counts)
    visible = ("[...document.querySelectorAll('.finding[data-severity]')].filter(e => !e.hidden)"
               ".map(e => e.dataset.severity)")
    for severity, expected in counts.items():
        page.click(f'[data-filter="{severity}"]')
        shown = page.evaluate(visible)
        c.that(f"'{severity}' chip shows only its {expected} finding(s)",
               len(shown) == expected and set(shown) == {severity}, shown)
    page.click('[data-filter="all"]')
    c.equal("'Todos' shows every finding again", len(page.evaluate(visible)), total)


@case("MT-03", "browser", "Printable report saved as PDF")
def mt03(ctx: Context, c: Checks):
    page = browser(ctx)
    analysis_id = ctx.state["mt_analysis"]
    page.open(ctx.args.app_url + f"index.php?page=report&id={analysis_id}")
    data = page.pdf(ctx.evidence / "MT-03-report.pdf")
    c.that("a PDF was produced", data.startswith(b"%PDF"), data[:8])
    try:
        from pypdf import PdfReader
    except ImportError:
        c.that("pypdf available to read the PDF back", False, "pip install pypdf")
        return
    import io
    text = " ".join((p.extract_text() or "") for p in PdfReader(io.BytesIO(data)).pages)
    flat = re.sub(r"\s+", " ", text)
    export = ctx.export(analysis_id)
    c.that("header: application name", ctx.state["mt_application"] in flat)
    c.that("header: score", "Pontuação de Segurança" in flat and str(export["analysis"]["security_score"]) in flat)
    c.that("metrics", all(m in flat for m in ("Verificações executadas", "Achados", "Duração")))
    missing = [f["title"] for f in export["findings"] if re.sub(r"\s+", " ", f["title"]) not in flat]
    c.equal("every finding title printed", missing, [])
    c.that("navigation not printed", "Adicionar aplicação" not in flat)
    c.that("buttons not printed", "Imprimir / Salvar como PDF" not in flat and "Exportar JSON" not in flat)


# ---------------------------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------------------------


def write_reports(evidence: pathlib.Path, results: list[dict], meta: dict) -> None:
    (evidence / "results.json").write_text(json.dumps({"meta": meta, "results": results}, ensure_ascii=False,
                                                      indent=2), encoding="utf-8")
    lines = [f"# System test run {meta['run']}", "", f"- Started: {meta['started']}", f"- Finished: {meta['finished']}",
             f"- Application: {meta['app_url']}", f"- Passed: {meta['passed']} / {meta['total']}", "",
             "| Case | Title | Verdict | Duration (s) |", "|---|---|---|---|"]
    for r in results:
        lines.append(f"| {r['id']} | {r['title']} | **{r['verdict']}** | {r['seconds']} |")
    for r in results:
        lines += ["", f"## {r['id']} — {r['title']} — {r['verdict']}", ""]
        for label, ok, observed in r["checks"]:
            lines.append(f"- [{'x' if ok else ' '}] {label}" + ("" if ok else f" — observed: `{observed}`"))
        if r.get("error"):
            lines += ["", "```", r["error"], "```"]
    (evidence / "results.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="SentinelScope system and failure-injection tests")
    parser.add_argument("--app-url", default="http://localhost/www/Ciber/public/")
    parser.add_argument("--lab-port", type=int, default=8765)
    parser.add_argument("--suite", choices=["system", "failure", "browser", "all"], default="all")
    parser.add_argument("--only", nargs="*", default=None)
    parser.add_argument("--run-name", default=None)
    xampp = pathlib.Path("C:/xampp")
    parser.add_argument("--mysql", default=str(xampp / "mysql/bin/mysql.exe"))
    parser.add_argument("--mysqldump", default=str(xampp / "mysql/bin/mysqldump.exe"))
    parser.add_argument("--mysqladmin", default=str(xampp / "mysql/bin/mysqladmin.exe"))
    parser.add_argument("--mysqld", default=str(xampp / "mysql/bin/mysqld.exe"))
    parser.add_argument("--mysql-ini", default=str(xampp / "mysql/bin/my.ini"))
    parser.add_argument("--apache-log", default=str(xampp / "apache/logs/access.log"))
    # php.ini points error_log at php/logs/, which XAMPP does not create; PHP then writes to Apache's.
    parser.add_argument("--php-log", default=str(xampp / "apache/logs/error.log"))
    args = parser.parse_args()

    run = args.run_name or datetime.now().strftime("%Y-%m-%d_%H%M%S")
    evidence = ROOT / "docs" / "test-evidence" / run
    evidence.mkdir(parents=True, exist_ok=True)
    ctx = Context(args, evidence)
    selected = [(i, s, t, f) for i, s, t, f in CASES
                if (args.suite == "all" or s == args.suite) and (not args.only or i in args.only)]
    started = datetime.now(timezone.utc).isoformat(timespec="seconds")
    results = []
    try:
        for case_id, suite, title, function in selected:
            checks = Checks()
            clock = time.time()
            error = None
            try:
                function(ctx, checks)
                verdict = "PASS" if checks.passed and checks.items else "FAIL"
            except Exception:  # an exception is a failed case, recorded with its traceback
                error = traceback.format_exc(limit=4)
                verdict = "ERROR"
            seconds = round(time.time() - clock, 1)
            results.append({"id": case_id, "suite": suite, "title": title, "verdict": verdict, "seconds": seconds,
                            "checks": checks.items, "error": error})
            print(f"{case_id:6} {verdict:5} {seconds:7.1f}s  {title}", flush=True)
            for label, ok, observed in checks.items:
                if not ok:
                    print(f"         - {label}: {observed}", flush=True)
            if error:
                print("         " + error.strip().splitlines()[-1], flush=True)
    finally:
        ctx.lab.stop()
        if "browser" in ctx.state:
            ctx.state["browser"].close()
    passed = sum(r["verdict"] == "PASS" for r in results)
    meta = {"run": run, "started": started, "finished": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "app_url": args.app_url, "passed": passed, "total": len(results), "python": sys.version.split()[0],
            "platform": sys.platform}
    write_reports(evidence, results, meta)
    print(f"\n{passed}/{len(results)} passed — evidence in {evidence.relative_to(ROOT)}")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
