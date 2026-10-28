#!/usr/bin/env python3
"""Controllable laboratory target for the system (end-to-end) tests.

A deliberately vulnerable web application whose state is chosen on the command line, so a test
can scan it, "deploy a fix" by restarting it with another variant, and scan it again. It runs
on 127.0.0.1 only and is meant to be scanned by SentinelScope with ALLOW_PRIVATE_TARGETS=true.

Variants
    vulnerable  /search?q= and /profile?name= reflect their value unescaped (two XSS findings on
                two endpoints); no security headers; session cookie without flags.
    partial     /search is fixed (escaped), /profile is still vulnerable. Scanning `vulnerable`
                and then `partial` is the before/after pair of the comparison test (CA-04).
    fixed       every reflection escaped and the usual security headers sent.
    edge        `vulnerable` plus /feedback, a form whose field name is 300 characters long
                (reflected unescaped when posted), used to check
                that values longer than a database column respect the integration contract.

Every request received is appended as one JSON line to --log, so a test can prove what the
scanner did and did not do: that /logout and /item?action=delete were never requested, how
many baseline requests a page received, and which Cookie header reached the target.

Usage
    python tests/e2e/lab_target.py --port 8765 --variant vulnerable --log lab.jsonl [--delay 0]
"""
from __future__ import annotations

import argparse
import html
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

SESSION_COOKIE = "lab_session"
LONG_FIELD = "f" * 300

CONFIG: dict = {"variant": "vulnerable", "delay": 0.0, "log": None, "secret": "lab-secret"}
LOG_LOCK = threading.Lock()


def page(title: str, body: str) -> str:
    return (
        f"<!doctype html><html><head><meta charset='utf-8'><title>{title}</title></head>"
        f"<body><h1>{title}</h1>{body}</body></html>"
    )


NAV = (
    "<nav><a href='/search?q=livros'>Busca</a> <a href='/profile?name=ana'>Perfil</a> "
    "<a href='/about'>Sobre</a> <a href='/account'>Minha conta</a> "
    "<a href='/logout'>Sair</a> <a href='/item?id=7&action=delete'>Excluir item</a></nav>"
)


class LabHandler(BaseHTTPRequestHandler):
    server_version = "LabTarget/1.0"

    # -- plumbing ---------------------------------------------------------------------------
    def log_message(self, *args) -> None:  # silence stderr; the JSONL log is the record
        pass

    def _record(self) -> None:
        if not CONFIG["log"]:
            return
        entry = {
            "t": round(time.time(), 3),
            "method": self.command,
            "path": self.path,
            "cookie": self.headers.get("Cookie"),
        }
        with LOG_LOCK, open(CONFIG["log"], "a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry) + "\n")

    def _send(self, status: int, body: str, extra: dict | None = None) -> None:
        if CONFIG["delay"]:
            time.sleep(CONFIG["delay"])
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        if CONFIG["variant"] == "fixed":
            self.send_header("Content-Security-Policy", "default-src 'self'")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
        for name, value in (extra or {}).items():
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _authenticated(self) -> bool:
        return f"{SESSION_COOKIE}={CONFIG['secret']}" in (self.headers.get("Cookie") or "")

    def _reflect(self, value: str, vulnerable: bool) -> str:
        return value if vulnerable else html.escape(value)

    # -- routes -----------------------------------------------------------------------------
    def do_HEAD(self) -> None:
        self.do_GET()

    def do_POST(self) -> None:
        self._record()
        length = int(self.headers.get("Content-Length") or 0)
        fields = parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
        path = urlparse(self.path).path
        if path == "/feedback" and CONFIG["variant"] == "edge":
            value = fields.get(LONG_FIELD, [""])[0]
            self._send(200, page("Obrigado", f"<p>Recebido: {value}</p>"))
            return
        self._send(405, page("Método não permitido", ""))

    def do_GET(self) -> None:
        self._record()
        url = urlparse(self.path)
        query = parse_qs(url.query)
        variant = CONFIG["variant"]
        vulnerable_search = variant in ("vulnerable", "edge")
        vulnerable_profile = variant in ("vulnerable", "partial", "edge")

        if url.path == "/":
            extra = {"Set-Cookie": "tracking=abc123; Path=/"}
            body = NAV + "<p>Loja de laboratório para testes autorizados.</p>"
            if variant == "edge":
                body += "<a href='/feedback'>Fale conosco</a>"
            self._send(200, page("Início", body), extra)
        elif url.path == "/feedback" and variant == "edge":
            # The engine submits form probes to the page that holds the form.
            self._send(200, page("Fale conosco", (
                "<form method='post' action='/feedback'>"
                f"<input name='{LONG_FIELD}' value='ok'><button>Enviar</button></form>"
            )))
        elif url.path == "/search":
            value = query.get("q", [""])[0]
            self._send(200, page("Busca", NAV + f"<p>Você pesquisou por: {self._reflect(value, vulnerable_search)}</p>"))
        elif url.path == "/profile":
            value = query.get("name", [""])[0]
            self._send(200, page("Perfil", NAV + f"<p>Olá, {self._reflect(value, vulnerable_profile)}</p>"))
        elif url.path == "/about":
            self._send(200, page("Sobre", NAV + "<p>Página estática.</p>"))
        elif url.path == "/account":
            if not self._authenticated():
                self._send(302, "", {"Location": "/"})
                return
            self._send(200, page("Área do cliente", NAV + "<a href='/account/notes?n=nota'>Notas</a>"))
        elif url.path == "/account/notes":
            if not self._authenticated():
                self._send(302, "", {"Location": "/"})
                return
            value = query.get("n", [""])[0]
            self._send(200, page("Notas", f"<p>Nota: {self._reflect(value, variant != 'fixed')}</p>"))
        elif url.path in ("/logout", "/item"):
            # Must never be reached by the read-only crawler; the log proves it.
            self._send(200, page("Ação executada", "<p>Estado alterado.</p>"))
        else:
            self._send(404, page("Não encontrado", ""))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--variant", choices=["vulnerable", "partial", "fixed", "edge"], default="vulnerable")
    parser.add_argument("--delay", type=float, default=0.0, help="Seconds to wait before each response")
    parser.add_argument("--log", default=None, help="JSONL file receiving one line per request")
    parser.add_argument("--secret", default="lab-secret", help="Session cookie value that unlocks /account")
    args = parser.parse_args()
    CONFIG.update(variant=args.variant, delay=args.delay, log=args.log, secret=args.secret)
    server = ThreadingHTTPServer(("127.0.0.1", args.port), LabHandler)
    print(f"lab target ({args.variant}) on http://127.0.0.1:{args.port}/", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
