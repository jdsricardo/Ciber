#!/usr/bin/env python3
"""Loja de testes para a demonstração "antes e depois" do SentinelScope.

A mesma loja, no mesmo endereço (http://127.0.0.1:8765/), em dois modos:

  vulneravel  (o "antes")  /search?q= e /profile?name= devolvem o valor sem escapar (XSS
              refletido); nenhum cabeçalho de segurança; cookie sem HttpOnly e sem SameSite;
              cabeçalho Server expondo produto e versão.
  corrigido   (o "depois") as correções que o SentinelScope recomendou, marcadas no código com
              "CORREÇÃO". O único achado que continua é "Conexão não é criptografada": a loja
              roda em http:// local, e corrigi-lo exigiria um certificado TLS.

Como o endereço é o mesmo, as duas análises pertencem à mesma aplicação cadastrada e podem ser
comparadas. Escuta apenas em 127.0.0.1; analise com ALLOW_PRIVATE_TARGETS=true no .env.

    python tests/apresentacao/loja.py --modo vulneravel
    python tests/apresentacao/loja.py --modo corrigido
"""
from __future__ import annotations

import argparse
import html
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

CORRIGIDO = False  # definido pelo --modo

NAV = "<nav><a href='/'>Início</a> <a href='/search?q=livros'>Busca</a> " \
      "<a href='/profile?name=ana'>Perfil</a> <a href='/about'>Sobre</a></nav>"

# CORREÇÃO: cabeçalhos de segurança enviados em toda resposta.
SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'",      # limita de onde vêm scripts e recursos
    "X-Frame-Options": "DENY",                            # impede incorporar a página (clickjacking)
    "X-Content-Type-Options": "nosniff",                  # navegador não adivinha o tipo do conteúdo
    "Referrer-Policy": "no-referrer",                     # URLs não vazam pelo Referer
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Opener-Policy": "same-origin",          # isola a janela de outros sites
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cache-Control": "no-store",                          # resposta com sessão não fica em cache
}


def page(title: str, body: str) -> str:
    return (f"<!doctype html><html><head><meta charset='utf-8'><title>{title}</title></head>"
            f"<body><h1>{title}</h1>{NAV}{body}</body></html>")


def exibir(valor: str) -> str:
    """Valor vindo da URL, pronto para entrar no HTML."""
    if CORRIGIDO:
        return html.escape(valor)  # CORREÇÃO: valor escapado (sem XSS)
    return valor                   # vulnerável: HTML/script do atacante é executado


class Loja(BaseHTTPRequestHandler):
    server_version = "LojaDeTestes/1.0"  # no modo vulnerável vai no cabeçalho Server, com a versão do Python

    def log_message(self, *args) -> None:
        pass

    def send_response(self, code: int, message: str | None = None) -> None:
        if not CORRIGIDO:
            super().send_response(code, message)
            return
        # CORREÇÃO: não envia o cabeçalho Server (produto e versão ficam ocultos).
        self.log_request(code)
        self.send_response_only(code, message)
        self.send_header("Date", self.date_time_string())

    def send(self, status: int, body: str, headers: dict | None = None) -> None:
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        extra = {**SECURITY_HEADERS, **(headers or {})} if CORRIGIDO else (headers or {})
        for name, value in extra.items():
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def do_HEAD(self) -> None:
        self.do_GET()

    def do_GET(self) -> None:
        url = urlparse(self.path)
        query = parse_qs(url.query)

        if url.path == "/":
            if CORRIGIDO:
                # CORREÇÃO: HttpOnly (JavaScript não lê) e SameSite (não vai em requisições de outros sites).
                cookie = "sessao=abc123; Path=/; HttpOnly; SameSite=Lax"
            else:
                cookie = "sessao=abc123; Path=/"
            self.send(200, page("Início", "<p>Loja de laboratório para testes autorizados.</p>"),
                      {"Set-Cookie": cookie})
        elif url.path == "/search":
            termo = exibir(query.get("q", [""])[0])
            self.send(200, page("Busca", f"<p>Você pesquisou por: {termo}</p>"))
        elif url.path == "/profile":
            nome = exibir(query.get("name", [""])[0])
            self.send(200, page("Perfil", f"<p>Olá, {nome}</p>"))
        elif url.path == "/about":
            self.send(200, page("Sobre", "<p>Página estática.</p>"))
        else:
            self.send(404, page("Não encontrado", ""))


class Servidor(ThreadingHTTPServer):
    allow_reuse_address = False  # no Windows, True deixaria duas lojas ouvirem a mesma porta


def main() -> None:
    global CORRIGIDO
    parser = argparse.ArgumentParser(description="Loja de testes (antes e depois)")
    parser.add_argument("--modo", choices=["vulneravel", "corrigido"], default="vulneravel")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    CORRIGIDO = args.modo == "corrigido"
    try:
        server = Servidor(("127.0.0.1", args.port), Loja)
    except OSError:
        sys.exit(f"A porta {args.port} já está em uso. Encerre a outra loja (Ctrl+C) e tente de novo.")
    print(f"Loja {args.modo.upper()} no ar em http://127.0.0.1:{args.port}/  (Ctrl+C para encerrar)", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
