"""Tiny local HTTP server for realistic active-plugin integration tests.

Real sockets, real timing, real bytes on the wire — not a mocked transport — so a
passing test means the plugin genuinely works against an HTTP server, not just
against hand-built HttpResponse objects.

Usage:
    from http.server import BaseHTTPRequestHandler
    from support.local_server import serve

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            ...
        def log_message(self, *args):
            pass  # silence request logging during tests

    with serve(Handler) as base_url:
        result = run_scan(base_url + "/vuln?id=1", mode="safe_active", allow_private=True)
"""
from __future__ import annotations
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer

@contextmanager
def serve(handler_class: type[BaseHTTPRequestHandler]):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler_class)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
