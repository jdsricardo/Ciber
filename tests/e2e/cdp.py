"""Minimal Chrome DevTools Protocol client, standard library only.

Drives a real headless Chrome or Edge for the browser cases of the system tests (MT-01…MT-03):
navigate, evaluate JavaScript, dispatch real mouse events and print to PDF. It implements just
enough of RFC 6455 (client-masked text frames, unmasked server frames, fragmentation) for the
DevTools endpoint on 127.0.0.1; it is test tooling, not a general WebSocket library.
"""
from __future__ import annotations

import base64
import json
import os
import pathlib
import shutil
import socket
import struct
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request

BROWSER_CANDIDATES = (
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    "/usr/bin/google-chrome", "/usr/bin/chromium", "/usr/bin/chromium-browser",
)


def find_browser() -> str | None:
    for candidate in BROWSER_CANDIDATES:
        if os.path.exists(candidate):
            return candidate
    return shutil.which("chrome") or shutil.which("msedge")


class WebSocket:
    def __init__(self, url: str, timeout: float = 30) -> None:
        parts = urllib.parse.urlsplit(url)
        self.sock = socket.create_connection((parts.hostname, parts.port), timeout=timeout)
        key = base64.b64encode(os.urandom(16)).decode()
        self.sock.sendall((
            f"GET {parts.path} HTTP/1.1\r\nHost: {parts.hostname}:{parts.port}\r\nUpgrade: websocket\r\n"
            f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        ).encode())
        header = b""
        while b"\r\n\r\n" not in header:
            chunk = self.sock.recv(1)
            if not chunk:
                raise ConnectionError("DevTools closed the connection during the handshake")
            header += chunk
        if b" 101 " not in header.split(b"\r\n", 1)[0]:
            raise ConnectionError(header.decode("latin-1"))

    def _read(self, size: int) -> bytes:
        data = b""
        while len(data) < size:
            chunk = self.sock.recv(size - len(data))
            if not chunk:
                raise ConnectionError("DevTools connection closed")
            data += chunk
        return data

    def send(self, text: str) -> None:
        payload = text.encode()
        header = bytes([0x81])
        length = len(payload)
        if length < 126:
            header += bytes([0x80 | length])
        elif length < 65536:
            header += bytes([0x80 | 126]) + struct.pack(">H", length)
        else:
            header += bytes([0x80 | 127]) + struct.pack(">Q", length)
        mask = os.urandom(4)
        self.sock.sendall(header + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload)))

    def recv(self) -> str:
        message = b""
        while True:
            first, second = self._read(2)
            length = second & 0x7F
            if length == 126:
                length = struct.unpack(">H", self._read(2))[0]
            elif length == 127:
                length = struct.unpack(">Q", self._read(8))[0]
            payload = self._read(length)
            opcode = first & 0x0F
            if opcode == 0x8:
                raise ConnectionError("DevTools closed the connection")
            if opcode in (0x1, 0x2, 0x0):
                message += payload
                if first & 0x80:
                    return message.decode("utf-8")

    def close(self) -> None:
        self.sock.close()


class Browser:
    """One headless browser process with one page, controlled through DevTools."""

    def __init__(self, executable: str, port: int = 9333) -> None:
        self.profile = tempfile.mkdtemp(prefix="sentinelscope-browser-")
        self.process = subprocess.Popen(
            [executable, "--headless=new", f"--remote-debugging-port={port}", f"--user-data-dir={self.profile}",
             "--no-first-run", "--no-default-browser-check", "--disable-gpu", "--window-size=1280,900",
             "about:blank"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        deadline = time.time() + 20
        targets = None
        while time.time() < deadline:
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/json/list", timeout=2) as reply:
                    targets = [t for t in json.loads(reply.read()) if t.get("type") == "page"]
                if targets:
                    break
            except OSError:
                pass
            time.sleep(0.3)
        if not targets:
            self.close()
            raise RuntimeError("headless browser did not expose a page")
        self.ws = WebSocket(targets[0]["webSocketDebuggerUrl"])
        self.next_id = 0
        self.call("Page.enable")
        self.call("Runtime.enable")

    def call(self, method: str, **params):
        self.next_id += 1
        ident = self.next_id
        self.ws.send(json.dumps({"id": ident, "method": method, "params": params}))
        while True:
            message = json.loads(self.ws.recv())
            if message.get("id") == ident:
                if "error" in message:
                    raise RuntimeError(f"{method}: {message['error']}")
                return message.get("result", {})

    def evaluate(self, expression: str):
        result = self.call("Runtime.evaluate", expression=expression, returnByValue=True, awaitPromise=True)
        if "exceptionDetails" in result:
            raise RuntimeError(f"JavaScript error: {result['exceptionDetails']}")
        return result.get("result", {}).get("value")

    def wait_for(self, expression: str, timeout: float = 30) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                if self.evaluate(expression):
                    return True
            except (RuntimeError, ConnectionError):
                pass  # the page may be mid-navigation; ask again
            time.sleep(0.2)
        return False

    def open(self, url: str, timeout: float = 30) -> None:
        self.call("Page.navigate", url=url)
        time.sleep(0.2)
        self.wait_for(f"location.href === {json.dumps(url)} && document.readyState === 'complete'", timeout)

    def click(self, selector: str, count: int = 1) -> None:
        """Real mouse clicks at the centre of the element; count=2 is a double click."""
        box = self.evaluate(
            f"(() => {{ const e = document.querySelector({json.dumps(selector)}); e.scrollIntoView({{block:'center'}});"
            " const r = e.getBoundingClientRect(); return [r.x + r.width / 2, r.y + r.height / 2]; })()")
        x, y = box
        for click in range(1, count + 1):
            for kind in ("mousePressed", "mouseReleased"):
                self.call("Input.dispatchMouseEvent", type=kind, x=x, y=y, button="left", clickCount=click)

    def pdf(self, path: pathlib.Path) -> bytes:
        data = base64.b64decode(self.call("Page.printToPDF", printBackground=False)["data"])
        path.write_bytes(data)
        return data

    def close(self) -> None:
        try:
            self.ws.close()
        except Exception:  # the socket may never have been opened; closing is best effort
            pass
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
        shutil.rmtree(self.profile, ignore_errors=True)
