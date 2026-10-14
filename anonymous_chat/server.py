#!/usr/bin/env python3
"""
Anonymous Chat — frontend server.

Serves index.html on 127.0.0.1 (port 8080 by default) and opens it in your
browser. It is NOT a chat server: it never relays, stores, fabricates or
processes chat messages — the page it serves connects straight to the live
chat network from your browser.
"""

import os
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

if os.name == "nt":
    os.system("")  # enable ANSI colours on Windows 10+ consoles

RESET, BOLD, DIM = "\033[0m", "\033[1m", "\033[2m"
RED, GREEN, YELLOW, CYAN = "\033[91m", "\033[92m", "\033[93m", "\033[96m"

HOST = "127.0.0.1"
PREFERRED_PORT = 8080
ROOT = os.path.dirname(os.path.abspath(__file__))
INDEX = os.path.join(ROOT, "index.html")


class FrontendHandler(BaseHTTPRequestHandler):
    server_version = "AnonymousChat/1.0"

    def do_GET(self):
        if self.path not in ("/", "/index.html"):
            self._send(404, b"404 - not found\n", "text/plain; charset=utf-8")
            return
        try:
            with open(INDEX, "rb") as fh:
                body = fh.read()
        except OSError:
            self._send(500, b"500 - index.html is missing next to server.py\n",
                       "text/plain; charset=utf-8")
            return
        self._send(200, body, "text/html; charset=utf-8")

    def _send(self, code, body, ctype):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):  # keep the console clean
        pass


def build_server():
    """Return (port, httpd) — tries 8080, then 8081 … 8090."""
    for port in range(PREFERRED_PORT, PREFERRED_PORT + 11):
        try:
            return port, ThreadingHTTPServer((HOST, port), FrontendHandler)
        except OSError:
            continue
    return None, None


def _open(url):
    try:
        webbrowser.open(url)
    except Exception:
        pass


def main(open_browser=True):
    port, httpd = build_server()
    if httpd is None:
        print(f"{RED}{BOLD}[!] could not start: ports 8080-8090 on {HOST} are busy.{RESET}")
        print(f"{YELLOW}    close whatever is using them and try again.{RESET}")
        return 1

    url = f"http://{HOST}:{port}/"
    print()
    print(f"  {CYAN}{BOLD}ANONYMOUS CHAT{RESET} {DIM}// browser frontend{RESET}")
    if port == PREFERRED_PORT:
        print(f"  {GREEN}[+] serving {url}{RESET}")
    else:
        print(f"  {YELLOW}[!] port 8080 was busy — using {url} instead{RESET}")
    print(f"  {DIM}this server only delivers the web page — it never sees your messages{RESET}")
    print(f"  {DIM}press Ctrl+C to stop{RESET}")
    print()

    if open_browser:
        threading.Timer(0.4, lambda: _open(url)).start()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    print(f"{CYAN}[*] frontend server stopped — returning to the main menu …{RESET}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())