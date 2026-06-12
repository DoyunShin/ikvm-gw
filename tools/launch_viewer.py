"""Turnkey local noVNC viewer launcher.

Fetches a one-time session ticket from a running ikvm-gateway (using the
control API key), injects it into the noVNC viewer page (web/viewer.html), and
serves that page on a local port so it can be opened in a browser. The ticket
lives only in the served HTML body, never in a URL or a log line.

Usage:
    # 1. Start the gateway (prints its control API key to stderr):
    uv run python -m ikvm_gateway --secret secret
    # 2. Launch the viewer with that key:
    uv run python -m tools.launch_viewer --api-key <key>
    # 3. Open the printed http://127.0.0.1:8800/ URL in a browser.
"""

from __future__ import annotations

import argparse
import http.server
import json
import socketserver
import sys
import urllib.request
from pathlib import Path

VIEWER_TEMPLATE = Path(__file__).resolve().parent.parent / "web" / "viewer.html"


def fetch_ticket(gateway_http: str, api_key: str) -> str:
    """Request a one-time session ticket from the gateway control endpoint.

    Args:
        gateway_http (str): Gateway HTTP base, e.g. http://127.0.0.1:5700.
        api_key (str): Control API key (Bearer).

    Returns:
        ticket (str): The issued one-time ticket.
    """
    req = urllib.request.Request(
        f"{gateway_http}/sessions",
        method="GET",
        headers={"Authorization": f"Bearer {api_key}"},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())["data"]["ticket"]


def render_viewer(ws_url: str, ticket: str) -> bytes:
    """Render the viewer HTML with the WS URL and ticket substituted."""
    html = VIEWER_TEMPLATE.read_text()
    return html.replace("__WS_URL__", ws_url).replace("__TICKET__", ticket).encode()


def serve_once(page: bytes, port: int) -> None:
    """Serve the viewer page on the given local port until interrupted."""

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(page)))
            self.end_headers()
            self.wfile.write(page)

        def log_message(self, *args: object) -> None:
            pass  # silence default logging (avoid leaking anything)

    with socketserver.TCPServer(("127.0.0.1", port), _Handler) as httpd:
        sys.stderr.write(f"Open http://127.0.0.1:{port}/ in a browser (Ctrl-C to stop)\n")
        sys.stderr.flush()
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass


def main(argv: list[str] | None = None) -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(prog="launch_viewer")
    parser.add_argument("--api-key", required=True, help="gateway control API key")
    parser.add_argument("--gateway-host", default="127.0.0.1")
    parser.add_argument("--gateway-port", type=int, default=5700)
    parser.add_argument("--viewer-port", type=int, default=8800)
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])

    gateway_http = f"http://{args.gateway_host}:{args.gateway_port}"
    ws_url = f"ws://{args.gateway_host}:{args.gateway_port}/vnc"
    ticket = fetch_ticket(gateway_http, args.api_key)
    page = render_viewer(ws_url, ticket)
    serve_once(page, args.viewer_port)


if __name__ == "__main__":
    main()
