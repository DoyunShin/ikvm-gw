"""Authentication helpers for the ATEN iKVM upstream connection.

Ported from spike/m0_probe.py.  No live network in tests; the only I/O is
blocking HTTP via urllib (intentional: these calls happen once at startup
outside the asyncio loop).

Security contract:
  - Password, SID, token, and credential block bytes are NEVER logged.
  - Cookie / Set-Cookie / Authorization header values are NEVER logged.
"""

from __future__ import annotations

import base64
import http.cookies
import json
import logging
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

log = logging.getLogger(__name__)


def load_credentials(path: Path) -> tuple[str, str, str]:
    """Load BMC connection credentials from a plain-text file.

    The file must contain exactly 3 non-empty lines:
        line 1: BMC hostname or IP address
        line 2: web-UI username
        line 3: web-UI password

    The file contents are never logged.

    Args:
        path (Path): Path to the credentials file (e.g. ``Path("secret")``).

    Returns:
        credentials (tuple[str, str, str]): ``(host, username, password)``.

    Raises:
        ValueError: If the file does not contain exactly 3 non-empty lines.
        FileNotFoundError: If the path does not exist.
    """
    lines = [ln.rstrip("\n") for ln in path.read_text().splitlines()]
    lines = [ln for ln in lines if ln]
    if len(lines) != 3:
        raise ValueError(
            f"Expected 3 credential lines in {path}; found {len(lines)}"
        )
    return lines[0], lines[1], lines[2]


def login_web_ui(host: str, username: str, password: str) -> str:
    """Perform BMC web login and return the SID cookie value.

    Issues a blocking POST to ``https://<host>/cgi/login.cgi`` with
    form-encoded fields ``name`` and ``pwd``.  TLS verification is
    intentionally disabled (self-signed BMC certificate; the management
    network is trusted).

    Args:
        host (str): BMC hostname or IP address.
        username (str): Web-UI username.
        password (str): Web-UI password.

    Returns:
        sid (str): The SID cookie value from Set-Cookie.

    Raises:
        RuntimeError: If the response contains no SID cookie.  The error
                      message includes only the HTTP status and body length
                      (no credential material).
    """
    url = f"https://{host}/cgi/login.cgi"
    form_data = urllib.parse.urlencode(
        {"name": username, "pwd": password}
    ).encode("ascii")

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(
        url,
        data=form_data,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )

    log.info("Attempting web login to %s", host)

    with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
        status = resp.status
        body_len = len(resp.read())
        raw_cookies = resp.headers.get_all("Set-Cookie") or []

    jar: dict[str, str] = {}
    for cookie_header in raw_cookies:
        morsel = http.cookies.SimpleCookie()
        morsel.load(cookie_header)
        for key, val in morsel.items():
            jar[key] = val.value

    if "SID" not in jar:
        raise RuntimeError(
            f"Web login failed: HTTP {status}, body {body_len} bytes, no SID in Set-Cookie"
        )

    log.info("Web login succeeded; SID obtained (value [REDACTED])")
    return jar["SID"]


def fetch_ikvm_token(host: str, username: str, password: str) -> str:
    """Fetch the per-session iKVM credential token from the HTML5 console page.

    The Insyde/Nuvoton HTML5 console authenticates the RFB stream with a
    short-lived session token embedded in a Redfish-generated HTML page:

      1. GET ``https://<host>/redfish/v1/Managers/1/Oem/Supermicro/IKVM``
         (HTTP Basic auth) -> JSON ``{"URI": "/redfish/<random>.IKVM"}``
      2. GET ``https://<host><URI>`` (HTTP Basic auth) -> HTML containing
         ``<input type="hidden" id="entry_value" value="<TOKEN>">``

    The token must be sent as the 24-byte RFB username field (NUL-padded),
    with 24 zero bytes as the password field.  It is never logged.

    Args:
        host (str): BMC hostname or IP.
        username (str): BMC username (for HTTP Basic auth).
        password (str): BMC password (for HTTP Basic auth).

    Returns:
        token (str): The ``entry_value`` session token.

    Raises:
        RuntimeError: If the Redfish URI or the ``entry_value`` token cannot
                      be found.  Error messages contain no secret material.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    basic = base64.b64encode(
        f"{username}:{password}".encode("latin-1")
    ).decode("ascii")
    auth_header = {
        "Authorization": f"Basic {basic}",
        "User-Agent": "Mozilla/5.0",
    }

    log.info("Fetching Redfish IKVM launch URI from %s", host)
    redfish_url = f"https://{host}/redfish/v1/Managers/1/Oem/Supermicro/IKVM"
    req = urllib.request.Request(redfish_url, headers=auth_header)
    with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
        payload = json.loads(resp.read())

    uri = payload.get("URI")
    if not uri:
        raise RuntimeError("Redfish IKVM response has no URI field")
    log.info("Redfish IKVM URI obtained")

    page_url = f"https://{host}{uri}"
    req2 = urllib.request.Request(page_url, headers=auth_header)
    with urllib.request.urlopen(req2, context=ctx, timeout=15) as resp:
        html = resp.read().decode("utf-8", errors="replace")

    match = re.search(
        r'id=["\']entry_value["\']\s+value=["\']([^"\']+)["\']', html
    )
    if not match:
        raise RuntimeError(
            f"entry_value token not found in console page ({len(html)} bytes)"
        )

    log.info("iKVM session token obtained (value [REDACTED])")
    return match.group(1)
