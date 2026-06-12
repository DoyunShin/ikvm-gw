"""Milestone-0 feasibility spike — ATEN iKVM probe orchestrator.

Proves the auth path on the real board:
  web login -> SID -> wss://<host>/ with SID cookie
  -> ATEN type-16 handshake (go-rfb style, with tunnels/aten1 pre-step)
  -> SecurityResult OK -> ServerInit -> FramebufferUpdateRequest
  -> capture first encoding header (expect 0x57 / 0x59).

DO NOT run against 10.239.251.3 directly; the team leader invokes this
after review.

Usage:
    uv run python -m spike.m0_probe

Expects a file named 'secret' in the current working directory with exactly
3 lines:
    line 1: BMC hostname or IP
    line 2: web-UI username
    line 3: web-UI password
"""

from __future__ import annotations

import asyncio
import base64
import http.cookies
import json
import logging
import re
import ssl
import struct
import sys
import time
import urllib.request
import urllib.parse
import urllib.error
from pathlib import Path
from typing import Any

from prompt_toolkit import print_formatted_text
from prompt_toolkit.formatted_text import FormattedText

from spike.aten_protocol import (
    ATEN_ENCODINGS,
    ATEN_EXTRA_MESSAGE_SKIP,
    build_framebuffer_update_request,
    build_set_encodings,
    check_aten_magic_gate,
    parse_rectangle_header,
    parse_security_result,
    parse_server_init,
)

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

READ_TIMEOUT_SEC = 10.0
MAX_AUTH_ATTEMPTS = 6
CAPTURES_DIR = Path("captures")


class PromptToolkitHandler(logging.Handler):
    """Log handler that writes via prompt_toolkit with styled output.

    Falls back to plain stderr text when the terminal does not support
    ANSI styling (e.g. serial console or pipe).
    """

    _STYLE_MAP: dict[int, str] = {
        logging.DEBUG: "ansicyan",
        logging.INFO: "ansigreen",
        logging.WARNING: "ansiyellow",
        logging.ERROR: "ansired",
        logging.CRITICAL: "ansired bold",
    }

    def _supports_color(self) -> bool:
        """Return True if stdout appears to support ANSI colour sequences."""
        return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

    def emit(self, record: logging.LogRecord) -> None:
        """Format and write one log record."""
        try:
            msg = self.format(record)
            if self._supports_color():
                style = self._STYLE_MAP.get(record.levelno, "")
                print_formatted_text(FormattedText([(style, msg)]))
            else:
                sys.stderr.write(msg + "\n")
                sys.stderr.flush()
        except Exception:
            self.handleError(record)


def _configure_logging(debug: bool = False) -> None:
    """Set up root logger with PromptToolkitHandler.

    Args:
        debug (bool): If True, set level to DEBUG and use verbose format.
    """
    root = logging.getLogger()
    root.handlers.clear()

    handler = PromptToolkitHandler()
    if debug:
        root.setLevel(logging.DEBUG)
        fmt = "[%(asctime)s] [%(filename)s:%(lineno)d] %(levelname)s # %(message)s"
    else:
        root.setLevel(logging.INFO)
        fmt = "[%(asctime)s] %(levelname)s # %(message)s"

    handler.setFormatter(logging.Formatter(fmt))
    root.addHandler(handler)


log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Credentials
# ---------------------------------------------------------------------------


def load_credentials(path: Path) -> tuple[str, str, str]:
    """Load BMC connection credentials from a local plain-text file.

    The file must contain exactly 3 lines (trailing newline allowed):
        line 1: BMC hostname or IP address
        line 2: web-UI username
        line 3: web-UI password

    The contents are never logged.

    Args:
        path (Path): Path to the credentials file.

    Returns:
        credentials (tuple[str, str, str]): (host, username, password).

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


# ---------------------------------------------------------------------------
# Web login
# ---------------------------------------------------------------------------


def login_web_ui(host: str, username: str, password: str) -> str:
    """Perform BMC web login and return the SID cookie value.

    Issues a blocking POST to https://<host>/cgi/login.cgi with the
    form-encoded fields 'name' and 'pwd'. The BMC uses a self-signed TLS
    certificate; TLS verification is intentionally disabled (management
    network is trusted; this is anti-eavesdrop only — REQUIREMENTS.md §8).

    Args:
        host (str): BMC hostname or IP address.
        username (str): Web-UI username.
        password (str): Web-UI password.

    Returns:
        sid (str): The SID cookie value from Set-Cookie.

    Raises:
        RuntimeError: If the response contains no SID cookie. The error
                      message includes the HTTP status and body length only
                      (no body content, since it could echo credentials).
    """
    url = f"https://{host}/cgi/login.cgi"
    form_data = urllib.parse.urlencode({"name": username, "pwd": password}).encode(
        "ascii"
    )

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

    The modern Supermicro/Nuvoton HTML5 console authenticates the RFB stream
    with a short-lived session token, NOT the BMC username/password. The token
    is embedded as a hidden input (id="entry_value") in the console HTML page
    that the Redfish OEM IKVM endpoint generates per launch:

      1. GET https://<host>/redfish/v1/Managers/1/Oem/Supermicro/IKVM
         (HTTP Basic auth) -> JSON {"URI": "/redfish/<random>.IKVM"}
      2. GET https://<host><URI> (HTTP Basic auth) -> HTML containing
         <input type="hidden" id="entry_value" value="<TOKEN>">

    The browser then sends this token (NUL-padded to 24 bytes) as the RFB
    InsydeVNC username field. The token is treated as a secret and never logged.

    Args:
        host (str): BMC hostname or IP.
        username (str): BMC username (for HTTP Basic auth).
        password (str): BMC password (for HTTP Basic auth).

    Returns:
        token (str): The entry_value session token.

    Raises:
        RuntimeError: If the Redfish URI or the entry_value token cannot be
                      found. Error messages contain no secret material.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    basic = base64.b64encode(f"{username}:{password}".encode("latin-1")).decode("ascii")
    auth_header = {"Authorization": f"Basic {basic}", "User-Agent": "Mozilla/5.0"}

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

    match = re.search(r'id=["\']entry_value["\']\s+value=["\']([^"\']+)["\']', html)
    if not match:
        raise RuntimeError(
            f"entry_value token not found in console page ({len(html)} bytes)"
        )
    log.info("iKVM session token obtained (value [REDACTED])")
    return match.group(1)


# ---------------------------------------------------------------------------
# Hex dump helper (received bytes only)
# ---------------------------------------------------------------------------


def hexdump_bytes(data: bytes, label: str = "") -> str:
    """Return a compact hex representation of received bytes for logging.

    Suitable for dumping protocol fields observed on the wire.

    Args:
        data (bytes): The bytes to dump.
        label (str): Optional label prepended to the output.

    Returns:
        text (str): Multi-line hex dump string.
    """
    lines: list[str] = []
    if label:
        lines.append(f"{label} ({len(data)} bytes):")
    for i in range(0, len(data), 16):
        chunk = data[i : i + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        lines.append(f"  {i:04x}  {hex_part}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Transport abstractions
# ---------------------------------------------------------------------------


class WsTransport:
    """Async transport wrapping a websockets connection to the BMC.

    The ATEN RFB byte stream may be fragmented across WebSocket frames
    arbitrarily, because RFB is a stream protocol and WebSocket framing
    is independent. Incoming binary messages are buffered and reassembled;
    read_exact(n) returns exactly n bytes regardless of frame boundaries.

    TLS verification is intentionally disabled (self-signed BMC cert;
    management network is trusted).

    Args:
        host (str): BMC hostname or IP.
        sid (str): SID cookie value from web login.
    """

    def __init__(self, host: str, sid: str) -> None:
        self._host = host
        self._sid = sid
        self._ws: Any = None
        self._buf = bytearray()

    async def connect(self) -> None:
        """Establish the WebSocket connection to wss://<host>/.

        Sets Sec-WebSocket-Version: 13, Cookie: SID=<sid>, Origin header.
        No subprotocol is negotiated (the BMC uses none).
        Credentials in Cookie header are never logged.
        """
        import websockets

        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

        additional_headers = {
            "Cookie": f"SID={self._sid}",
            "Origin": f"https://{self._host}",
        }

        log.info("Connecting via WebSocket to wss://%s/", self._host)

        self._ws = await websockets.connect(
            f"wss://{self._host}/",
            ssl=ssl_ctx,
            additional_headers=additional_headers,
            max_size=None,
        )
        log.info("WebSocket connection established")

    async def _fill_buf(self, needed: int) -> None:
        """Read WebSocket frames until buf has at least 'needed' bytes.

        Args:
            needed (int): Minimum number of bytes required in the buffer.
        """
        while len(self._buf) < needed:
            frame = await asyncio.wait_for(self._ws.recv(), timeout=READ_TIMEOUT_SEC)
            if isinstance(frame, str):
                self._buf.extend(frame.encode("latin-1"))
            else:
                self._buf.extend(frame)

    async def read_exact(self, n: int) -> bytes:
        """Read exactly n bytes from the ATEN RFB byte stream.

        Buffers across WebSocket frame boundaries.

        Args:
            n (int): Number of bytes to read.

        Returns:
            data (bytes): Exactly n bytes.
        """
        await asyncio.wait_for(self._fill_buf(n), timeout=READ_TIMEOUT_SEC)
        data = bytes(self._buf[:n])
        del self._buf[:n]
        return data

    async def write(self, data: bytes) -> None:
        """Send bytes to the BMC as a binary WebSocket frame.

        Args:
            data (bytes): Bytes to send.
        """
        await self._ws.send(data)

    async def close(self) -> None:
        """Close the WebSocket connection."""
        if self._ws is not None:
            await self._ws.close()


class TcpTransport:
    """Async transport for raw TLS TCP on port 5900.

    TLS is applied from the very first byte (TLS-from-start, not STARTTLS).
    TLS verification is intentionally disabled (self-signed BMC cert).
    check_hostname is set to False because the target is an IP address.

    Args:
        host (str): BMC hostname or IP.
        port (int): TCP port (default 5900).
    """

    def __init__(self, host: str, port: int = 5900) -> None:
        self._host = host
        self._port = port
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None

    async def connect(self) -> None:
        """Open a TLS TCP connection to <host>:<port>.

        Uses server_hostname=None workaround for IP targets with
        check_hostname=False to avoid hostname validation errors.
        """
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

        log.info("Connecting via TLS TCP to %s:%d", self._host, self._port)

        self._reader, self._writer = await asyncio.open_connection(
            self._host, self._port, ssl=ssl_ctx, server_hostname=self._host
        )
        log.info("TLS TCP connection established")

    async def read_exact(self, n: int) -> bytes:
        """Read exactly n bytes from the TCP stream.

        Args:
            n (int): Number of bytes to read.

        Returns:
            data (bytes): Exactly n bytes.

        Raises:
            EOFError: If the connection closes before n bytes arrive.
        """
        data = await asyncio.wait_for(
            self._reader.readexactly(n), timeout=READ_TIMEOUT_SEC
        )
        return data

    async def write(self, data: bytes) -> None:
        """Write bytes to the TCP stream and drain.

        Args:
            data (bytes): Bytes to send.
        """
        self._writer.write(data)
        await self._writer.drain()

    async def close(self) -> None:
        """Close the TCP connection."""
        if self._writer is not None:
            self._writer.close()
            try:
                await self._writer.wait_closed()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# ATEN handshake
# ---------------------------------------------------------------------------


async def perform_aten_handshake(
    transport: WsTransport | TcpTransport,
    credential_block: bytes,
    version_echo: bytes | None = None,
) -> dict:
    """Execute the full ATEN type-16 RFB authentication handshake.

    Steps (per unistack-org/go-rfb security_aten.go and REQUIREMENTS.md §4.2):
      1. Read 12-byte RFB version banner.
      2. Validate it starts with 'RFB '.
      3. Echo the EXACT same 12 bytes back (do NOT normalise to 003.008).
      4. Read u8 num_security_types, then that many type bytes.
      5. Require type 0x10 is present; send single byte 0x10.
      6. Read 4-byte nt (TightVNC tunnel count / magic field).
      7. Apply magic gate: if fires, read and discard 20 bytes; set aten1 mode.
      8. Send the 48-byte credential block.
      9. Read 4-byte SecurityResult.

    The credential block must NOT be logged or included in the return dict.

    Args:
        transport: A connected WsTransport or TcpTransport instance.
        credential_block (bytes): 48-byte credential block (not logged).

    Returns:
        result (dict):
            version_banner       (bytes): 12-byte banner received.
            num_security_types   (int)
            security_types       (list[int])
            aten1_gate_fired     (bool)
            nt_value             (int): raw uint32 from tunnel field
            nt_hex               (str): hex representation of nt_value
            opaque_block_hex     (str): hex of the 24-byte block (nt + skip)
            security_result      (int): 0=OK, 1=fail
            security_result_hex  (str)

    Raises:
        RuntimeError: On protocol violations (wrong banner, missing type 16).
        asyncio.TimeoutError: If a read exceeds READ_TIMEOUT_SEC.
    """
    result: dict[str, Any] = {}

    # Step 1-3: Version banner
    banner = await transport.read_exact(12)
    log.info("Server banner: %r", banner)

    if not banner.startswith(b"RFB "):
        raise RuntimeError(f"Unexpected banner: {banner!r}")

    result["version_banner"] = banner
    echo = version_echo if version_echo is not None else banner
    result["version_echo"] = echo
    if echo == banner:
        log.info("Echoing exact banner bytes back: %r", echo)
    else:
        log.info("Sending overridden version %r (server sent %r)", echo, banner)
    await transport.write(echo)

    # Step 4: Security types
    num_types_raw = await transport.read_exact(1)
    num_types = num_types_raw[0]
    result["num_security_types"] = num_types
    log.info("Number of security types offered: %d", num_types)

    if num_types == 0:
        raise RuntimeError("Server offered 0 security types (connection rejected)")

    types_raw = await transport.read_exact(num_types)
    sec_types = list(types_raw)
    result["security_types"] = sec_types
    log.info("Security types offered: %s", [hex(t) for t in sec_types])

    # Step 5: Select type 16
    if 0x10 not in sec_types:
        raise RuntimeError(
            f"ATEN security type 0x10 not offered; got: {[hex(t) for t in sec_types]}"
        )

    log.info("Selecting security type 0x10 (ATEN)")
    await transport.write(bytes([0x10]))

    # Step 6: Read 4-byte nt (TightVNC tunnel count / magic field)
    nt_raw = await transport.read_exact(4)
    (nt,) = struct.unpack(">I", nt_raw)
    result["nt_value"] = nt
    result["nt_hex"] = nt_raw.hex()
    log.info("nt field: 0x%08x", nt)

    # Step 7: Magic gate
    gate_fired = check_aten_magic_gate(nt)
    result["aten1_gate_fired"] = gate_fired

    if gate_fired:
        log.info("Magic gate fired; reading and discarding 20 bytes (aten1 path)")
        skip_raw = await transport.read_exact(20)
        opaque_block = nt_raw + skip_raw
        result["opaque_block_hex"] = opaque_block.hex()
        log.debug(
            "24-byte opaque block (nt + skip):\n%s",
            hexdump_bytes(opaque_block, "opaque"),
        )
    else:
        log.info("Magic gate did NOT fire; no skip bytes consumed (aten1 path NOT taken)")
        result["opaque_block_hex"] = nt_raw.hex()

    # Step 8: Send credential block (never logged)
    log.info("Sending credential block [REDACTED 48 bytes]")
    await transport.write(credential_block)

    # Step 9: SecurityResult
    sr_raw = await transport.read_exact(4)
    sr = parse_security_result(sr_raw)
    result["security_result"] = sr
    result["security_result_hex"] = sr_raw.hex()
    log.info("SecurityResult: %d (%s)", sr, "OK" if sr == 0 else "FAIL")

    if sr != 0:
        # Try to read failure reason
        try:
            reason_len_raw = await asyncio.wait_for(
                transport.read_exact(4), timeout=READ_TIMEOUT_SEC
            )
            (reason_len,) = struct.unpack(">I", reason_len_raw)
            reason_bytes = await asyncio.wait_for(
                transport.read_exact(reason_len), timeout=READ_TIMEOUT_SEC
            )
            result["failure_reason"] = reason_bytes.decode("utf-8", errors="replace")
            log.warning("Auth failure reason: %s", result["failure_reason"])
        except Exception as exc:
            log.warning("Could not read failure reason: %s", exc)

    return result


# ---------------------------------------------------------------------------
# Single probe variant
# ---------------------------------------------------------------------------


async def run_probe_variant(
    variant_name: str,
    host: str,
    transport_kind: str,
    credential_block: bytes,
    sid: str,
    username: str,
    password: str,
    version_echo: bytes | None = None,
) -> dict:
    """Run one full probe attempt and return a structured result dict.

    Connects via the given transport, performs the ATEN handshake, and on
    SecurityResult==0 proceeds through ClientInit, ServerInit, and captures
    the first FramebufferUpdate rectangle header.

    All bytes RECEIVED are written to captures/m0_<variant_name>.bin.
    Credentials and SID are never written to capture files.

    Args:
        variant_name (str): Identifier for this variant (used in filenames
                            and log output).
        host (str): BMC hostname or IP.
        transport_kind (str): 'ws' or 'tcp5900'.
        credential_block (bytes): 48-byte credential block (never logged).
        sid (str): SID value used in WS Cookie header (never logged).
        username (str): Username (used only if transport_kind='tcp5900').
        password (str): Password (used only if transport_kind='tcp5900').

    Returns:
        outcome (dict):
            variant_name       (str)
            transport          (str)
            success            (bool): True if SecurityResult==0 AND rect captured
            security_result    (int): 0=OK, else failure code
            handshake          (dict): Output of perform_aten_handshake
            server_init        (dict | None): Parsed ServerInit, or None
            first_rect         (dict | None): Parsed rect header, or None
            error              (str | None): Exception message on failure
    """
    log.info("--- Variant %s (%s) ---", variant_name, transport_kind)
    CAPTURES_DIR.mkdir(exist_ok=True)
    capture_path = CAPTURES_DIR / f"m0_{variant_name}.bin"
    capture_fh = open(capture_path, "wb")

    received_bytes = bytearray()

    def record(data: bytes) -> bytes:
        """Append received bytes to the capture buffer (no creds)."""
        received_bytes.extend(data)
        capture_fh.write(data)
        capture_fh.flush()
        return data

    # Wrap transport.read_exact to record all received bytes
    class RecordingTransport:
        def __init__(self, inner: Any) -> None:
            self._inner = inner

        async def read_exact(self, n: int) -> bytes:
            data = await self._inner.read_exact(n)
            record(data)
            return data

        async def write(self, data: bytes) -> None:
            await self._inner.write(data)

        async def close(self) -> None:
            await self._inner.close()

    outcome: dict[str, Any] = {
        "variant_name": variant_name,
        "transport": transport_kind,
        "success": False,
        "security_result": -1,
        "handshake": None,
        "server_init": None,
        "first_rect": None,
        "error": None,
    }

    transport: Any = None
    try:
        if transport_kind == "ws":
            raw_transport = WsTransport(host, sid)
        else:
            raw_transport = TcpTransport(host, 5900)

        await raw_transport.connect()
        transport = RecordingTransport(raw_transport)

        handshake = await perform_aten_handshake(
            transport, credential_block, version_echo
        )
        outcome["handshake"] = handshake
        outcome["security_result"] = handshake["security_result"]

        if handshake["security_result"] != 0:
            log.warning("Variant %s: auth failed, stopping", variant_name)
            return outcome

        # ClientInit: shared=1
        log.info("Sending ClientInit (shared=1)")
        await transport.write(bytes([0x01]))

        # ServerInit: base 24 bytes + name + ATEN extra 12 bytes
        log.info("Reading ServerInit base (24 bytes)")
        srv_base = await transport.read_exact(24)

        name_len = struct.unpack_from(">I", srv_base, 20)[0]
        log.info("ServerInit name_length: %d", name_len)

        name_bytes = await transport.read_exact(name_len) if name_len > 0 else b""
        aten_extra = await transport.read_exact(12)

        srv_data = srv_base + name_bytes + aten_extra
        srv_init = parse_server_init(srv_data)
        outcome["server_init"] = srv_init

        log.info(
            "ServerInit: %dx%d, name=%r, IKVMVideo=%d, IKVMKM=%d",
            srv_init["framebuffer_width"],
            srv_init["framebuffer_height"],
            srv_init["name_text"].decode("ascii", errors="replace"),
            srv_init["ikvm_video_enable"],
            srv_init["ikvm_km_enable"],
        )
        log.debug(
            "ServerInit pixel_format raw:\n%s",
            hexdump_bytes(srv_init["pixel_format"]["raw"], "pf"),
        )
        log.debug(
            "ServerInit ATEN unknown bytes:\n%s",
            hexdump_bytes(srv_init["aten_unknown"], "aten_extra"),
        )

        # SetEncodings
        fb_w = srv_init["framebuffer_width"] or 800
        fb_h = srv_init["framebuffer_height"] or 600
        log.info("Sending SetEncodings (%d encodings)", len(ATEN_ENCODINGS))
        await transport.write(build_set_encodings(ATEN_ENCODINGS))

        # FramebufferUpdateRequest (non-incremental, full screen)
        log.info("Sending FramebufferUpdateRequest (non-incremental, %dx%d)", fb_w, fb_h)
        await transport.write(
            build_framebuffer_update_request(False, 0, 0, fb_w, fb_h)
        )

        # Read server messages until we see a FramebufferUpdate (type 0)
        first_rect = None
        for _ in range(20):
            msg_type_raw = await transport.read_exact(1)
            msg_type = msg_type_raw[0]
            log.info("Received server message type: 0x%02x (%d)", msg_type, msg_type)

            if msg_type in ATEN_EXTRA_MESSAGE_SKIP:
                skip_n = ATEN_EXTRA_MESSAGE_SKIP[msg_type]
                log.info(
                    "ATEN extra message type %d; skipping %d bytes", msg_type, skip_n
                )
                await transport.read_exact(skip_n)
                continue

            if msg_type == 0:
                # FramebufferUpdate
                padding = await transport.read_exact(1)
                num_rects_raw = await transport.read_exact(2)
                (num_rects,) = struct.unpack(">H", num_rects_raw)
                log.info("FramebufferUpdate: %d rectangle(s)", num_rects)

                if num_rects > 0:
                    rect_raw = await transport.read_exact(12)
                    first_rect = parse_rectangle_header(rect_raw)
                    outcome["first_rect"] = first_rect
                    log.info(
                        "First rect: x=%d y=%d w=%d h=%d encoding=0x%x (effective=0x%x)",
                        first_rect["x"],
                        first_rect["y"],
                        first_rect["width"],
                        first_rect["height"],
                        first_rect["raw_encoding"],
                        first_rect["effective_encoding"],
                    )

                    # Read up to 65536 payload sample bytes
                    sample_size = min(65536, 4096)
                    try:
                        payload_sample = await asyncio.wait_for(
                            transport.read_exact(sample_size), timeout=READ_TIMEOUT_SEC
                        )
                        log.info(
                            "Payload sample: %d bytes captured", len(payload_sample)
                        )
                        log.debug(
                            "Payload sample (first 64 bytes):\n%s",
                            hexdump_bytes(payload_sample[:64], "payload"),
                        )
                    except asyncio.TimeoutError:
                        log.info("Payload sample read timed out (partial data OK)")
                    break
                else:
                    log.info("FramebufferUpdate with 0 rects; continuing")
                    continue
            else:
                log.warning("Unknown message type 0x%02x; stopping variant", msg_type)
                break

        if first_rect is not None:
            outcome["success"] = True
            log.info("Variant %s: SUCCESS (rect captured)", variant_name)
        else:
            log.warning("Variant %s: no rectangle captured", variant_name)

    except Exception as exc:
        log.error("Variant %s failed: %s", variant_name, exc, exc_info=True)
        outcome["error"] = str(exc)
    finally:
        capture_fh.close()
        if transport is not None:
            try:
                await transport.close()
            except Exception:
                pass
        log.info(
            "Capture written: %s (%d bytes)", capture_path, capture_path.stat().st_size
        )

    return outcome


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


async def _main() -> None:
    """Async entry point: load credentials, run probe variants, print summary."""
    _configure_logging(debug=False)

    cred_path = Path("secret")
    host, username, password = load_credentials(cred_path)
    log.info("Loaded credentials for host %s", host)

    # Web login to obtain SID (authenticates the downstream WebSocket).
    sid = login_web_ui(host, username, password)

    # Fetch the per-launch iKVM session token from the Redfish-generated console
    # page. This board's served noVNC sets username = password = entry_value
    # (the token) and routes security type 16 to _negotiate_insyde_auth, which
    # sends username[24] NUL-padded + 24 zero bytes (the password is NOT sent).
    token = fetch_ikvm_token(host, username, password)

    from spike.aten_protocol import build_credential_block

    # InsydeVNC layout: session token in the 24-byte username field, 24 zeros.
    cred_token = build_credential_block(token, "")
    # Control: legacy ATEN username/password layout (expected to fail).
    cred_user_pass = build_credential_block(username, password)

    variants = [
        {
            "name": "ws_insyde_token",
            "transport": "ws",
            "cred": cred_token,
            "echo": None,
            "desc": "WS(SID) + verbatim echo + InsydeVNC token[24]+zero[24]",
        },
        {
            "name": "ws_user_pass_control",
            "transport": "ws",
            "cred": cred_user_pass,
            "echo": None,
            "desc": "WS + verbatim echo + username/password (control, expected fail)",
        },
    ]

    results: list[dict] = []
    attempts = 0

    for variant in variants:
        if attempts >= MAX_AUTH_ATTEMPTS:
            log.warning("Hard cap of %d auth attempts reached; stopping", MAX_AUTH_ATTEMPTS)
            break

        log.info("Starting variant: %s — %s", variant["name"], variant["desc"])
        attempts += 1

        outcome = await run_probe_variant(
            variant_name=variant["name"],
            host=host,
            transport_kind=variant["transport"],
            credential_block=variant["cred"],
            sid=sid,
            username=username,
            password=password,
            version_echo=variant.get("echo"),
        )
        results.append(outcome)

        if outcome["success"]:
            log.info(
                "First successful variant with rect: %s — stopping early",
                variant["name"],
            )
            break

        if variant is not variants[-1]:
            log.info("Sleeping 2 seconds before next variant")
            await asyncio.sleep(2)

    # Summary table
    log.info("=" * 60)
    log.info("PROBE SUMMARY")
    log.info("=" * 60)
    for r in results:
        sr = r.get("security_result", -1)
        rect = r.get("first_rect")
        enc = hex(rect["effective_encoding"]) if rect else "none"
        status = "SUCCESS" if r["success"] else ("AUTH_OK/NO_RECT" if sr == 0 else "AUTH_FAIL")
        err = r.get("error") or ""
        log.info(
            "%-25s transport=%-10s result=%s sr=%d enc=%s err=%s",
            r["variant_name"],
            r["transport"],
            status,
            sr,
            enc,
            err[:80] if err else "-",
        )


def main() -> None:
    """Synchronous entry point."""
    asyncio.run(_main())


if __name__ == "__main__":
    main()
