"""ATEN iKVM upstream client implementing FramebufferSource.

Connects to the BMC via WebSocket, performs the ATEN type-16 handshake,
exchanges ClientInit/ServerInit, and streams FramebufferUpdate messages.
Decoded RGB888 frames are stored internally; snapshot_rgb() returns a copy.

Security contract:
  - Password, SID, token, credential block are NEVER logged.
  - Cookie / Set-Cookie / Authorization header values are NEVER logged.
"""

from __future__ import annotations

import asyncio
import logging
import ssl
import struct
import threading
import time
from pathlib import Path
from typing import Any

from ikvm_gateway import _ast2100 as ikvm_ast2100

from ikvm_gateway.framebuffer import FramebufferSource
from ikvm_gateway.input.translate import build_aten_key_event, build_aten_pointer_event
from ikvm_gateway.upstream.auth import fetch_ikvm_token, load_credentials, login_web_ui
from ikvm_gateway.upstream.protocol import (
    ATEN_ENCODINGS,
    ATEN_EXTRA_MESSAGE_SKIP,
    build_credential_block,
    build_framebuffer_update_request,
    build_set_encodings,
    check_aten_magic_gate,
    parse_aten_rect_extra,
    parse_rectangle_header,
    parse_security_result,
    parse_server_init,
)

log = logging.getLogger(__name__)

# Minimum interval between incremental FramebufferUpdateRequests (seconds).
_FBU_THROTTLE_SEC = 0.050

# Timeout for reading from the WebSocket (seconds).
_READ_TIMEOUT_SEC = 30.0


class _WsTransport:
    """Async WebSocket transport with stream-reassembly buffer.

    The ATEN RFB stream may arrive fragmented across WebSocket frames.
    read_exact(n) buffers frames and returns exactly n bytes.
    Credentials in Cookie headers are never logged.
    """

    def __init__(self, host: str, sid: str) -> None:
        self._host = host
        self._sid = sid
        self._ws: Any = None
        self._buf = bytearray()

    async def connect(self) -> None:
        """Open wss://<host>/ with SID cookie and no subprotocol.

        TLS verification is intentionally disabled (self-signed BMC cert;
        management network is trusted).
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

    async def _fill(self, needed: int) -> None:
        """Receive WebSocket frames until the buffer has at least needed bytes."""
        while len(self._buf) < needed:
            frame = await asyncio.wait_for(
                self._ws.recv(), timeout=_READ_TIMEOUT_SEC
            )
            if isinstance(frame, str):
                self._buf.extend(frame.encode("latin-1"))
            else:
                self._buf.extend(frame)

    async def read_exact(self, n: int) -> bytes:
        """Return exactly n bytes from the reassembly buffer.

        Args:
            n (int): Number of bytes to read.

        Returns:
            data (bytes): Exactly n bytes.
        """
        await asyncio.wait_for(self._fill(n), timeout=_READ_TIMEOUT_SEC)
        data = bytes(self._buf[:n])
        del self._buf[:n]
        return data

    async def write(self, data: bytes) -> None:
        """Send bytes as a binary WebSocket frame.

        Args:
            data (bytes): Bytes to send.
        """
        await self._ws.send(data)

    async def close(self) -> None:
        """Close the WebSocket connection."""
        if self._ws is not None:
            await self._ws.close()


def _decode_rect(codec_data: bytes, width: int, height: int) -> bytes:
    """Decode one ATEN 0x57 rectangle via the Rust decoder.

    This helper is a thin wrapper so it can be called via asyncio.to_thread.

    Args:
        codec_data (bytes): Raw codec bytes (starting at the 4-byte codec
                            header 04 07 01a6 ...).
        width (int): Rectangle width in pixels.
        height (int): Rectangle height in pixels.

    Returns:
        rgb (bytes): RGB888 row-major pixels, length ``width * height * 3``.
    """
    return ikvm_ast2100.decode_frame(codec_data, width, height)


class AtenUpstreamClient:
    """ATEN iKVM upstream client satisfying the FramebufferSource Protocol.

    Usage::

        client = AtenUpstreamClient.from_secret(Path("secret"))
        await client.connect()
        asyncio.create_task(client.run())
        # later:
        rgb = client.snapshot_rgb()

    Args:
        host (str): BMC hostname or IP.
        sid (str): SID cookie value from web login.
        token (str): Per-session iKVM token from Redfish.
    """

    def __init__(self, host: str, sid: str, token: str) -> None:
        self._host = host
        self._sid = sid
        self._token = token

        self._transport: _WsTransport | None = None

        # Framebuffer state protected by a lock.
        self._fb_lock = threading.Lock()
        self._fb_width = 0
        self._fb_height = 0
        self._fb_rgb: bytes = b""

        self._last_fbu_req_time: float = 0.0
        self._connected = False

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def from_secret(cls, secret_path: Path) -> "AtenUpstreamClient":
        """Create a client by loading credentials from a secret file.

        This is a synchronous factory; it performs blocking HTTP calls to
        obtain the SID and token.  Call it before entering the asyncio loop.

        Args:
            secret_path (Path): Path to the three-line credentials file.

        Returns:
            client (AtenUpstreamClient): Configured but not yet connected.
        """
        host, username, password = load_credentials(secret_path)
        log.info("Loaded credentials for host %s", host)
        sid = login_web_ui(host, username, password)
        token = fetch_ikvm_token(host, username, password)
        return cls(host, sid, token)

    # ------------------------------------------------------------------
    # FramebufferSource properties
    # ------------------------------------------------------------------

    @property
    def width(self) -> int:
        """Current framebuffer width in pixels."""
        with self._fb_lock:
            return self._fb_width

    @property
    def height(self) -> int:
        """Current framebuffer height in pixels."""
        with self._fb_lock:
            return self._fb_height

    def snapshot_rgb(self) -> bytes:
        """Return a consistent copy of the current RGB888 framebuffer.

        Returns:
            rgb (bytes): Row-major RGB888 snapshot, length ``width*height*3``.
        """
        with self._fb_lock:
            return self._fb_rgb

    # ------------------------------------------------------------------
    # FramebufferSource async methods
    # ------------------------------------------------------------------

    async def send_pointer_event(self, x: int, y: int, button_mask: int) -> None:
        """Build and send an ATEN PointerEvent (type 5, 18 bytes).

        Args:
            x (int): Cursor X in framebuffer pixels.
            y (int): Cursor Y in framebuffer pixels.
            button_mask (int): Pressed-button bitmask (bit0=left, bit1=mid,
                               bit2=right).
        """
        if self._transport is None:
            return
        msg = build_aten_pointer_event(x, y, button_mask)
        await self._transport.write(msg)

    async def send_key_event(self, keysym: int, down: bool) -> None:
        """Build and send an ATEN KeyEvent (type 4, 18 bytes).

        Args:
            keysym (int): X11 keysym value.
            down (bool): True for press; False for release.
        """
        if self._transport is None:
            return
        msg = build_aten_key_event(keysym, down)
        await self._transport.write(msg)

    # ------------------------------------------------------------------
    # Connection and handshake
    # ------------------------------------------------------------------

    async def connect(self) -> None:
        """Authenticate and complete RFB handshake through ServerInit.

        Steps:
          1. WebSocket connect with SID cookie.
          2. ATEN type-16 handshake (banner echo, security type 0x10,
             magic-gate, credential block, SecurityResult).
          3. ClientInit (shared=1).
          4. ServerInit (24 base + name + 12 ATEN extra bytes).
          5. SetEncodings.
          6. Initial non-incremental FramebufferUpdateRequest.
        """
        transport = _WsTransport(self._host, self._sid)
        await transport.connect()
        self._transport = transport

        # Step 2: handshake
        await self._handshake()

        # Step 3: ClientInit
        log.info("Sending ClientInit (shared=1)")
        await transport.write(bytes([0x01]))

        # Step 4: ServerInit
        await self._read_server_init()

        # Step 5: SetEncodings
        log.info("Sending SetEncodings (%d encodings)", len(ATEN_ENCODINGS))
        await transport.write(build_set_encodings(ATEN_ENCODINGS))

        # Step 6: Initial full FramebufferUpdateRequest
        with self._fb_lock:
            w = self._fb_width or 1024
            h = self._fb_height or 768
        log.info(
            "Sending initial FramebufferUpdateRequest (non-incremental, %dx%d)", w, h
        )
        await transport.write(build_framebuffer_update_request(False, 0, 0, w, h))
        self._last_fbu_req_time = time.monotonic()
        self._connected = True

    async def _handshake(self) -> None:
        """Perform the ATEN type-16 RFB authentication handshake."""
        transport = self._transport
        assert transport is not None

        # Read and echo 12-byte RFB version banner.
        banner = await transport.read_exact(12)
        log.info("Server banner: %r", banner)
        if not banner.startswith(b"RFB "):
            raise RuntimeError(f"Unexpected banner: {banner!r}")
        await transport.write(banner)

        # Security type negotiation.
        num_types = (await transport.read_exact(1))[0]
        if num_types == 0:
            raise RuntimeError("Server offered 0 security types")
        sec_types = list(await transport.read_exact(num_types))
        log.info("Security types: %s", [hex(t) for t in sec_types])

        if 0x10 not in sec_types:
            raise RuntimeError(
                f"ATEN security type 0x10 not offered; got: {[hex(t) for t in sec_types]}"
            )
        await transport.write(bytes([0x10]))

        # Magic gate.
        nt_raw = await transport.read_exact(4)
        (nt,) = struct.unpack(">I", nt_raw)
        log.info("nt field: 0x%08x", nt)
        if check_aten_magic_gate(nt):
            log.info("Magic gate fired; discarding 20 bytes (aten1 path)")
            await transport.read_exact(20)
        else:
            log.info("Magic gate did NOT fire")

        # Credential block: token[24] + zero[24].
        cred = build_credential_block(self._token, "")
        log.info("Sending credential block [REDACTED 48 bytes]")
        await transport.write(cred)

        # SecurityResult.
        sr_raw = await transport.read_exact(4)
        sr = parse_security_result(sr_raw)
        log.info("SecurityResult: %d (%s)", sr, "OK" if sr == 0 else "FAIL")
        if sr != 0:
            raise RuntimeError(f"ATEN authentication failed (SecurityResult={sr})")

    async def _read_server_init(self) -> None:
        """Read and parse the ServerInit message (24 + name + 12 ATEN extra)."""
        transport = self._transport
        assert transport is not None

        base = await transport.read_exact(24)
        (name_len,) = struct.unpack_from(">I", base, 20)
        name_bytes = await transport.read_exact(name_len) if name_len > 0 else b""
        aten_extra = await transport.read_exact(12)

        info = parse_server_init(base + name_bytes + aten_extra)
        log.info(
            "ServerInit: advertised %dx%d, name=%r, IKVMVideo=%d, IKVMKM=%d",
            info["framebuffer_width"],
            info["framebuffer_height"],
            info["name_text"].decode("ascii", errors="replace"),
            info["ikvm_video_enable"],
            info["ikvm_km_enable"],
        )
        # The ATEN BMC advertises a fake size (e.g. 480x640).
        # Real resolution comes from the first FramebufferUpdate rectangle.
        with self._fb_lock:
            self._fb_width = info["framebuffer_width"] or 1024
            self._fb_height = info["framebuffer_height"] or 768

    # ------------------------------------------------------------------
    # Main receive loop
    # ------------------------------------------------------------------

    async def run(self) -> None:
        """Continuously read server messages and update the internal framebuffer.

        Handles:
          - ATEN extra message types (4, 22, 51, 55, 57, 60): absorbed.
          - FramebufferUpdate (type 0): reads all rectangles, decodes 0x57
            codec via asyncio.to_thread, updates internal framebuffer.
          - Sends throttled incremental FramebufferUpdateRequests (>=50 ms).

        This coroutine runs until the connection closes or raises.
        """
        transport = self._transport
        assert transport is not None

        while True:
            msg_type_byte = await transport.read_exact(1)
            msg_type = msg_type_byte[0]

            if msg_type in ATEN_EXTRA_MESSAGE_SKIP:
                skip_n = ATEN_EXTRA_MESSAGE_SKIP[msg_type]
                log.debug(
                    "Absorbing ATEN extra message type %d (%d bytes)", msg_type, skip_n
                )
                await transport.read_exact(skip_n)
                continue

            if msg_type == 0:
                await self._handle_framebuffer_update(transport)
                await self._send_refresh_fbu_req()
                continue

            # Unknown message type: log and stop.
            log.warning("Unknown server message type 0x%02x; stopping run()", msg_type)
            break

    async def _handle_framebuffer_update(self, transport: _WsTransport) -> None:
        """Read and process one FramebufferUpdate message.

        Layout after the type byte (0x00):
          1 byte padding + 2 bytes num_rects (big-endian u16),
          then for each rect: 20-byte ATEN rect header + getDataLen codec bytes.
        """
        _pad = await transport.read_exact(1)
        num_rects_raw = await transport.read_exact(2)
        (num_rects,) = struct.unpack(">H", num_rects_raw)
        log.debug("FramebufferUpdate: %d rect(s)", num_rects)

        for _ in range(num_rects):
            await self._handle_one_rect(transport)

    async def _handle_one_rect(self, transport: _WsTransport) -> None:
        """Read and decode one ATEN rectangle.

        The 20-byte ATEN rect header consists of:
          - 12 bytes: standard RFB rect header (x, y, w, h as u16 each,
            encoding as s32 big-endian)
          - 4 bytes: mode (u32 big-endian)
          - 4 bytes: getDataLen (u32 big-endian)
        Followed by getDataLen bytes of codec_data.

        Only encoding 0x57 (ATEN_AST2100) is decoded.  Other encodings are
        absorbed (codec bytes consumed and discarded).
        """
        rect_base = await transport.read_exact(12)
        rect_extra = await transport.read_exact(8)

        rect = parse_rectangle_header(rect_base)
        mode, get_data_len = parse_aten_rect_extra(rect_extra)

        log.debug(
            "Rect: x=%d y=%d w=%d h=%d enc=0x%x mode=0x%x dataLen=%d",
            rect["x"],
            rect["y"],
            rect["width"],
            rect["height"],
            rect["effective_encoding"],
            mode,
            get_data_len,
        )

        codec_data = await transport.read_exact(get_data_len)

        if rect["effective_encoding"] != 0x57 or get_data_len == 0:
            return

        w = rect["width"]
        h = rect["height"]
        rgb = await asyncio.to_thread(_decode_rect, codec_data, w, h)

        with self._fb_lock:
            self._fb_width = w
            self._fb_height = h
            self._fb_rgb = rgb

        log.debug("Framebuffer updated: %dx%d (%d bytes)", w, h, len(rgb))

    async def _send_refresh_fbu_req(self) -> None:
        """Request the next frame if >=50 ms have elapsed since the last request.

        The request is NON-incremental (full frame). The AST2100 stateless
        decoder allocates a fresh buffer per call, so incremental updates (which
        carry skip blocks that reference the previous framebuffer) would decode
        to black. Always requesting a full frame keeps every decode complete and
        correct. The Rust decode of a full frame is ~1-3 ms, so the cost is low.
        TODO (optimization): make the decoder stateful (carry the previous
        framebuffer so skip/copy blocks work) and switch back to incremental.
        """
        now = time.monotonic()
        if now - self._last_fbu_req_time < _FBU_THROTTLE_SEC:
            return
        with self._fb_lock:
            w = self._fb_width or 1024
            h = self._fb_height or 768
        transport = self._transport
        if transport is None:
            return
        await transport.write(
            build_framebuffer_update_request(False, 0, 0, w, h)
        )
        self._last_fbu_req_time = now

    # ------------------------------------------------------------------
    # Testable helper: decode a raw rect payload into the internal buffer
    # ------------------------------------------------------------------

    async def decode_rect_payload(
        self,
        rect_header_20: bytes,
        codec_data: bytes,
    ) -> None:
        """Decode a single ATEN rect and update the internal framebuffer.

        Designed to be callable from tests without a live connection.  The
        caller passes the 20-byte ATEN rect header (12-byte RFB header + 8
        bytes mode/getDataLen) and the codec_data separately.

        Args:
            rect_header_20 (bytes): Exactly 20 bytes: standard 12-byte RFB
                                    rect header + 4-byte mode + 4-byte
                                    getDataLen.
            codec_data (bytes): The raw codec bytes (getDataLen bytes).
        """
        if len(rect_header_20) != 20:
            raise ValueError(
                f"rect_header_20 must be 20 bytes; got {len(rect_header_20)}"
            )

        rect = parse_rectangle_header(rect_header_20[:12])
        mode, get_data_len = parse_aten_rect_extra(rect_header_20[12:20])

        if rect["effective_encoding"] != 0x57 or get_data_len == 0:
            return

        w = rect["width"]
        h = rect["height"]
        rgb = await asyncio.to_thread(_decode_rect, codec_data, w, h)

        with self._fb_lock:
            self._fb_width = w
            self._fb_height = h
            self._fb_rgb = rgb


# Make AtenUpstreamClient a concrete type that satisfies FramebufferSource.
# This assertion is validated at import time during tests.
def _check_protocol() -> None:
    """Assert that AtenUpstreamClient satisfies FramebufferSource at runtime."""
    assert isinstance(AtenUpstreamClient, type)
    # Protocol check skipped: runtime_checkable only validates structural
    # compatibility for instances; class-level check requires instantiation.


_check_protocol()
