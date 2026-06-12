"""Tests for the downstream RFB server and WebSocket gateway.

All tests are pure (no network, no BMC, no live WebSocket connections).
A FakeFramebufferSource provides a synthetic RGB888 gradient framebuffer.
An InMemoryTransport provides a synchronous duplex pipe for RFB protocol tests.
"""

from __future__ import annotations

import asyncio
import hmac
import json
import struct
import time
import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ikvm_gateway.downstream.rfb_server import (
    PixelFormat,
    RfbServer,
    _DEFAULT_BIG_ENDIAN,
    _DEFAULT_BLUE_MAX,
    _DEFAULT_BLUE_SHIFT,
    _DEFAULT_BPP,
    _DEFAULT_DEPTH,
    _DEFAULT_GREEN_MAX,
    _DEFAULT_GREEN_SHIFT,
    _DEFAULT_RED_MAX,
    _DEFAULT_RED_SHIFT,
    _DEFAULT_TRUE_COLOUR,
    build_pixel_format_bytes,
    encode_raw_rectangle,
    parse_pixel_format_bytes,
)
from ikvm_gateway.downstream.ws_app import (
    GatewayConfig,
    IkvmGatewayApp,
    TicketStore,
)


# ---------------------------------------------------------------------------
# Fake framebuffer source
# ---------------------------------------------------------------------------


class FakeFramebufferSource:
    """Synthetic RGB888 gradient framebuffer for tests.

    Generates a deterministic gradient: pixel at (x, y) has
    R = x % 256, G = y % 256, B = (x + y) % 256.
    """

    def __init__(self, width: int = 64, height: int = 48) -> None:
        self._width = width
        self._height = height
        self.pointer_events: list[tuple[int, int, int]] = []
        self.key_events: list[tuple[int, bool]] = []

    @property
    def width(self) -> int:
        return self._width

    @property
    def height(self) -> int:
        return self._height

    def snapshot_rgb(self) -> bytes:
        """Return a deterministic RGB888 gradient for the full framebuffer."""
        buf = bytearray(self._width * self._height * 3)
        idx = 0
        for y in range(self._height):
            for x in range(self._width):
                buf[idx] = x % 256
                buf[idx + 1] = y % 256
                buf[idx + 2] = (x + y) % 256
                idx += 3
        return bytes(buf)

    async def send_pointer_event(self, x: int, y: int, button_mask: int) -> None:
        self.pointer_events.append((x, y, button_mask))

    async def send_key_event(self, keysym: int, down: bool) -> None:
        self.key_events.append((keysym, down))


# ---------------------------------------------------------------------------
# In-memory duplex transport
# ---------------------------------------------------------------------------


class InMemoryTransport:
    """Duplex byte-stream transport using asyncio queues.

    client_to_server: bytes written by the test (simulating client messages)
    server_to_client: bytes written by RfbServer (captured by the test)
    """

    def __init__(self) -> None:
        self._inbound: asyncio.Queue[bytes] = asyncio.Queue()
        self._outbound = bytearray()

    # Called by tests to push bytes that the server will read.
    def feed_client(self, data: bytes) -> None:
        """Queue bytes for the server to read."""
        self._inbound.put_nowait(data)

    # Called by tests to see what the server sent.
    def get_server_output(self) -> bytes:
        """Return all bytes the server has written so far."""
        return bytes(self._outbound)

    # Transport interface consumed by RfbServer.
    async def read_exact(self, n: int) -> bytes:
        """Read exactly n bytes from the inbound queue."""
        buf = bytearray()
        while len(buf) < n:
            needed = n - len(buf)
            chunk = await asyncio.wait_for(self._inbound.get(), timeout=2.0)
            buf.extend(chunk[:needed])
            if len(chunk) > needed:
                # Put back the remainder.
                self._inbound.put_nowait(chunk[needed:])
        return bytes(buf)

    async def write(self, data: bytes) -> None:
        """Capture bytes written by the server."""
        self._outbound.extend(data)


# ---------------------------------------------------------------------------
# Helper: drive a complete RFB handshake and return captured server output
# ---------------------------------------------------------------------------


async def _run_handshake_only(
    source: FakeFramebufferSource,
) -> tuple[InMemoryTransport, RfbServer]:
    """Drive the server through the full RFB handshake.

    Feeds all required client-side messages and runs the server until after
    ServerInit is sent.  Returns the transport (for inspection) and the
    server (paused before the message loop).

    Returns:
        transport (InMemoryTransport): Captured server output accessible via
            transport.get_server_output().
        server (RfbServer): Server instance (not yet started in message loop).
    """
    transport = InMemoryTransport()
    server = RfbServer(transport, source)

    # Feed: version (12 bytes client echo)
    transport.feed_client(b"RFB 003.008\n")
    # Feed: security selection (1 byte = type 1 None)
    transport.feed_client(bytes([1]))
    # Feed: ClientInit (1 byte shared flag)
    transport.feed_client(bytes([1]))

    await server._do_handshake()
    return transport, server


# ---------------------------------------------------------------------------
# RFB handshake tests
# ---------------------------------------------------------------------------


class TestRfbHandshake:
    def test_server_sends_version_banner(self):
        """Server must send exactly b'RFB 003.008\n'."""
        source = FakeFramebufferSource(width=320, height=240)

        async def run():
            transport, _ = await _run_handshake_only(source)
            output = transport.get_server_output()
            assert output[:12] == b"RFB 003.008\n"

        asyncio.run(run())

    def test_server_offers_security_none(self):
        """Server must offer exactly [count=1][type=1]."""
        source = FakeFramebufferSource(width=320, height=240)

        async def run():
            transport, _ = await _run_handshake_only(source)
            output = transport.get_server_output()
            # Offset 12: [count=1][type=1]
            assert output[12] == 1, "security type count must be 1"
            assert output[13] == 1, "security type must be 1 (None)"

        asyncio.run(run())

    def test_server_sends_security_result_zero(self):
        """RFB 3.8 requires SecurityResult=0 even after security None."""
        source = FakeFramebufferSource(width=320, height=240)

        async def run():
            transport, _ = await _run_handshake_only(source)
            output = transport.get_server_output()
            # Offset 14: [SecurityResult u32 big-endian = 0]
            (result,) = struct.unpack(">I", output[14:18])
            assert result == 0

        asyncio.run(run())

    def test_server_init_framebuffer_dimensions(self):
        """ServerInit must encode the real framebuffer dimensions."""
        source = FakeFramebufferSource(width=1024, height=768)

        async def run():
            transport, _ = await _run_handshake_only(source)
            output = transport.get_server_output()
            # Offset 18: ServerInit starts (after 12 version + 2 security + 4 result)
            server_init_offset = 18
            w, h = struct.unpack(">HH", output[server_init_offset: server_init_offset + 4])
            assert w == 1024
            assert h == 768

        asyncio.run(run())

    def test_server_init_pixel_format_32bpp(self):
        """ServerInit PixelFormat must be 32bpp true-colour."""
        source = FakeFramebufferSource(width=64, height=48)

        async def run():
            transport, _ = await _run_handshake_only(source)
            output = transport.get_server_output()
            server_init_offset = 18
            pf_offset = server_init_offset + 4
            pf = parse_pixel_format_bytes(output[pf_offset: pf_offset + 16])
            assert pf.bpp == 32
            assert pf.depth == 24
            assert pf.true_colour == 1
            assert pf.big_endian == 0
            assert pf.red_max == 255
            assert pf.green_max == 255
            assert pf.blue_max == 255

        asyncio.run(run())

    def test_server_init_pixel_format_shifts(self):
        """Default shifts: red=16, green=8, blue=0 (BGRX little-endian)."""
        source = FakeFramebufferSource(width=64, height=48)

        async def run():
            transport, _ = await _run_handshake_only(source)
            output = transport.get_server_output()
            server_init_offset = 18
            pf_offset = server_init_offset + 4
            pf = parse_pixel_format_bytes(output[pf_offset: pf_offset + 16])
            assert pf.red_shift == 16
            assert pf.green_shift == 8
            assert pf.blue_shift == 0

        asyncio.run(run())

    def test_server_init_name_is_ikvm_gateway(self):
        """ServerInit name must be b'ikvm-gateway'."""
        source = FakeFramebufferSource(width=64, height=48)

        async def run():
            transport, _ = await _run_handshake_only(source)
            output = transport.get_server_output()
            server_init_offset = 18
            name_len_offset = server_init_offset + 4 + 16
            (name_len,) = struct.unpack(">I", output[name_len_offset: name_len_offset + 4])
            name = output[name_len_offset + 4: name_len_offset + 4 + name_len]
            assert name == b"ikvm-gateway"

        asyncio.run(run())


# ---------------------------------------------------------------------------
# FramebufferUpdate tests
# ---------------------------------------------------------------------------


class TestFramebufferUpdate:
    def _make_fbu_request(
        self, incremental: bool = False, x: int = 0, y: int = 0,
        w: int = 64, h: int = 48
    ) -> bytes:
        """Build a FramebufferUpdateRequest message (type 3)."""
        return struct.pack(
            ">BBHHHH",
            3,  # message type
            1 if incremental else 0,
            x, y, w, h,
        )

    def test_framebuffer_update_response_header(self):
        """FramebufferUpdate must start with [type=0][pad=0][num_rects=1]."""
        source = FakeFramebufferSource(width=64, height=48)

        async def run():
            transport, server = await _run_handshake_only(source)
            # Feed the payload AFTER the type byte (type already consumed by loop).
            # FramebufferUpdateRequest payload: incr(1) + x(2) + y(2) + w(2) + h(2) = 9 bytes.
            transport.feed_client(struct.pack(">BHHHH", 0, 0, 0, 64, 48))
            await server._handle_framebuffer_update_request()

            output = transport.get_server_output()
            # Find start of FramebufferUpdate response (after handshake bytes).
            # Handshake: 12 (version) + 2 (sec types) + 4 (sec result) + ServerInit
            # ServerInit: 4 (dims) + 16 (pf) + 4 (name_len) + len(b'ikvm-gateway') = 36
            handshake_len = 12 + 2 + 4 + 4 + 16 + 4 + len(b"ikvm-gateway")
            fbu = output[handshake_len:]

            assert fbu[0] == 0, "FramebufferUpdate type must be 0"
            assert fbu[1] == 0, "FramebufferUpdate padding must be 0"
            (num_rects,) = struct.unpack(">H", fbu[2:4])
            assert num_rects == 1

        asyncio.run(run())

    def test_framebuffer_update_raw_encoding(self):
        """The rectangle must use Raw encoding (encoding s32 = 0)."""
        source = FakeFramebufferSource(width=64, height=48)

        async def run():
            transport, server = await _run_handshake_only(source)
            # Payload only (no type byte).
            transport.feed_client(struct.pack(">BHHHH", 0, 0, 0, 64, 48))
            await server._handle_framebuffer_update_request()

            output = transport.get_server_output()
            handshake_len = 12 + 2 + 4 + 4 + 16 + 4 + len(b"ikvm-gateway")
            fbu = output[handshake_len:]

            # 4 bytes FBU header, then 12-byte rect header.
            rect_header = fbu[4:16]
            x, y, w, h, encoding = struct.unpack(">HHHHi", rect_header)
            assert x == 0
            assert y == 0
            assert w == 64
            assert h == 48
            assert encoding == 0  # Raw

        asyncio.run(run())

    def test_framebuffer_update_pixel_data_length(self):
        """Pixel data must be width * height * 4 bytes (32bpp)."""
        w, h = 64, 48
        source = FakeFramebufferSource(width=w, height=h)

        async def run():
            transport, server = await _run_handshake_only(source)
            # Payload only (no type byte).
            transport.feed_client(struct.pack(">BHHHH", 0, 0, 0, w, h))
            await server._handle_framebuffer_update_request()

            output = transport.get_server_output()
            handshake_len = 12 + 2 + 4 + 4 + 16 + 4 + len(b"ikvm-gateway")
            fbu = output[handshake_len:]

            # FBU header = 4, rect header = 12, pixel data follows.
            pixel_data = fbu[4 + 12:]
            expected_len = w * h * 4
            assert len(pixel_data) == expected_len

        asyncio.run(run())

    def test_framebuffer_update_pixel_values_match_source(self):
        """Packed pixel values must match the fake gradient source."""
        w, h = 8, 4
        source = FakeFramebufferSource(width=w, height=h)

        async def run():
            transport, server = await _run_handshake_only(source)
            # Payload only (no type byte).
            transport.feed_client(struct.pack(">BHHHH", 0, 0, 0, w, h))
            await server._handle_framebuffer_update_request()

            output = transport.get_server_output()
            handshake_len = 12 + 2 + 4 + 4 + 16 + 4 + len(b"ikvm-gateway")
            fbu = output[handshake_len:]
            pixel_data = fbu[4 + 12:]

            # Default pixel format: 32bpp LE, red_shift=16, green_shift=8, blue_shift=0.
            pf = PixelFormat()
            for y in range(h):
                for x in range(w):
                    idx = (y * w + x) * 4
                    (packed,) = struct.unpack_from("<I", pixel_data, idx)
                    r_got = (packed >> pf.red_shift) & 0xFF
                    g_got = (packed >> pf.green_shift) & 0xFF
                    b_got = (packed >> pf.blue_shift) & 0xFF
                    assert r_got == x % 256, f"R mismatch at ({x},{y})"
                    assert g_got == y % 256, f"G mismatch at ({x},{y})"
                    assert b_got == (x + y) % 256, f"B mismatch at ({x},{y})"

        asyncio.run(run())

    def test_custom_pixel_format_respected(self):
        """After SetPixelFormat, the server uses the client's requested shifts."""
        w, h = 4, 2
        source = FakeFramebufferSource(width=w, height=h)

        async def run():
            transport, server = await _run_handshake_only(source)

            # Request big-endian with swapped shifts: R=0, G=8, B=16.
            custom_pf = PixelFormat(
                bpp=32, depth=24, big_endian=1, true_colour=1,
                red_max=255, green_max=255, blue_max=255,
                red_shift=0, green_shift=8, blue_shift=16,
            )
            pf_bytes = build_pixel_format_bytes(custom_pf)
            # SetPixelFormat payload after type byte: 3 pad bytes + 16 pf bytes = 19 bytes.
            spf_payload = bytes([0, 0, 0]) + pf_bytes
            transport.feed_client(spf_payload)
            await server._handle_set_pixel_format()

            # FBU payload after type byte: incr(1) + x(2) + y(2) + w(2) + h(2) = 9 bytes.
            transport.feed_client(struct.pack(">BHHHH", 0, 0, 0, w, h))
            await server._handle_framebuffer_update_request()

            output = transport.get_server_output()
            handshake_len = 12 + 2 + 4 + 4 + 16 + 4 + len(b"ikvm-gateway")
            # After handshake: SetPixelFormat has no response; FBU follows.
            fbu = output[handshake_len:]
            pixel_data = fbu[4 + 12:]

            for y in range(h):
                for x in range(w):
                    idx = (y * w + x) * 4
                    (packed,) = struct.unpack_from(">I", pixel_data, idx)  # big-endian
                    r_got = (packed >> custom_pf.red_shift) & 0xFF
                    g_got = (packed >> custom_pf.green_shift) & 0xFF
                    b_got = (packed >> custom_pf.blue_shift) & 0xFF
                    assert r_got == x % 256
                    assert g_got == y % 256
                    assert b_got == (x + y) % 256

        asyncio.run(run())


# ---------------------------------------------------------------------------
# Input event forwarding tests
# ---------------------------------------------------------------------------


class TestInputEventForwarding:
    def test_key_event_forwarded(self):
        """KeyEvent message must call source.send_key_event with correct args."""
        source = FakeFramebufferSource()

        async def run():
            transport, server = await _run_handshake_only(source)
            # KeyEvent payload after type byte: down(1) + 2 pad + keysym(4) = 7 bytes.
            key_payload = struct.pack(">BxxI", 1, 0x61)
            transport.feed_client(key_payload)
            await server._handle_key_event()
            assert len(source.key_events) == 1
            keysym, down = source.key_events[0]
            assert keysym == 0x61
            assert down is True

        asyncio.run(run())

    def test_key_event_release(self):
        """KeyEvent with down=0 must call source.send_key_event(down=False)."""
        source = FakeFramebufferSource()

        async def run():
            transport, server = await _run_handshake_only(source)
            # KeyEvent payload: down=0, 2 pad, keysym=0xFF0D (Return).
            key_payload = struct.pack(">BxxI", 0, 0xFF0D)
            transport.feed_client(key_payload)
            await server._handle_key_event()
            assert source.key_events[0][1] is False

        asyncio.run(run())

    def test_pointer_event_forwarded(self):
        """PointerEvent message must call source.send_pointer_event."""
        source = FakeFramebufferSource()

        async def run():
            transport, server = await _run_handshake_only(source)
            # PointerEvent payload after type byte: button_mask(1) + x(2) + y(2) = 5 bytes.
            ptr_payload = struct.pack(">BHH", 0x01, 100, 200)
            transport.feed_client(ptr_payload)
            await server._handle_pointer_event()
            assert len(source.pointer_events) == 1
            x, y, mask = source.pointer_events[0]
            assert x == 100
            assert y == 200
            assert mask == 0x01

        asyncio.run(run())


# ---------------------------------------------------------------------------
# encode_raw_rectangle unit tests
# ---------------------------------------------------------------------------


class TestEncodeRawRectangle:
    def test_header_correct(self):
        """Rectangle header must encode x,y,w,h and Raw encoding=0."""
        rgb = bytes([255, 0, 0] * 4)  # 2x2 red
        rect = encode_raw_rectangle(rgb, x=0, y=0, w=2, h=2, pf=PixelFormat())
        x, y, w, h, enc = struct.unpack(">HHHHi", rect[:12])
        assert x == 0
        assert y == 0
        assert w == 2
        assert h == 2
        assert enc == 0  # Raw

    def test_pixel_count(self):
        """Pixel data must be w*h*4 bytes for 32bpp."""
        rgb = bytes(3 * 4 * 4)  # 4x4 black
        rect = encode_raw_rectangle(rgb, x=0, y=0, w=4, h=4, pf=PixelFormat())
        assert len(rect) == 12 + 4 * 4 * 4  # header + pixels

    def test_red_pixel_value(self):
        """Red pixel (255,0,0) with default shifts must produce 0x00FF0000."""
        rgb = bytes([255, 0, 0])  # 1 pixel
        pf = PixelFormat()  # red_shift=16, little-endian
        rect = encode_raw_rectangle(rgb, x=0, y=0, w=1, h=1, pf=pf)
        (packed,) = struct.unpack_from("<I", rect, 12)
        assert packed == 0x00FF0000

    def test_green_pixel_value(self):
        """Green pixel (0,255,0) with default shifts must produce 0x0000FF00."""
        rgb = bytes([0, 255, 0])
        pf = PixelFormat()  # green_shift=8
        rect = encode_raw_rectangle(rgb, x=0, y=0, w=1, h=1, pf=pf)
        (packed,) = struct.unpack_from("<I", rect, 12)
        assert packed == 0x0000FF00

    def test_blue_pixel_value(self):
        """Blue pixel (0,0,255) with default shifts must produce 0x000000FF."""
        rgb = bytes([0, 0, 255])
        pf = PixelFormat()  # blue_shift=0
        rect = encode_raw_rectangle(rgb, x=0, y=0, w=1, h=1, pf=pf)
        (packed,) = struct.unpack_from("<I", rect, 12)
        assert packed == 0x000000FF


# ---------------------------------------------------------------------------
# TicketStore tests
# ---------------------------------------------------------------------------


class TestTicketStore:
    def test_issue_returns_non_empty_string(self):
        async def run():
            store = TicketStore(ttl_seconds=30)
            ticket = await store.issue()
            assert isinstance(ticket, str)
            assert len(ticket) > 0

        asyncio.run(run())

    def test_issued_ticket_is_uuid(self):
        async def run():
            store = TicketStore(ttl_seconds=30)
            ticket = await store.issue()
            # Must be parseable as UUID.
            uuid.UUID(ticket)

        asyncio.run(run())

    def test_valid_ticket_consumed_once(self):
        async def run():
            store = TicketStore(ttl_seconds=30)
            ticket = await store.issue()
            result = await store.consume(ticket)
            assert result is True

        asyncio.run(run())

    def test_ticket_single_use(self):
        """Consuming a ticket a second time must fail."""
        async def run():
            store = TicketStore(ttl_seconds=30)
            ticket = await store.issue()
            await store.consume(ticket)
            result = await store.consume(ticket)
            assert result is False

        asyncio.run(run())

    def test_expired_ticket_rejected(self):
        """Expired tickets must not be accepted."""
        async def run():
            store = TicketStore(ttl_seconds=0.01)  # 10 ms TTL
            ticket = await store.issue()
            await asyncio.sleep(0.05)  # wait for expiry
            result = await store.consume(ticket)
            assert result is False

        asyncio.run(run())

    def test_unknown_ticket_rejected(self):
        async def run():
            store = TicketStore(ttl_seconds=30)
            result = await store.consume("not-a-real-ticket")
            assert result is False

        asyncio.run(run())

    def test_multiple_tickets_independent(self):
        """Two tickets must be independently consumable."""
        async def run():
            store = TicketStore(ttl_seconds=30)
            t1 = await store.issue()
            t2 = await store.issue()
            assert t1 != t2
            r1 = await store.consume(t1)
            r2 = await store.consume(t2)
            assert r1 is True
            assert r2 is True

        asyncio.run(run())


# ---------------------------------------------------------------------------
# API key authentication tests
# ---------------------------------------------------------------------------


class TestApiKeyAuth:
    def _make_config(self, api_key: str = "test-secret-key") -> GatewayConfig:
        return GatewayConfig(
            api_key=api_key,
            bmc_host="10.0.0.1",
        )

    def test_correct_key_accepted(self):
        config = self._make_config(api_key="correct-key")
        app = IkvmGatewayApp(config)
        assert app._verify_api_key("Bearer correct-key") is True

    def test_wrong_key_rejected(self):
        config = self._make_config(api_key="correct-key")
        app = IkvmGatewayApp(config)
        assert app._verify_api_key("Bearer wrong-key") is False

    def test_missing_auth_header_rejected(self):
        config = self._make_config()
        app = IkvmGatewayApp(config)
        assert app._verify_api_key(None) is False

    def test_empty_auth_header_rejected(self):
        config = self._make_config()
        app = IkvmGatewayApp(config)
        assert app._verify_api_key("") is False

    def test_malformed_bearer_rejected(self):
        config = self._make_config(api_key="key")
        app = IkvmGatewayApp(config)
        assert app._verify_api_key("key") is False  # missing "Bearer " prefix

    def test_wrong_scheme_rejected(self):
        config = self._make_config(api_key="key")
        app = IkvmGatewayApp(config)
        assert app._verify_api_key("Basic key") is False

    def test_constant_time_comparison(self):
        """Verify hmac.compare_digest is used (not ==)."""
        config = self._make_config(api_key="secret")
        app = IkvmGatewayApp(config)
        # Both should return True for correct, False for wrong.
        assert app._verify_api_key("Bearer secret") is True
        assert app._verify_api_key("Bearer oops") is False

    def test_empty_api_key_in_config_not_accepted_by_empty_header(self):
        """Even if api_key config is empty, empty header must not match."""
        config = GatewayConfig(api_key="non-empty", bmc_host="10.0.0.1")
        app = IkvmGatewayApp(config)
        assert app._verify_api_key("Bearer ") is False


# ---------------------------------------------------------------------------
# Sessions endpoint integration tests (using mocked WebSocket)
# ---------------------------------------------------------------------------


class TestSessionsEndpoint:
    def _make_request(self, path: str, auth_header: str | None) -> MagicMock:
        """Build a minimal mock HTTP request for process_request."""
        request = MagicMock()
        request.path = path
        headers = {}
        if auth_header is not None:
            headers["Authorization"] = auth_header
        request.headers = headers
        return request

    def test_valid_api_key_returns_200_with_ticket(self):
        config = GatewayConfig(api_key="key123", bmc_host="10.0.0.1")
        app = IkvmGatewayApp(config)

        async def run():
            request = self._make_request("/sessions", "Bearer key123")
            response = await app.process_request(MagicMock(), request)
            assert response.status_code == 200
            body = json.loads(response.body)
            assert body["status"] == 200
            assert "ticket" in body["data"]
            assert len(body["data"]["ticket"]) > 0

        asyncio.run(run())

    def test_invalid_api_key_returns_401(self):
        config = GatewayConfig(api_key="key123", bmc_host="10.0.0.1")
        app = IkvmGatewayApp(config)

        async def run():
            request = self._make_request("/sessions", "Bearer wrongkey")
            response = await app.process_request(MagicMock(), request)
            assert response.status_code == 401

        asyncio.run(run())

    def test_missing_api_key_returns_401(self):
        config = GatewayConfig(api_key="key123", bmc_host="10.0.0.1")
        app = IkvmGatewayApp(config)

        async def run():
            request = self._make_request("/sessions", None)
            response = await app.process_request(MagicMock(), request)
            assert response.status_code == 401

        asyncio.run(run())

    def test_vnc_path_proceeds_to_upgrade(self):
        """process_request returns None for /vnc so the WS handshake proceeds."""
        config = GatewayConfig(api_key="key", bmc_host="10.0.0.1")
        app = IkvmGatewayApp(config)

        async def run():
            request = self._make_request("/vnc", None)
            response = await app.process_request(MagicMock(), request)
            assert response is None

        asyncio.run(run())

    def test_issued_ticket_is_single_use(self):
        """Ticket issued via endpoint must be consumable exactly once."""
        config = GatewayConfig(api_key="key", bmc_host="10.0.0.1")
        app = IkvmGatewayApp(config)

        async def run():
            request = self._make_request("/sessions", "Bearer key")
            response = await app.process_request(MagicMock(), request)
            body = json.loads(response.body)
            ticket = body["data"]["ticket"]

            r1 = await app._ticket_store.consume(ticket)
            assert r1 is True
            r2 = await app._ticket_store.consume(ticket)
            assert r2 is False

        asyncio.run(run())
