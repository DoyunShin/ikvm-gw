"""Isolated downstream check: run the gateway with a synthetic framebuffer
(no BMC needed), then exercise POST /sessions + the /vnc RFB-None handshake +
a Raw FramebufferUpdate, and save the served frame as a PNG.

Validates the downstream HTTP/WS/RFB path independently of the upstream client.

Usage:
    uv run python -m tools.check_downstream
"""

from __future__ import annotations

import asyncio
import json
import struct
import urllib.request

import websockets
from PIL import Image

from ikvm_gateway.downstream.ws_app import GatewayConfig, run_server

WIDTH, HEIGHT = 320, 240
PORT = 5777
API_KEY = "test-key-123"


class FakeSource:
    """Synthetic FramebufferSource: a deterministic colour gradient."""

    def __init__(self) -> None:
        buf = bytearray(WIDTH * HEIGHT * 3)
        for y in range(HEIGHT):
            for x in range(WIDTH):
                i = (y * WIDTH + x) * 3
                buf[i] = x % 256
                buf[i + 1] = y % 256
                buf[i + 2] = (x + y) % 256
        self._rgb = bytes(buf)

    @property
    def width(self) -> int:
        return WIDTH

    @property
    def height(self) -> int:
        return HEIGHT

    def snapshot_rgb(self) -> bytes:
        return self._rgb

    async def send_pointer_event(self, x: int, y: int, button_mask: int) -> None:
        pass

    async def send_key_event(self, keysym: int, down: bool) -> None:
        pass


def _request_ticket() -> str:
    """POST /sessions with the API key and return the issued ticket."""
    req = urllib.request.Request(
        f"http://127.0.0.1:{PORT}/sessions",
        method="GET",
        headers={"Authorization": f"Bearer {API_KEY}"},
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        payload = json.loads(resp.read())
    return payload["data"]["ticket"]


async def _rfb_handshake_and_frame(ticket: str) -> bytes:
    """Connect to /vnc with the ticket subprotocol, do the RFB None handshake,
    request a FramebufferUpdate, and return the decoded RGB888 bytes."""
    async with websockets.connect(
        f"ws://127.0.0.1:{PORT}/vnc", subprotocols=[ticket]
    ) as ws:
        buf = bytearray()

        async def read_exact(n: int) -> bytes:
            while len(buf) < n:
                buf.extend(await asyncio.wait_for(ws.recv(), timeout=5))
            out = bytes(buf[:n])
            del buf[:n]
            return out

        # Version
        server_version = await read_exact(12)
        assert server_version == b"RFB 003.008\n", server_version
        await ws.send(b"RFB 003.008\n")

        # Security
        num = (await read_exact(1))[0]
        types = await read_exact(num)
        assert 1 in types, list(types)  # None
        await ws.send(bytes([1]))
        sec_result = struct.unpack(">I", await read_exact(4))[0]
        assert sec_result == 0, sec_result

        # ClientInit -> ServerInit
        await ws.send(bytes([1]))
        si = await read_exact(24)
        w, h = struct.unpack(">HH", si[:4])
        name_len = struct.unpack(">I", si[20:24])[0]
        await read_exact(name_len)
        assert (w, h) == (WIDTH, HEIGHT), (w, h)

        # FramebufferUpdateRequest (full, non-incremental)
        await ws.send(struct.pack(">BBHHHH", 3, 0, 0, 0, WIDTH, HEIGHT))

        # FramebufferUpdate
        msg_type = (await read_exact(1))[0]
        assert msg_type == 0, msg_type
        await read_exact(1)  # padding
        num_rects = struct.unpack(">H", await read_exact(2))[0]
        assert num_rects >= 1
        x, y, rw, rh, enc = struct.unpack(">HHHHi", await read_exact(12))
        assert enc == 0, enc  # Raw
        raw = await read_exact(rw * rh * 4)  # 32bpp

        # Unpack 32bpp little-endian (shifts r=16,g=8,b=0) to RGB888
        out = bytearray(rw * rh * 3)
        for p in range(rw * rh):
            px = struct.unpack_from("<I", raw, p * 4)[0]
            out[p * 3] = (px >> 16) & 0xFF
            out[p * 3 + 1] = (px >> 8) & 0xFF
            out[p * 3 + 2] = px & 0xFF
        return bytes(out)


async def _main() -> None:
    config = GatewayConfig(api_key=API_KEY, bmc_host="fake", bind_port=PORT)
    source = FakeSource()
    server_task = asyncio.create_task(run_server(config, source))
    await asyncio.sleep(0.6)
    try:
        ticket = await asyncio.to_thread(_request_ticket)
        print("ticket issued:", bool(ticket))
        rgb = await _rfb_handshake_and_frame(ticket)
        assert rgb == source.snapshot_rgb(), "served frame does not match source"
        Image.frombytes("RGB", (WIDTH, HEIGHT), rgb).save("captures/downstream_check.png")
        print(f"OK: RFB None handshake + Raw frame {WIDTH}x{HEIGHT} round-trips exactly")
    finally:
        server_task.cancel()


if __name__ == "__main__":
    asyncio.run(_main())
