"""Live end-to-end test: run the full gateway against the real BMC and pull a
frame through the downstream RFB-over-WebSocket path as a stock-noVNC-style
client would, saving the result as a PNG.

Pipeline exercised: upstream auth+decode (Rust AST2100) -> framebuffer ->
downstream RFB 3.8 security None -> WebSocket -> RFB client -> PNG.

Usage:
    uv run python -m tools.e2e_live
"""

from __future__ import annotations

import asyncio
import json
import struct
import urllib.request
from pathlib import Path

import numpy as np
import websockets
from PIL import Image

from ikvm_gateway.app import run_gateway
from ikvm_gateway.downstream.ws_app import GatewayConfig

PORT = 5701
API_KEY = "e2e-live-key"
SECRET = Path("secret")


def _request_ticket() -> str:
    """GET /sessions with the API key and return the issued ticket."""
    req = urllib.request.Request(
        f"http://127.0.0.1:{PORT}/sessions",
        method="GET",
        headers={"Authorization": f"Bearer {API_KEY}"},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())["data"]["ticket"]


async def _pull_frame(ticket: str) -> tuple[int, int, bytes]:
    """Connect /vnc, RFB None handshake, request an update, return (w,h,rgb)."""
    async with websockets.connect(
        f"ws://127.0.0.1:{PORT}/vnc", subprotocols=[ticket], max_size=None
    ) as ws:
        buf = bytearray()

        async def read_exact(n: int) -> bytes:
            while len(buf) < n:
                buf.extend(await asyncio.wait_for(ws.recv(), timeout=15))
            out = bytes(buf[:n])
            del buf[:n]
            return out

        assert (await read_exact(12)) == b"RFB 003.008\n"
        await ws.send(b"RFB 003.008\n")
        num = (await read_exact(1))[0]
        types = await read_exact(num)
        assert 1 in types
        await ws.send(bytes([1]))
        assert struct.unpack(">I", await read_exact(4))[0] == 0
        await ws.send(bytes([1]))  # ClientInit shared
        si = await read_exact(24)
        w, h = struct.unpack(">HH", si[:4])
        name_len = struct.unpack(">I", si[20:24])[0]
        await read_exact(name_len)

        await ws.send(struct.pack(">BBHHHH", 3, 0, 0, 0, w, h))
        assert (await read_exact(1))[0] == 0  # FramebufferUpdate
        await read_exact(1)
        num_rects = struct.unpack(">H", await read_exact(2))[0]
        assert num_rects >= 1
        _, _, rw, rh, enc = struct.unpack(">HHHHi", await read_exact(12))
        assert enc == 0, f"expected Raw, got {enc}"
        raw = await read_exact(rw * rh * 4)

        # 32bpp little-endian, shifts r=16 g=8 b=0 -> bytes laid out B,G,R,X.
        arr = np.frombuffer(raw, dtype=np.uint8).reshape(rh, rw, 4)
        rgb = arr[:, :, [2, 1, 0]].tobytes()
        return rw, rh, rgb


async def _main() -> None:
    config = GatewayConfig(
        api_key=API_KEY, bmc_host=SECRET.read_text().split()[0], bind_port=PORT
    )
    gateway = asyncio.create_task(run_gateway(SECRET, config))
    await asyncio.sleep(6.0)  # let upstream auth + decode the first frame
    try:
        ticket = await asyncio.to_thread(_request_ticket)
        w, h, rgb = await _pull_frame(ticket)
        arr = np.frombuffer(rgb, dtype=np.uint8)
        Image.frombytes("RGB", (w, h), rgb).save("captures/e2e_live.png")
        print(
            f"OK e2e: {w}x{h} frame served over RFB-None WS | "
            f"mean={arr.mean():.2f} stddev={arr.std():.2f} distinct={len(set(arr.tolist()))}"
        )
    finally:
        gateway.cancel()
        try:
            await gateway
        except (asyncio.CancelledError, Exception):
            pass


if __name__ == "__main__":
    asyncio.run(_main())
