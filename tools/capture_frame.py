"""Capture one or more COMPLETE AST2100 frames from the live BMC.

Performs the proven M0 auth path, requests a full (non-incremental)
FramebufferUpdate, then drains the rectangle payload to idle so the entire
frame is captured (not a fixed-size sample). Writes the raw rectangle payload
to captures/frame_full.bin and a JSON sidecar with the rectangle metadata, for
offline decoder development and validation.

Usage:
    uv run python -m tools.capture_frame

Reads the BMC host/user/password from the local 'secret' file (3 lines).
No secret material (password, SID, token, credential block) is ever logged or
written to the capture files; capture files contain only server-received bytes.
"""

from __future__ import annotations

import asyncio
import json
import ssl
import struct
from pathlib import Path
from typing import Any

import websockets

from spike.aten_protocol import (
    ATEN_ENCODINGS,
    ATEN_EXTRA_MESSAGE_SKIP,
    build_credential_block,
    build_framebuffer_update_request,
    build_set_encodings,
    parse_rectangle_header,
    parse_server_init,
)
from spike.m0_probe import fetch_ikvm_token, load_credentials, login_web_ui

CAPTURES_DIR = Path("captures")
READ_TIMEOUT_SEC = 10.0
IDLE_DRAIN_SEC = 2.0


class BufferedWs:
    """Minimal buffered reader over a websocket binary stream.

    Reassembles the RFB byte stream across arbitrary WebSocket frame
    boundaries and supports both exact reads and idle-draining.
    """

    def __init__(self, ws: Any) -> None:
        self._ws = ws
        self._buf = bytearray()

    async def _recv_frame(self, timeout: float) -> bool:
        """Receive one WS frame into the buffer. Return False on timeout."""
        try:
            frame = await asyncio.wait_for(self._ws.recv(), timeout=timeout)
        except asyncio.TimeoutError:
            return False
        if isinstance(frame, str):
            self._buf.extend(frame.encode("latin-1"))
        else:
            self._buf.extend(frame)
        return True

    async def read_exact(self, n: int) -> bytes:
        """Read exactly n bytes, waiting across frames."""
        while len(self._buf) < n:
            if not await self._recv_frame(READ_TIMEOUT_SEC):
                raise asyncio.TimeoutError(f"timeout waiting for {n} bytes")
        data = bytes(self._buf[:n])
        del self._buf[:n]
        return data

    async def write(self, data: bytes) -> None:
        await self._ws.send(data)

    async def drain_to_idle(self) -> bytes:
        """Return all buffered bytes plus everything received until the server
        stays silent for IDLE_DRAIN_SEC. Used to capture a full frame payload."""
        while await self._recv_frame(IDLE_DRAIN_SEC):
            pass
        data = bytes(self._buf)
        self._buf.clear()
        return data


async def capture_one_frame() -> dict:
    """Connect, authenticate, request a full frame, and capture it.

    Returns:
        meta (dict): rectangle metadata (dimensions, encoding, payload sizes).
    """
    host, username, password = load_credentials(Path("secret"))
    sid = login_web_ui(host, username, password)
    token = fetch_ikvm_token(host, username, password)

    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE

    CAPTURES_DIR.mkdir(exist_ok=True)

    async with websockets.connect(
        f"wss://{host}/",
        ssl=ssl_ctx,
        additional_headers={"Cookie": f"SID={sid}"},
        max_size=None,
    ) as ws:
        t = BufferedWs(ws)

        # Handshake (verbatim version echo + InsydeVNC token credential).
        banner = await t.read_exact(12)
        await t.write(banner)
        num_types = (await t.read_exact(1))[0]
        types = await t.read_exact(num_types)
        if 0x10 not in types:
            raise RuntimeError(f"type 0x10 not offered: {list(types)}")
        await t.write(bytes([0x10]))
        await t.read_exact(24)  # opaque challenge, discarded
        await t.write(build_credential_block(token, ""))
        sec = struct.unpack(">I", await t.read_exact(4))[0]
        if sec != 0:
            raise RuntimeError(f"SecurityResult={sec}")

        # ClientInit + ServerInit (+12 ATEN extra).
        await t.write(bytes([0x01]))
        base = await t.read_exact(24)
        name_len = struct.unpack_from(">I", base, 20)[0]
        name = await t.read_exact(name_len) if name_len else b""
        extra = await t.read_exact(12)
        srv = parse_server_init(base + name + extra)

        await t.write(build_set_encodings(ATEN_ENCODINGS))

        # Request a full (non-incremental) screen update.
        fb_w = srv["framebuffer_width"] or 1024
        fb_h = srv["framebuffer_height"] or 768
        await t.write(build_framebuffer_update_request(False, 0, 0, fb_w, fb_h))

        # Read messages until a FramebufferUpdate, absorbing extra types.
        rects: list[dict] = []
        for _ in range(40):
            msg_type = (await t.read_exact(1))[0]
            if msg_type in ATEN_EXTRA_MESSAGE_SKIP:
                await t.read_exact(ATEN_EXTRA_MESSAGE_SKIP[msg_type])
                continue
            if msg_type != 0:
                raise RuntimeError(f"unexpected message type {msg_type}")
            await t.read_exact(1)  # padding
            num_rects = struct.unpack(">H", await t.read_exact(2))[0]
            for i in range(num_rects):
                hdr = parse_rectangle_header(await t.read_exact(12))
                # The full-screen AST2100 rectangle payload has no explicit
                # length; drain to idle to capture the complete frame.
                payload = await t.drain_to_idle()
                out = CAPTURES_DIR / f"frame_rect{i}.bin"
                out.write_bytes(payload)
                rects.append(
                    {
                        "index": i,
                        "x": hdr["x"],
                        "y": hdr["y"],
                        "width": hdr["width"],
                        "height": hdr["height"],
                        "raw_encoding": hdr["raw_encoding"],
                        "effective_encoding": hdr["effective_encoding"],
                        "payload_file": out.name,
                        "payload_len": len(payload),
                        "payload_head_hex": payload[:32].hex(),
                    }
                )
            break

        meta = {
            "server_init": {
                "advertised_width": srv["framebuffer_width"],
                "advertised_height": srv["framebuffer_height"],
                "name": srv["name_text"].decode("ascii", "replace"),
                "pixel_format": {
                    k: v
                    for k, v in srv["pixel_format"].items()
                    if k != "raw"
                },
            },
            "rectangles": rects,
        }
        (CAPTURES_DIR / "frame_meta.json").write_text(json.dumps(meta, indent=2))
        return meta


def main() -> None:
    """Synchronous entry point."""
    meta = asyncio.run(capture_one_frame())
    print(json.dumps(meta, indent=2))


if __name__ == "__main__":
    main()
