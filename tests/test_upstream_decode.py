"""Tests for the upstream rectangle-decode path using a real captured frame.

Reads captures/frame_rect0.bin and drives AtenUpstreamClient.decode_rect_payload
directly so that snapshot_rgb() returns a 1024x768 RGB888 buffer.

No live network; no BMC connection.

Frame metadata (from captures/frame_meta.json):
  - Rectangle 0: x=0, y=0, w=1024, h=768, encoding=0x57 (ATEN_AST2100)
  - payload_file: captures/frame_rect0.bin (16420 bytes)
  - Layout: 4 bytes mode (0x00000000) + 4 bytes getDataLen (0x0000401c=16412)
            + 16412 bytes codec_data starting with 04 07 01 a6 ...
"""

from __future__ import annotations

import asyncio
import struct
from pathlib import Path

import pytest

CAPTURES_DIR = Path(__file__).parent.parent / "captures"
FRAME_RECT0 = CAPTURES_DIR / "frame_rect0.bin"

EXPECTED_WIDTH = 1024
EXPECTED_HEIGHT = 768
EXPECTED_RGB_LEN = EXPECTED_WIDTH * EXPECTED_HEIGHT * 3


def _build_rect_header_20(
    x: int, y: int, w: int, h: int, encoding: int, mode: int, get_data_len: int
) -> bytes:
    """Build a 20-byte ATEN rect header.

    Args:
        x, y, w, h (int): Rectangle coordinates and dimensions (u16 each).
        encoding (int): RFB encoding type (s32).
        mode (int): ATEN mode field (u32).
        get_data_len (int): Codec data length (u32).

    Returns:
        header (bytes): 20 bytes: 12-byte RFB header + 8-byte ATEN extension.
    """
    rfb_part = struct.pack(">HHHHi", x, y, w, h, encoding)
    aten_part = struct.pack(">II", mode, get_data_len)
    return rfb_part + aten_part


@pytest.mark.skipif(
    not FRAME_RECT0.exists(),
    reason="captures/frame_rect0.bin not present"
)
class TestFrameRectDecode:
    """Feed captured frame data through decode_rect_payload and verify result."""

    def _read_frame_payload(self) -> tuple[bytes, bytes]:
        """Read frame_rect0.bin and split into header+codec_data.

        Returns:
            header_20 (bytes): 20-byte ATEN rect header.
            codec_data (bytes): getDataLen bytes of codec data.
        """
        raw = FRAME_RECT0.read_bytes()
        # Layout: 4-byte mode + 4-byte getDataLen + getDataLen codec bytes
        mode = struct.unpack(">I", raw[0:4])[0]
        get_data_len = struct.unpack(">I", raw[4:8])[0]
        codec_data = raw[8 : 8 + get_data_len]

        header_20 = _build_rect_header_20(
            x=0, y=0,
            w=EXPECTED_WIDTH, h=EXPECTED_HEIGHT,
            encoding=0x57,   # ATEN_AST2100
            mode=mode,
            get_data_len=get_data_len,
        )
        return header_20, codec_data

    def test_snapshot_rgb_length(self):
        """After decode_rect_payload, snapshot_rgb() must have correct length."""
        from ikvm_gateway.upstream.client import AtenUpstreamClient

        client = AtenUpstreamClient.__new__(AtenUpstreamClient)
        # Minimal init without calling __init__ (no auth needed).
        import threading
        client._fb_lock = threading.Lock()
        client._fb_width = 0
        client._fb_height = 0
        client._fb_rgb = b""
        client._transport = None

        header_20, codec_data = self._read_frame_payload()
        asyncio.run(client.decode_rect_payload(header_20, codec_data))

        rgb = client.snapshot_rgb()
        assert len(rgb) == EXPECTED_RGB_LEN

    def test_framebuffer_dimensions(self):
        """Width and height must match expected 1024x768 after decode."""
        from ikvm_gateway.upstream.client import AtenUpstreamClient

        client = AtenUpstreamClient.__new__(AtenUpstreamClient)
        import threading
        client._fb_lock = threading.Lock()
        client._fb_width = 0
        client._fb_height = 0
        client._fb_rgb = b""
        client._transport = None

        header_20, codec_data = self._read_frame_payload()
        asyncio.run(client.decode_rect_payload(header_20, codec_data))

        assert client.width == EXPECTED_WIDTH
        assert client.height == EXPECTED_HEIGHT

    def test_snapshot_rgb_non_uniform(self):
        """RGB data must contain more than one unique byte value (not blank)."""
        from ikvm_gateway.upstream.client import AtenUpstreamClient

        client = AtenUpstreamClient.__new__(AtenUpstreamClient)
        import threading
        client._fb_lock = threading.Lock()
        client._fb_width = 0
        client._fb_height = 0
        client._fb_rgb = b""
        client._transport = None

        header_20, codec_data = self._read_frame_payload()
        asyncio.run(client.decode_rect_payload(header_20, codec_data))

        rgb = client.snapshot_rgb()
        unique_values = len(set(rgb))
        assert unique_values > 1, (
            f"snapshot_rgb() returned uniform data ({unique_values} unique byte values); "
            "expected a real image"
        )

    def test_snapshot_rgb_is_bytes(self):
        """snapshot_rgb() must return bytes, not bytearray or memoryview."""
        from ikvm_gateway.upstream.client import AtenUpstreamClient

        client = AtenUpstreamClient.__new__(AtenUpstreamClient)
        import threading
        client._fb_lock = threading.Lock()
        client._fb_width = 0
        client._fb_height = 0
        client._fb_rgb = b""
        client._transport = None

        header_20, codec_data = self._read_frame_payload()
        asyncio.run(client.decode_rect_payload(header_20, codec_data))

        rgb = client.snapshot_rgb()
        assert isinstance(rgb, bytes)
