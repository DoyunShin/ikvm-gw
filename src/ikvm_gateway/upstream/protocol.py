"""Pure byte-level helpers for the ATEN iKVM RFB upstream protocol.

Ported from spike/aten_protocol.py with no changes to logic or byte layout.
No I/O, no asyncio.  All functions are fully unit-testable in isolation.
"""

from __future__ import annotations

import struct

# ---------------------------------------------------------------------------
# Re-exports from spike.aten_protocol (single source of truth)
# ---------------------------------------------------------------------------
# Rather than duplicating the implementations we import directly.
# Tests and callers should import from this module.

from spike.aten_protocol import (
    ATEN_CREDENTIAL_LEN,
    ATEN_ENCODINGS,
    ATEN_EXTRA_MESSAGE_SKIP,
    build_credential_block,
    build_framebuffer_update_request,
    build_set_encodings,
    check_aten_magic_gate,
    parse_rectangle_header,
    parse_security_result,
    parse_server_init,
)

__all__ = [
    "ATEN_CREDENTIAL_LEN",
    "ATEN_ENCODINGS",
    "ATEN_EXTRA_MESSAGE_SKIP",
    "build_credential_block",
    "build_framebuffer_update_request",
    "build_set_encodings",
    "check_aten_magic_gate",
    "parse_rectangle_header",
    "parse_security_result",
    "parse_server_init",
    "parse_aten_rect_extra",
]


def parse_aten_rect_extra(data: bytes) -> tuple[int, int]:
    """Parse the 8 extra bytes in the ATEN rectangle header (after the 12 RFB bytes).

    The ATEN 0x57 rectangle header is 20 bytes total:
        Bytes  0-11: standard RFB rect header (x, y, w, h as u16 each, encoding as s32)
        Bytes 12-15: mode        (u32, big-endian)
        Bytes 16-19: getDataLen  (u32, big-endian)

    This function parses bytes 12-19 (the ATEN-specific extension).

    Args:
        data (bytes): Exactly 8 bytes: 4-byte mode + 4-byte getDataLen.

    Returns:
        result (tuple[int, int]): (mode, get_data_len)

    Raises:
        ValueError: If data is not exactly 8 bytes.
    """
    if len(data) != 8:
        raise ValueError(f"ATEN rect extra must be 8 bytes; got {len(data)}")
    mode, get_data_len = struct.unpack(">II", data)
    return mode, get_data_len
