"""Pure byte-level helpers for the ATEN iKVM RFB protocol.

No I/O, no asyncio. All functions are fully unit-testable in isolation.

Wire sequence reference (ATEN type-16 / aten1 path):
    CLIENT                              SERVER
                      <-- 12B "RFB 055.008\\n"
    "RFB 055.008\\n"  -->
                      <-- 0x01 (num sec types = 1)
                      <-- 0x10 (security type = 16)
    0x10             -->
                      <-- 4B nt (readTightTunnels)
                      <-- 20B skip (magic gate fired)
    username[24]     -->  credential block (48 bytes total)
    password[24]     -->
                      <-- 4B SecurityResult uint32; 0=OK
    0x01             -->  ClientInit: shared=1
                      <-- 2B FBWidth u16
                      <-- 2B FBHeight u16
                      <-- 16B PixelFormat
                      <-- 4B NameLength u32
                      <-- NameLength bytes NameText
                      <-- 8B unknown (aten1 extra)
                      <-- 1B IKVMVideoEnable
                      <-- 1B IKVMKMEnable
                      <-- 1B IKVMKickEnable
                      <-- 1B VUSBEnable
"""

import struct

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ATEN_CREDENTIAL_LEN = 24

# Server-to-client extra message types specific to ATEN iKVM.
# Maps message type byte -> total bytes to skip AFTER the type byte.
# Sources: kelleyk/noVNC rfb.js (bmc-support branch); thefloweringash/aten-proxy.
ATEN_EXTRA_MESSAGE_SKIP: dict[int, int] = {
    4: 20,    # Front Ground Event
    22: 1,    # Keep Alive Event
    51: 4,    # Video Get Info
    55: 2,    # Mouse Get Info
    57: 264,  # Session Message (4 + 4 + 256 bytes)
    60: 8,    # Get Viewer Lang
}

# SetEncodings advertisement list (preference order per RFB spec).
# ATEN servers ignore standard encodings and respond with ATEN ones.
# Source: kelleyk/noVNC rfb.js _encodings array (bmc-support branch).
ATEN_ENCODINGS: list[int] = [
    0x01,   # COPYRECT
    0x07,   # TIGHT
    -260,   # TIGHT_PNG
    0x05,   # HEXTILE
    0x02,   # RRE
    0x00,   # RAW
    0x57,   # ATEN_AST2100 (AST2100 JPEG-like codec)
    0x58,   # ATEN_ASTJPEG
    0x59,   # ATEN_HERMON (subrects or raw full-frame)
    0x60,   # ATEN_YARKON
    0x61,   # ATEN_PILOT3
    -26,    # JPEG_quality_med
    -247,   # compress_hi
    -223,   # DesktopSize
    -224,   # last_rect
    -239,   # Cursor
    -258,   # QEMUExtendedKeyEvent
    -308,   # ExtendedDesktopSize
    -309,   # xvp
    -312,   # Fence
    -313,   # ContinuousUpdates
]


# ---------------------------------------------------------------------------
# Credential helpers
# ---------------------------------------------------------------------------


def build_credential_block(username: str, password: str) -> bytes:
    """Build the 48-byte ATEN type-16 auth credential block.

    Each field is encoded as latin-1, NUL-padded to exactly 24 bytes.
    If either string exceeds 24 bytes when encoded, ValueError is raised
    (mirrors the go-rfb behaviour: 'allowed 0-23', but the actual check
    is len > 24 so 24 characters are permitted).

    Wire layout:
        Bytes  0-23: username field (24 bytes, NUL-padded)
        Bytes 24-47: password field (24 bytes, NUL-padded)

    For the ATEN WSS path the SID cookie value must be passed as BOTH
    username AND password (per flameeyes 2012 and REQUIREMENTS.md §4.2).

    Args:
        username (str): Username or SID string (max 24 bytes latin-1).
        password (str): Password or SID string (max 24 bytes latin-1).

    Returns:
        block (bytes): 48-byte credential block ready to send on the wire.

    Raises:
        ValueError: If username or password exceeds 24 bytes after encoding.
    """
    raw_user = username.encode("latin-1")
    raw_pass = password.encode("latin-1")

    if len(raw_user) > ATEN_CREDENTIAL_LEN:
        raise ValueError(
            f"username too long ({len(raw_user)} bytes); max {ATEN_CREDENTIAL_LEN}"
        )
    if len(raw_pass) > ATEN_CREDENTIAL_LEN:
        raise ValueError(
            f"password too long ({len(raw_pass)} bytes); max {ATEN_CREDENTIAL_LEN}"
        )

    user_field = raw_user.ljust(ATEN_CREDENTIAL_LEN, b"\x00")
    pass_field = raw_pass.ljust(ATEN_CREDENTIAL_LEN, b"\x00")
    return user_field + pass_field


# ---------------------------------------------------------------------------
# Magic gate
# ---------------------------------------------------------------------------


def check_aten_magic_gate(nt: int) -> bool:
    """Return True if the ATEN aten1 magic gate condition fires.

    The gate fires when either:
      1. (nt & 0xffff0ff0) == 0xaff90fb0  (magic pattern match), OR
      2. nt <= 0 or nt > 0x1000000        (implausible tunnel count)

    When the gate fires the caller must read and discard 20 additional bytes
    from the stream, and set the protocol version to "aten1".

    Source: unistack-org/go-rfb security_aten.go ClientAuthATEN.Auth

    Args:
        nt (int): The 4-byte big-endian uint32 read from the stream after
                  security-type selection (the TightVNC tunnel count field).

    Returns:
        fires (bool): True if the gate condition is met.
    """
    pattern_match = (nt & 0xFFFF0FF0) == 0xAFF90FB0
    out_of_range = nt <= 0 or nt > 0x1000000
    return pattern_match or out_of_range


# ---------------------------------------------------------------------------
# SecurityResult
# ---------------------------------------------------------------------------


def parse_security_result(data: bytes) -> int:
    """Parse the 4-byte SecurityResult field from the server.

    Args:
        data (bytes): Exactly 4 bytes received from the server.

    Returns:
        result (int): 0 = success, 1 = failure (further reason bytes follow
                      in the stream; not parsed here).

    Raises:
        ValueError: If data is not exactly 4 bytes.
    """
    if len(data) != 4:
        raise ValueError(f"SecurityResult must be 4 bytes; got {len(data)}")
    (result,) = struct.unpack(">I", data)
    return result


# ---------------------------------------------------------------------------
# ServerInit parser
# ---------------------------------------------------------------------------


def parse_server_init(data: bytes) -> dict:
    """Parse a standard RFB ServerInit message plus the ATEN +12 extra bytes.

    Standard RFB ServerInit layout (24 bytes fixed, then variable name):
        Offset  Size  Field
        0       2     framebuffer_width   (u16, big-endian)
        2       2     framebuffer_height  (u16, big-endian)
        4       16    pixel_format        (16 bytes, see below)
        20      4     name_length         (u32, big-endian)
        24      N     name_text           (N = name_length bytes)

    PixelFormat layout (16 bytes, offsets relative to start of pixel_format):
        0   1   bits_per_pixel   (u8)
        1   1   depth            (u8)
        2   1   big_endian_flag  (u8, 0 or 1)
        3   1   true_colour_flag (u8, 0 or 1)
        4   2   red_max          (u16, big-endian)
        6   2   green_max        (u16, big-endian)
        8   2   blue_max         (u16, big-endian)
        10  1   red_shift        (u8)
        11  1   green_shift      (u8)
        12  1   blue_shift       (u8)
        13  3   padding          (3 bytes, unused)

    ATEN extra bytes (12 bytes, appended after name_text):
        0   8   unknown          (8 bytes, skip)
        8   1   ikvm_video_enable (u8)
        9   1   ikvm_km_enable    (u8)
        10  1   ikvm_kick_enable  (u8)
        11  1   vusb_enable       (u8)

    Source: kelleyk/noVNC rfb.js (bmc-support); thefloweringash/aten-proxy main.cc.

    Args:
        data (bytes): The raw bytes of a complete ServerInit message including
                      the ATEN extra 12 bytes. Must be at least 24 + name_length
                      + 12 bytes.

    Returns:
        info (dict): Parsed fields:
            framebuffer_width    (int)
            framebuffer_height   (int)
            pixel_format         (dict): bits_per_pixel, depth, big_endian_flag,
                                         true_colour_flag, red_max, green_max,
                                         blue_max, red_shift, green_shift,
                                         blue_shift, raw (bytes)
            name_length          (int)
            name_text            (bytes)
            aten_unknown         (bytes): 8 unknown bytes from the ATEN extension
            ikvm_video_enable    (int)
            ikvm_km_enable       (int)
            ikvm_kick_enable     (int)
            vusb_enable          (int)

    Raises:
        ValueError: If data is too short for the declared name_length + extras.
    """
    if len(data) < 24:
        raise ValueError(f"ServerInit too short: need >=24 bytes, got {len(data)}")

    fb_width, fb_height = struct.unpack_from(">HH", data, 0)
    pf_raw = data[4:20]

    (
        bpp,
        depth,
        big_endian,
        true_colour,
        red_max,
        green_max,
        blue_max,
        red_shift,
        green_shift,
        blue_shift,
    ) = struct.unpack_from(">BBBBHHHBBBxxx", data, 4)

    (name_length,) = struct.unpack_from(">I", data, 20)

    min_total = 24 + name_length + 12
    if len(data) < min_total:
        raise ValueError(
            f"ServerInit too short: need {min_total} bytes for name+aten, got {len(data)}"
        )

    name_text = data[24 : 24 + name_length]
    aten_offset = 24 + name_length
    aten_unknown = data[aten_offset : aten_offset + 8]
    ikvm_video_enable = data[aten_offset + 8]
    ikvm_km_enable = data[aten_offset + 9]
    ikvm_kick_enable = data[aten_offset + 10]
    vusb_enable = data[aten_offset + 11]

    return {
        "framebuffer_width": fb_width,
        "framebuffer_height": fb_height,
        "pixel_format": {
            "bits_per_pixel": bpp,
            "depth": depth,
            "big_endian_flag": big_endian,
            "true_colour_flag": true_colour,
            "red_max": red_max,
            "green_max": green_max,
            "blue_max": blue_max,
            "red_shift": red_shift,
            "green_shift": green_shift,
            "blue_shift": blue_shift,
            "raw": bytes(pf_raw),
        },
        "name_length": name_length,
        "name_text": bytes(name_text),
        "aten_unknown": bytes(aten_unknown),
        "ikvm_video_enable": ikvm_video_enable,
        "ikvm_km_enable": ikvm_km_enable,
        "ikvm_kick_enable": ikvm_kick_enable,
        "vusb_enable": vusb_enable,
    }


# ---------------------------------------------------------------------------
# Rectangle header parser
# ---------------------------------------------------------------------------


def parse_rectangle_header(data: bytes) -> dict:
    """Parse a standard RFB rectangle header (12 bytes).

    Wire layout:
        Offset  Size  Field
        0       2     x         (u16, big-endian)
        2       2     y         (u16, big-endian)
        4       2     width     (u16, big-endian)
        6       2     height    (u16, big-endian)
        8       4     encoding  (s32, big-endian)

    ATEN 0x00 remap: when ATEN mode is active and the encoding field reads
    0x00000000 (which would normally mean RAW), it is remapped to 0x59
    (ATEN_HERMON). Both the raw and effective encoding are returned.

    Source: kelleyk/noVNC rfb.js bmc-support — '0x00 even when it is meant
    to be 0x59'.

    Args:
        data (bytes): Exactly 12 bytes of a rectangle header.

    Returns:
        rect (dict):
            x                (int)
            y                (int)
            width            (int)
            height           (int)
            raw_encoding     (int): The s32 value as read from the wire.
            effective_encoding (int): raw_encoding, or 0x59 if raw was 0x00.

    Raises:
        ValueError: If data is not exactly 12 bytes.
    """
    if len(data) != 12:
        raise ValueError(f"Rectangle header must be 12 bytes; got {len(data)}")

    x, y, w, h, encoding = struct.unpack(">HHHHi", data)

    effective = 0x59 if encoding == 0x00 else encoding

    return {
        "x": x,
        "y": y,
        "width": w,
        "height": h,
        "raw_encoding": encoding,
        "effective_encoding": effective,
    }


# ---------------------------------------------------------------------------
# Client message builders
# ---------------------------------------------------------------------------


def build_set_encodings(encodings: list[int]) -> bytes:
    """Build a SetEncodings client message (RFB message type 2).

    Wire layout:
        Offset  Size  Field
        0       1     message_type  (u8 = 2)
        1       1     padding       (u8 = 0)
        2       2     num_encodings (u16, big-endian)
        4       4*N   encodings     (s32 each, big-endian)

    Args:
        encodings (list[int]): List of encoding IDs in preference order.
                               Each value is a signed 32-bit integer.

    Returns:
        msg (bytes): Complete SetEncodings wire message.
    """
    n = len(encodings)
    header = struct.pack(">BBH", 2, 0, n)
    body = struct.pack(f">{n}i", *encodings)
    return header + body


def build_framebuffer_update_request(
    incremental: bool, x: int, y: int, w: int, h: int
) -> bytes:
    """Build a FramebufferUpdateRequest client message (RFB message type 3).

    Wire layout:
        Offset  Size  Field
        0       1     message_type  (u8 = 3)
        1       1     incremental   (u8; 1 = incremental, 0 = full refresh)
        2       2     x             (u16, big-endian)
        4       2     y             (u16, big-endian)
        6       2     width         (u16, big-endian)
        8       2     height        (u16, big-endian)

    Args:
        incremental (bool): True for incremental update, False for full refresh.
        x (int): X origin of the requested region.
        y (int): Y origin of the requested region.
        w (int): Width of the requested region.
        h (int): Height of the requested region.

    Returns:
        msg (bytes): 10-byte FramebufferUpdateRequest wire message.
    """
    return struct.pack(">BBHHHH", 3, 1 if incremental else 0, x, y, w, h)
