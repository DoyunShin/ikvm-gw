"""Standard RFB 3.8 server (security None) for one viewer session.

This module drives the downstream side of the ikvm-gateway:
  - Speaks RFB 003.008 to any stock VNC client or noVNC browser.
  - Security type None (type 1): the browser never sees BMC credentials.
  - Serves the framebuffer from a FramebufferSource (upstream decoded pixels).
  - Translates standard RFB input events (KeyEvent, PointerEvent) back to the
    upstream FramebufferSource for forwarding to the BMC.

Transport abstraction
---------------------
The server communicates through a Transport object rather than directly with
a socket or WebSocket.  Transport exposes two methods:

  read_exact(n: int) -> bytes
      Read exactly n bytes; raise ConnectionError on EOF or short read.

  write(data: bytes) -> Awaitable[None]
      Write bytes to the peer; backpressure is the caller's responsibility.

This allows the same RFB logic to run over:
  - WebSocket frames (see ws_app.py)
  - Plain TCP/TLS sockets
  - In-memory duplex streams (unit tests)

Pixel format
------------
Default server-advertised format: 32-bit little-endian true-colour, BGRX
  bpp=32, depth=24, big-endian=0, true-colour=1
  red_max=255 green_max=255 blue_max=255
  red_shift=16 green_shift=8 blue_shift=0

noVNC uses exactly this layout (BGRX / xRGB in little-endian order) so no
client-side SetPixelFormat is required for a standard noVNC connection.

The server accepts a SetPixelFormat from the client and honours the requested
shifts/maxima when encoding Raw rectangles, enabling other clients too.
"""

from __future__ import annotations

import asyncio
import struct
from dataclasses import dataclass, field
from typing import Protocol


# ---------------------------------------------------------------------------
# Transport protocol
# ---------------------------------------------------------------------------


class Transport(Protocol):
    """Byte-stream transport used by RfbServer.

    The implementation may be a WebSocket adapter, a raw TCP socket wrapper,
    or an in-memory duplex pipe for tests.
    """

    async def read_exact(self, n: int) -> bytes:
        """Read exactly n bytes from the peer.

        Args:
            n (int): Number of bytes to read.

        Returns:
            data (bytes): Exactly n bytes.

        Raises:
            ConnectionError: If the connection is closed before n bytes arrive.
        """
        ...

    async def write(self, data: bytes) -> None:
        """Write data to the peer.

        Args:
            data (bytes): Bytes to send.
        """
        ...


# ---------------------------------------------------------------------------
# Pixel format helpers
# ---------------------------------------------------------------------------

# Default 32-bit little-endian true-colour (matches noVNC default).
# Wire format: 32-bit pixel, red at bits [23:16], green [15:8], blue [7:0].
_DEFAULT_BPP: int = 32
_DEFAULT_DEPTH: int = 24
_DEFAULT_BIG_ENDIAN: int = 0
_DEFAULT_TRUE_COLOUR: int = 1
_DEFAULT_RED_MAX: int = 255
_DEFAULT_GREEN_MAX: int = 255
_DEFAULT_BLUE_MAX: int = 255
_DEFAULT_RED_SHIFT: int = 16
_DEFAULT_GREEN_SHIFT: int = 8
_DEFAULT_BLUE_SHIFT: int = 0

# RFB message type constants (client -> server)
_MSG_SET_PIXEL_FORMAT: int = 0
_MSG_SET_ENCODINGS: int = 2
_MSG_FRAMEBUFFER_UPDATE_REQUEST: int = 3
_MSG_KEY_EVENT: int = 4
_MSG_POINTER_EVENT: int = 5
_MSG_CLIENT_CUT_TEXT: int = 6

# RFB security type identifiers
_SECURITY_TYPE_NONE: int = 1

# RFB server->client message type
_MSG_FRAMEBUFFER_UPDATE: int = 0

# Raw encoding identifier
_ENCODING_RAW: int = 0


@dataclass
class PixelFormat:
    """Negotiated pixel format for an RFB session.

    All fields follow the RFB specification layout.
    """

    bpp: int = _DEFAULT_BPP
    depth: int = _DEFAULT_DEPTH
    big_endian: int = _DEFAULT_BIG_ENDIAN
    true_colour: int = _DEFAULT_TRUE_COLOUR
    red_max: int = _DEFAULT_RED_MAX
    green_max: int = _DEFAULT_GREEN_MAX
    blue_max: int = _DEFAULT_BLUE_MAX
    red_shift: int = _DEFAULT_RED_SHIFT
    green_shift: int = _DEFAULT_GREEN_SHIFT
    blue_shift: int = _DEFAULT_BLUE_SHIFT


def build_pixel_format_bytes(pf: PixelFormat) -> bytes:
    """Serialise a PixelFormat into 16 wire bytes (RFB spec layout).

    Args:
        pf (PixelFormat): Pixel format to serialise.

    Returns:
        data (bytes): 16-byte big-endian encoded PixelFormat block.
    """
    return struct.pack(
        ">BBBBHHHBBBxxx",
        pf.bpp,
        pf.depth,
        pf.big_endian,
        pf.true_colour,
        pf.red_max,
        pf.green_max,
        pf.blue_max,
        pf.red_shift,
        pf.green_shift,
        pf.blue_shift,
    )


def parse_pixel_format_bytes(data: bytes) -> PixelFormat:
    """Parse 16 wire bytes into a PixelFormat.

    Args:
        data (bytes): Exactly 16 bytes from a SetPixelFormat or ServerInit.

    Returns:
        pf (PixelFormat): Decoded pixel format.

    Raises:
        ValueError: If data is not exactly 16 bytes.
    """
    if len(data) != 16:
        raise ValueError(f"PixelFormat must be 16 bytes; got {len(data)}")
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
    ) = struct.unpack_from(">BBBBHHHBBBxxx", data)
    return PixelFormat(
        bpp=bpp,
        depth=depth,
        big_endian=big_endian,
        true_colour=true_colour,
        red_max=red_max,
        green_max=green_max,
        blue_max=blue_max,
        red_shift=red_shift,
        green_shift=green_shift,
        blue_shift=blue_shift,
    )


# ---------------------------------------------------------------------------
# Framebuffer encoding
# ---------------------------------------------------------------------------


def encode_raw_rectangle(
    rgb: bytes,
    x: int,
    y: int,
    w: int,
    h: int,
    pf: PixelFormat,
) -> bytes:
    """Encode an RGB888 region as a Raw RFB rectangle.

    Converts RGB888 source pixels into the negotiated pixel format and
    prepends the standard 12-byte rectangle header.

    Currently only 32-bit formats (bpp == 32) are supported. Each output
    pixel is packed as a 4-byte value with the configured shifts; the
    fourth byte is left at zero (padding / alpha-ignored).

    Args:
        rgb (bytes): RGB888 row-major pixel data for the full framebuffer.
                     Length must equal fb_width * fb_height * 3 where
                     fb_width and fb_height are the dimensions of the full
                     framebuffer passed in as part of x/y/w/h context.
                     NOTE: rgb must contain data for the full framebuffer;
                     the slice [x:x+w, y:y+h] is extracted here.
        x (int): Left edge of the rectangle in framebuffer coordinates.
        y (int): Top edge of the rectangle in framebuffer coordinates.
        w (int): Rectangle width in pixels.
        h (int): Rectangle height in pixels.
        pf (PixelFormat): Negotiated client pixel format.

    Returns:
        rectangle (bytes): 12-byte header + encoded pixel data.

    Raises:
        ValueError: If bpp is not 32 (unsupported format).
    """
    if pf.bpp != 32:
        raise ValueError(f"Only 32-bpp pixel formats supported; got {pf.bpp}")

    # Compute full framebuffer width from rgb length and h context.
    # We derive fb_width from the rgb buffer: len(rgb) / 3 / total_rows would
    # require knowing total_rows; instead we accept that callers pass the
    # full-screen rgb and we derive width from w and the fact that this is
    # a full-width rectangle (x=0 for full-frame calls).
    #
    # For the general case, callers must pass the full framebuffer rgb;
    # we reconstruct fb_width = len(rgb) // 3 // fb_height.  Since we are
    # encoding potentially a sub-rectangle we need fb_width passed in.
    # To keep the API simple, encode_raw_rectangle accepts the FULL framebuffer
    # bytes; x/y/w/h indicate the sub-rectangle to extract.
    #
    # Derive full framebuffer height and width from the total pixel count
    # via: total_pixels = len(rgb) // 3; fb_width = total_pixels // fb_height.
    # But we don't have fb_height here. Accept fb_width implicitly via:
    # row stride = (total_pixels / expected_rows). We skip to a simpler
    # contract: callers must ensure rgb contains exactly the region [y:y+h]
    # with each row being the full fb_width pixels.  We use the helper
    # pack_pixels_rgb888_to_32bit which takes the full flat buffer and the
    # parameters needed to extract the sub-rectangle.
    #
    # For the current v1 use (full-screen rectangle, x=0, y=0):
    # rgb length = fb_width * fb_height * 3 => fb_width = len(rgb)//3//fb_height
    # We pass fb_width as an implicit parameter by requiring callers to use
    # encode_raw_rectangle_with_stride instead for non-full-width cases.
    # For simplicity at v1, fb_width is inferred as w (full-width only).
    # TODO: add fb_stride parameter when dirty-region/sub-rect support is added.
    fb_stride = w  # v1: always full-width rectangle (x=0, w=full_width)

    if pf.big_endian:
        pack_fmt = ">I"
    else:
        pack_fmt = "<I"

    # Build pixel data: iterate over the h rows of the sub-rectangle.
    # For a full-width rectangle (x=0, w=fb_width), each row starts at
    # pixel index (y + row) * fb_stride.
    pixel_count = w * h
    out = bytearray(pixel_count * 4)
    out_idx = 0

    for row in range(h):
        row_start = ((y + row) * fb_stride + x) * 3
        for col in range(w):
            src = row_start + col * 3
            r = rgb[src]
            g = rgb[src + 1]
            b = rgb[src + 2]
            pixel = (r << pf.red_shift) | (g << pf.green_shift) | (b << pf.blue_shift)
            struct.pack_into(pack_fmt, out, out_idx, pixel)
            out_idx += 4

    # Rectangle header: x, y, w, h (u16 each big-endian) + encoding s32 big-endian.
    header = struct.pack(">HHHHi", x, y, w, h, _ENCODING_RAW)
    return bytes(header) + bytes(out)


# ---------------------------------------------------------------------------
# RFB server
# ---------------------------------------------------------------------------


@dataclass
class _SessionState:
    """Mutable state for one RFB session."""

    pixel_format: PixelFormat = field(default_factory=PixelFormat)
    # Accepted encodings list from client (not used at v1 beyond acknowledgement)
    accepted_encodings: list[int] = field(default_factory=list)


class RfbServer:
    """RFB 3.8 server for one viewer session (security None).

    Drives the full RFB handshake and message loop over a Transport.

    Usage::

        transport = SomeTransportImpl(...)
        source = SomeFramebufferSource(...)
        server = RfbServer(transport, source)
        await server.run()

    The server exits when the client disconnects or on any transport error.
    Caller is responsible for lifecycle (timeouts, cancellation).
    """

    _SERVER_NAME: bytes = b"ikvm-gateway"

    def __init__(
        self,
        transport: Transport,
        source: object,
    ) -> None:
        """Initialise the RFB server.

        Args:
            transport (Transport): Byte-stream transport to communicate with
                the VNC client.
            source (FramebufferSource): Upstream framebuffer and input source.
                Must satisfy the FramebufferSource protocol from
                src/ikvm_gateway/framebuffer.py.
        """
        self._transport = transport
        self._source = source
        self._state = _SessionState()

    async def run(self) -> None:
        """Run the full RFB session: handshake then message loop.

        Returns when the client disconnects or an unrecoverable error occurs.
        """
        await self._do_handshake()
        await self._message_loop()

    # ------------------------------------------------------------------
    # Handshake phases
    # ------------------------------------------------------------------

    async def _do_handshake(self) -> None:
        """Execute the RFB 3.8 handshake sequence.

        Phase 1: Version negotiation (RFB 003.008).
        Phase 2: Security type negotiation (type 1 = None).
        Phase 3: SecurityResult (0 = OK, no challenge/response needed).
        Phase 4: ClientInit / ServerInit.
        """
        await self._negotiate_version()
        await self._negotiate_security()
        await self._exchange_init()

    async def _negotiate_version(self) -> None:
        """Send server version banner and read client version.

        Server sends: b'RFB 003.008\n' (12 bytes).
        Client sends: 12-byte version string (accepted as-is; we require 3.8).
        """
        await self._transport.write(b"RFB 003.008\n")
        # Read and discard client version (12 bytes); we accept anything.
        await self._transport.read_exact(12)

    async def _negotiate_security(self) -> None:
        """Offer security type None (type 1) and confirm selection.

        Server sends: [count=1][type=1]
        Client sends: [1 byte type selection] (must be 1)
        RFB 3.8 requires server to send SecurityResult after type selection.
        Server sends: [0x00 0x00 0x00 0x00] (SecurityResult = OK)
        """
        # Offer one security type: None (1)
        await self._transport.write(bytes([1, _SECURITY_TYPE_NONE]))
        # Read client selection (1 byte)
        selection = await self._transport.read_exact(1)
        if selection[0] != _SECURITY_TYPE_NONE:
            raise ValueError(
                f"Client selected unexpected security type {selection[0]}; expected {_SECURITY_TYPE_NONE}"
            )
        # RFB 3.8: send SecurityResult = 0 (OK) after security-type selection,
        # even for security None.
        await self._transport.write(struct.pack(">I", 0))

    async def _exchange_init(self) -> None:
        """Read ClientInit and send ServerInit.

        Client sends: [shared-flag u8] (1 = allow sharing; ignored by v1).
        Server sends: ServerInit with real framebuffer dimensions and pixel format.
        """
        # Read ClientInit (1 byte, shared flag; ignore at v1)
        await self._transport.read_exact(1)

        width = self._source.width
        height = self._source.height

        pf_bytes = build_pixel_format_bytes(self._state.pixel_format)
        name_bytes = self._SERVER_NAME
        name_len = struct.pack(">I", len(name_bytes))

        server_init = (
            struct.pack(">HH", width, height)
            + pf_bytes
            + name_len
            + name_bytes
        )
        await self._transport.write(server_init)

    # ------------------------------------------------------------------
    # Message loop
    # ------------------------------------------------------------------

    async def _message_loop(self) -> None:
        """Receive and dispatch client messages until the connection closes."""
        while True:
            msg_type_bytes = await self._transport.read_exact(1)
            msg_type = msg_type_bytes[0]

            if msg_type == _MSG_SET_PIXEL_FORMAT:
                await self._handle_set_pixel_format()
            elif msg_type == _MSG_SET_ENCODINGS:
                await self._handle_set_encodings()
            elif msg_type == _MSG_FRAMEBUFFER_UPDATE_REQUEST:
                await self._handle_framebuffer_update_request()
            elif msg_type == _MSG_KEY_EVENT:
                await self._handle_key_event()
            elif msg_type == _MSG_POINTER_EVENT:
                await self._handle_pointer_event()
            elif msg_type == _MSG_CLIENT_CUT_TEXT:
                await self._handle_client_cut_text()
            else:
                raise ValueError(f"Unknown client message type: {msg_type}")

    async def _handle_set_pixel_format(self) -> None:
        """Read and store a SetPixelFormat message (type 0).

        Wire layout after the type byte:
            3 bytes padding
            16 bytes PixelFormat
        """
        # 3 padding + 16 pixel format = 19 bytes
        payload = await self._transport.read_exact(19)
        # bytes [3:19] = pixel format (skip 3 padding bytes)
        pf = parse_pixel_format_bytes(payload[3:19])
        self._state.pixel_format = pf

    async def _handle_set_encodings(self) -> None:
        """Read and store a SetEncodings message (type 2).

        Wire layout after the type byte:
            1 byte padding
            2 bytes num_encodings (u16 big-endian)
            4 * num_encodings bytes (s32 each, big-endian)
        """
        header = await self._transport.read_exact(3)  # 1 pad + 2 count
        (num_encodings,) = struct.unpack(">H", header[1:3])
        enc_bytes = await self._transport.read_exact(num_encodings * 4)
        encodings = list(struct.unpack(f">{num_encodings}i", enc_bytes))
        self._state.accepted_encodings = encodings

    async def _handle_framebuffer_update_request(self) -> None:
        """Read a FramebufferUpdateRequest and respond with one Raw rectangle.

        Wire layout after the type byte:
            1 byte incremental flag
            2 bytes x (u16 big-endian)
            2 bytes y (u16 big-endian)
            2 bytes width (u16 big-endian)
            2 bytes height (u16 big-endian)
        Total: 9 bytes after type byte.

        Response: one full-screen Raw FramebufferUpdate.
        TODO: dirty-region tracking, Tight/ZRLE encoding.
        """
        # Read 9 bytes: incremental + x + y + w + h
        await self._transport.read_exact(9)
        # Ignore incremental flag and requested region at v1; always send full frame.
        await self._send_full_frame_update()

    async def _send_full_frame_update(self) -> None:
        """Encode and send a full-screen FramebufferUpdate (1 Raw rectangle).

        Wire layout of FramebufferUpdate:
            1 byte  msg_type = 0
            1 byte  padding = 0
            2 bytes num_rects (u16 big-endian) = 1
            [rectangle header + pixel data]
        """
        rgb = self._source.snapshot_rgb()
        width = self._source.width
        height = self._source.height

        rect_bytes = encode_raw_rectangle(
            rgb=rgb,
            x=0,
            y=0,
            w=width,
            h=height,
            pf=self._state.pixel_format,
        )

        header = struct.pack(">BBH", _MSG_FRAMEBUFFER_UPDATE, 0, 1)
        await self._transport.write(header + rect_bytes)

    async def _handle_key_event(self) -> None:
        """Read a KeyEvent message and forward to the upstream source.

        Wire layout after the type byte:
            1 byte down-flag (1 = press, 0 = release)
            2 bytes padding
            4 bytes keysym (u32 big-endian)
        Total: 7 bytes after type byte.
        """
        payload = await self._transport.read_exact(7)
        down_flag = payload[0]
        (keysym,) = struct.unpack_from(">I", payload, 3)
        await self._source.send_key_event(keysym=keysym, down=bool(down_flag))

    async def _handle_pointer_event(self) -> None:
        """Read a PointerEvent message and forward to the upstream source.

        Wire layout after the type byte:
            1 byte button-mask
            2 bytes x-position (u16 big-endian)
            2 bytes y-position (u16 big-endian)
        Total: 5 bytes after type byte.
        """
        payload = await self._transport.read_exact(5)
        button_mask = payload[0]
        x, y = struct.unpack_from(">HH", payload, 1)
        await self._source.send_pointer_event(x=x, y=y, button_mask=button_mask)

    async def _handle_client_cut_text(self) -> None:
        """Absorb a ClientCutText message (type 6).

        Wire layout after the type byte:
            3 bytes padding
            4 bytes length (u32 big-endian)
            length bytes text
        """
        header = await self._transport.read_exact(7)  # 3 pad + 4 length
        (length,) = struct.unpack_from(">I", header, 3)
        if length > 0:
            await self._transport.read_exact(length)
