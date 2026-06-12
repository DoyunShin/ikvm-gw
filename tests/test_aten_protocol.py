"""Unit tests for spike/aten_protocol.py.

No network, no asyncio. All tests are pure byte-level.
"""

import struct

import pytest

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


# ---------------------------------------------------------------------------
# build_credential_block
# ---------------------------------------------------------------------------


class TestBuildCredentialBlock:
    def test_total_length_is_48(self):
        block = build_credential_block("user", "pass")
        assert len(block) == 48

    def test_username_padded_to_24(self):
        block = build_credential_block("ab", "")
        assert block[0:2] == b"ab"
        assert block[2:24] == b"\x00" * 22

    def test_password_padded_to_24(self):
        block = build_credential_block("", "xyz")
        assert block[24:27] == b"xyz"
        assert block[27:48] == b"\x00" * 21

    def test_empty_strings(self):
        block = build_credential_block("", "")
        assert block == b"\x00" * 48

    def test_max_length_username(self):
        """Exactly 24 characters must be accepted."""
        name = "a" * 24
        block = build_credential_block(name, "")
        assert block[:24] == name.encode("latin-1")
        assert len(block) == 48

    def test_max_length_password(self):
        pwd = "b" * 24
        block = build_credential_block("", pwd)
        assert block[24:48] == pwd.encode("latin-1")

    def test_too_long_username_raises(self):
        with pytest.raises(ValueError, match="username too long"):
            build_credential_block("a" * 25, "")

    def test_too_long_password_raises(self):
        with pytest.raises(ValueError, match="password too long"):
            build_credential_block("", "b" * 25)

    def test_sid_in_both_slots(self):
        """SID placed in both username and password slots."""
        sid = "NP12ZnzPZ6Z4R2U"
        block = build_credential_block(sid, sid)
        sid_bytes = sid.encode("latin-1")
        assert block[:len(sid_bytes)] == sid_bytes
        assert block[len(sid_bytes):24] == b"\x00" * (24 - len(sid_bytes))
        assert block[24 : 24 + len(sid_bytes)] == sid_bytes
        assert block[24 + len(sid_bytes):] == b"\x00" * (24 - len(sid_bytes))

    def test_fields_concatenated_without_separator(self):
        """No separator between username and password slots."""
        block = build_credential_block("AB", "CD")
        assert block[22] == 0x00
        assert block[23] == 0x00
        assert block[24:26] == b"CD"


# ---------------------------------------------------------------------------
# check_aten_magic_gate
# ---------------------------------------------------------------------------


class TestCheckAtenMagicGate:
    def test_magic_pattern_exact(self):
        """0xaff90fb0 itself must match the pattern gate."""
        # (0xaff90fb0 & 0xffff0ff0) == 0x00f90fb0 != 0xaff90fb0
        # But 0xaff90fb0 > 0x1000000 so out-of-range gate fires.
        assert check_aten_magic_gate(0xAFF90FB0) is True

    def test_value_matching_mask(self):
        """A value where (nt & 0xffff0ff0) == 0xaff90fb0 must match."""
        # Construct a value: take 0xaff90fb0 and fill bits[11:8] freely.
        # e.g. 0xaff90fb0 | 0x00000100 = 0xaff90eb0... recalculate:
        # 0xaff90fb0 & 0xffff0ff0 = ?
        # 0xaff90fb0 = 1010 1111 1111 1001 0000 1111 1011 0000
        # mask       = 1111 1111 1111 1111 0000 1111 1111 0000
        # result     = 1010 1111 1111 1001 0000 1111 1011 0000
        #            = 0xaff90fb0
        # So 0xaff90fb0 itself satisfies the pattern.
        assert (0xAFF90FB0 & 0xFFFF0FF0) == 0xAFF90FB0
        assert check_aten_magic_gate(0xAFF90FB0) is True

    def test_out_of_range_large(self):
        """nt > 0x1000000 triggers the out-of-range gate."""
        assert check_aten_magic_gate(0x1000001) is True

    def test_out_of_range_zero(self):
        """nt == 0 triggers the out-of-range gate (nt <= 0)."""
        assert check_aten_magic_gate(0) is True

    def test_real_board_example(self):
        """Example from REQUIREMENTS.md §4.2: nt = 0x4006a074.

        0x4006a074 > 0x1000000 so out-of-range gate fires.
        """
        assert check_aten_magic_gate(0x4006A074) is True

    def test_plausible_value_no_gate(self):
        """A plausible tunnel count in range (1–16M) that does not match pattern."""
        # nt = 1: not > 0x1000000, not <= 0, and (1 & 0xffff0ff0) = 0 != 0xaff90fb0
        assert check_aten_magic_gate(1) is False

    def test_plausible_mid_range_no_gate(self):
        """nt = 5 is a valid tunnel count; gate should NOT fire."""
        assert check_aten_magic_gate(5) is False

    def test_boundary_max_plausible(self):
        """nt == 0x1000000 is exactly on the boundary; gate must NOT fire
        (condition is > not >=) and 0x1000000 > 0x1000000 is False.
        Also check pattern: (0x1000000 & 0xffff0ff0) = 0 != 0xaff90fb0.
        """
        assert check_aten_magic_gate(0x1000000) is False


# ---------------------------------------------------------------------------
# parse_security_result
# ---------------------------------------------------------------------------


class TestParseSecurityResult:
    def test_success_zero(self):
        assert parse_security_result(b"\x00\x00\x00\x00") == 0

    def test_failure_one(self):
        assert parse_security_result(b"\x00\x00\x00\x01") == 1

    def test_big_endian(self):
        # 0x00000100 big-endian = 256
        assert parse_security_result(b"\x00\x00\x01\x00") == 256

    def test_wrong_length_raises(self):
        with pytest.raises(ValueError, match="4 bytes"):
            parse_security_result(b"\x00\x00\x00")

    def test_wrong_length_too_long_raises(self):
        with pytest.raises(ValueError, match="4 bytes"):
            parse_security_result(b"\x00\x00\x00\x00\x00")


# ---------------------------------------------------------------------------
# parse_server_init
# ---------------------------------------------------------------------------


def _make_server_init_bytes(
    fb_width: int = 800,
    fb_height: int = 600,
    bpp: int = 16,
    depth: int = 15,
    big_endian: int = 0,
    true_colour: int = 1,
    red_max: int = 31,
    green_max: int = 31,
    blue_max: int = 31,
    red_shift: int = 10,
    green_shift: int = 5,
    blue_shift: int = 0,
    name: bytes = b"ATEN",
    aten_unknown: bytes = b"\xAA" * 8,
    ikvm_video: int = 1,
    ikvm_km: int = 1,
    ikvm_kick: int = 0,
    vusb: int = 0,
) -> bytes:
    """Build a synthetic ServerInit byte string for tests."""
    pf = struct.pack(
        ">BBBBHHHBBBxxx",
        bpp, depth, big_endian, true_colour,
        red_max, green_max, blue_max,
        red_shift, green_shift, blue_shift,
    )
    header = struct.pack(">HH", fb_width, fb_height) + pf + struct.pack(">I", len(name))
    aten_extra = aten_unknown + bytes([ikvm_video, ikvm_km, ikvm_kick, vusb])
    return header + name + aten_extra


class TestParseServerInit:
    def test_basic_fields(self):
        data = _make_server_init_bytes()
        info = parse_server_init(data)
        assert info["framebuffer_width"] == 800
        assert info["framebuffer_height"] == 600
        assert info["name_text"] == b"ATEN"
        assert info["name_length"] == 4

    def test_pixel_format_fields(self):
        data = _make_server_init_bytes(bpp=16, depth=15, red_max=31, green_max=31, blue_max=31)
        info = parse_server_init(data)
        pf = info["pixel_format"]
        assert pf["bits_per_pixel"] == 16
        assert pf["depth"] == 15
        assert pf["red_max"] == 31
        assert pf["green_max"] == 31
        assert pf["blue_max"] == 31
        assert pf["red_shift"] == 10
        assert pf["green_shift"] == 5
        assert pf["blue_shift"] == 0

    def test_aten_extra_bytes(self):
        data = _make_server_init_bytes(
            aten_unknown=b"\xDE\xAD\xBE\xEF\xCA\xFE\xBA\xBE",
            ikvm_video=1, ikvm_km=0, ikvm_kick=1, vusb=0,
        )
        info = parse_server_init(data)
        assert info["aten_unknown"] == b"\xDE\xAD\xBE\xEF\xCA\xFE\xBA\xBE"
        assert info["ikvm_video_enable"] == 1
        assert info["ikvm_km_enable"] == 0
        assert info["ikvm_kick_enable"] == 1
        assert info["vusb_enable"] == 0

    def test_empty_name(self):
        data = _make_server_init_bytes(name=b"")
        info = parse_server_init(data)
        assert info["name_text"] == b""
        assert info["name_length"] == 0

    def test_too_short_raises(self):
        with pytest.raises(ValueError):
            parse_server_init(b"\x00" * 10)

    def test_name_overflow_raises(self):
        """If name_length says more bytes than available, must raise."""
        # Build valid header but truncate after the name length field
        data = _make_server_init_bytes(name=b"ATEN")
        # Truncate to 25 bytes (just enough for header + 1 byte of name)
        with pytest.raises(ValueError):
            parse_server_init(data[:25])

    def test_pixel_format_raw_is_16_bytes(self):
        data = _make_server_init_bytes()
        info = parse_server_init(data)
        assert len(info["pixel_format"]["raw"]) == 16


# ---------------------------------------------------------------------------
# parse_rectangle_header
# ---------------------------------------------------------------------------


class TestParseRectangleHeader:
    def _make_rect(
        self, x: int = 0, y: int = 0, w: int = 16, h: int = 16, encoding: int = 0x59
    ) -> bytes:
        return struct.pack(">HHHHi", x, y, w, h, encoding)

    def test_basic_parse(self):
        data = self._make_rect(x=10, y=20, w=100, h=200, encoding=0x57)
        rect = parse_rectangle_header(data)
        assert rect["x"] == 10
        assert rect["y"] == 20
        assert rect["width"] == 100
        assert rect["height"] == 200
        assert rect["raw_encoding"] == 0x57
        assert rect["effective_encoding"] == 0x57

    def test_zero_encoding_remapped_to_0x59(self):
        """RAW (0x00) encoding must be remapped to ATEN_HERMON (0x59) in ATEN mode."""
        data = self._make_rect(encoding=0x00)
        rect = parse_rectangle_header(data)
        assert rect["raw_encoding"] == 0x00
        assert rect["effective_encoding"] == 0x59

    def test_ast2100_encoding_unchanged(self):
        data = self._make_rect(encoding=0x57)
        rect = parse_rectangle_header(data)
        assert rect["effective_encoding"] == 0x57

    def test_hermon_encoding_unchanged(self):
        data = self._make_rect(encoding=0x59)
        rect = parse_rectangle_header(data)
        assert rect["raw_encoding"] == 0x59
        assert rect["effective_encoding"] == 0x59

    def test_negative_encoding_preserved(self):
        data = self._make_rect(encoding=-223)  # DesktopSize pseudo-encoding
        rect = parse_rectangle_header(data)
        assert rect["raw_encoding"] == -223
        assert rect["effective_encoding"] == -223

    def test_wrong_length_raises(self):
        with pytest.raises(ValueError, match="12 bytes"):
            parse_rectangle_header(b"\x00" * 11)

    def test_wrong_length_too_long_raises(self):
        with pytest.raises(ValueError, match="12 bytes"):
            parse_rectangle_header(b"\x00" * 13)

    def test_signed_encoding_s32_negative(self):
        """Encoding field is signed int32; large unsigned looks negative."""
        # 0xFFFFFFFF as s32 = -1
        data = self._make_rect(encoding=-1)
        rect = parse_rectangle_header(data)
        assert rect["raw_encoding"] == -1
        assert rect["effective_encoding"] == -1  # not 0, so no remap


# ---------------------------------------------------------------------------
# build_set_encodings
# ---------------------------------------------------------------------------


class TestBuildSetEncodings:
    def test_message_type_byte(self):
        msg = build_set_encodings([0])
        assert msg[0] == 2

    def test_padding_byte_zero(self):
        msg = build_set_encodings([0])
        assert msg[1] == 0

    def test_num_encodings_big_endian(self):
        encodings = [0x57, 0x59]
        msg = build_set_encodings(encodings)
        (n,) = struct.unpack(">H", msg[2:4])
        assert n == 2

    def test_encoding_values_signed_big_endian(self):
        encodings = [0x57, -260]
        msg = build_set_encodings(encodings)
        (e0, e1) = struct.unpack(">ii", msg[4:12])
        assert e0 == 0x57
        assert e1 == -260

    def test_total_length(self):
        encodings = [1, 2, 3]
        msg = build_set_encodings(encodings)
        # 1 (type) + 1 (pad) + 2 (count) + 4*3 (encodings) = 16
        assert len(msg) == 16

    def test_empty_encodings(self):
        msg = build_set_encodings([])
        assert len(msg) == 4
        (n,) = struct.unpack(">H", msg[2:4])
        assert n == 0

    def test_aten_encodings_constant(self):
        """Smoke test: build from the module constant without error."""
        msg = build_set_encodings(ATEN_ENCODINGS)
        assert msg[0] == 2
        (n,) = struct.unpack(">H", msg[2:4])
        assert n == len(ATEN_ENCODINGS)


# ---------------------------------------------------------------------------
# build_framebuffer_update_request
# ---------------------------------------------------------------------------


class TestBuildFramebufferUpdateRequest:
    def test_message_type_byte(self):
        msg = build_framebuffer_update_request(False, 0, 0, 800, 600)
        assert msg[0] == 3

    def test_non_incremental(self):
        msg = build_framebuffer_update_request(False, 0, 0, 800, 600)
        assert msg[1] == 0

    def test_incremental(self):
        msg = build_framebuffer_update_request(True, 0, 0, 800, 600)
        assert msg[1] == 1

    def test_dimensions_big_endian(self):
        msg = build_framebuffer_update_request(False, 10, 20, 800, 600)
        x, y, w, h = struct.unpack(">HHHH", msg[2:10])
        assert x == 10
        assert y == 20
        assert w == 800
        assert h == 600

    def test_total_length_10(self):
        msg = build_framebuffer_update_request(False, 0, 0, 1920, 1080)
        assert len(msg) == 10

    def test_zero_origin_full_screen(self):
        msg = build_framebuffer_update_request(False, 0, 0, 800, 600)
        _, _, x, y, w, h = struct.unpack(">BBHHHH", msg)
        assert x == 0
        assert y == 0
        assert w == 800
        assert h == 600


# ---------------------------------------------------------------------------
# Constants sanity checks
# ---------------------------------------------------------------------------


class TestConstants:
    def test_aten_extra_message_skip_keys(self):
        expected_keys = {4, 22, 51, 55, 57, 60}
        assert set(ATEN_EXTRA_MESSAGE_SKIP.keys()) == expected_keys

    def test_aten_extra_message_skip_values(self):
        assert ATEN_EXTRA_MESSAGE_SKIP[4] == 20
        assert ATEN_EXTRA_MESSAGE_SKIP[22] == 1
        assert ATEN_EXTRA_MESSAGE_SKIP[51] == 4
        assert ATEN_EXTRA_MESSAGE_SKIP[55] == 2
        assert ATEN_EXTRA_MESSAGE_SKIP[57] == 264
        assert ATEN_EXTRA_MESSAGE_SKIP[60] == 8

    def test_aten_encodings_contains_aten_types(self):
        assert 0x57 in ATEN_ENCODINGS  # ATEN_AST2100
        assert 0x58 in ATEN_ENCODINGS  # ATEN_ASTJPEG
        assert 0x59 in ATEN_ENCODINGS  # ATEN_HERMON

    def test_aten_credential_len(self):
        assert ATEN_CREDENTIAL_LEN == 24
