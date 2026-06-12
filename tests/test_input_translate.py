"""Unit tests for src/ikvm_gateway/input/translate.py.

All tests are pure byte-level with no live network.
Wire formats verified against refjs/rfb.js RFB.messages.keyEventInsyde /
pointerEventInsyde.
"""

from __future__ import annotations

import struct

import pytest

from ikvm_gateway.input.translate import (
    build_aten_key_event,
    build_aten_pointer_event,
    keysym_to_hid,
)


# ---------------------------------------------------------------------------
# keysym_to_hid
# ---------------------------------------------------------------------------


class TestKeysymToHid:
    def test_lowercase_a(self):
        # XK_a = 0x61, HID Usage ID 4 (Keyboard a and A)
        assert keysym_to_hid(0x61) == 4

    def test_uppercase_a(self):
        # XK_A = 0x41 maps to same HID code 4
        assert keysym_to_hid(0x41) == 4

    def test_lowercase_z(self):
        # XK_z = 0x7a -> HID 29
        assert keysym_to_hid(0x7a) == 29

    def test_uppercase_z(self):
        assert keysym_to_hid(0x5a) == 29

    def test_digit_1(self):
        # XK_1 = 0x31, HID 30 (1 and !)
        assert keysym_to_hid(0x31) == 30

    def test_digit_0(self):
        # XK_0 = 0x30, HID 39 (0 and ))
        assert keysym_to_hid(0x30) == 39

    def test_enter(self):
        # XK_Return = 0xff0d, HID 40
        assert keysym_to_hid(0xff0d) == 40

    def test_escape(self):
        # XK_Escape = 0xff1b, HID 41
        assert keysym_to_hid(0xff1b) == 41

    def test_backspace(self):
        # XK_BackSpace = 0xff08, HID 42
        assert keysym_to_hid(0xff08) == 42

    def test_tab(self):
        # XK_Tab = 0xff09, HID 43
        assert keysym_to_hid(0xff09) == 43

    def test_space(self):
        # XK_space = 0x20, HID 44
        assert keysym_to_hid(0x20) == 44

    def test_f1(self):
        # XK_F1 = 0xffbe, HID 58
        assert keysym_to_hid(0xffbe) == 58

    def test_f12(self):
        # XK_F12 = 0xffc9, HID 69
        assert keysym_to_hid(0xffc9) == 69

    def test_ctrl_l(self):
        # XK_Control_L = 0xffe3, HID 224
        assert keysym_to_hid(0xffe3) == 224

    def test_shift_l(self):
        # XK_Shift_L = 0xffe1, HID 225
        assert keysym_to_hid(0xffe1) == 225

    def test_alt_l(self):
        # XK_Alt_L = 0xffe9, HID 226
        assert keysym_to_hid(0xffe9) == 226

    def test_delete(self):
        # XK_Delete = 0xffff, HID 76
        assert keysym_to_hid(0xffff) == 76

    def test_unknown_keysym_returns_zero(self):
        assert keysym_to_hid(0xDEAD) == 0


# ---------------------------------------------------------------------------
# build_aten_key_event byte layout
# ---------------------------------------------------------------------------


class TestBuildAtenKeyEvent:
    """Verify the 18-byte ATEN KeyEvent wire format.

    Expected layout (from rfb.js RFB.messages.keyEventInsyde):
        Byte  0   : 0x04  (message_type)
        Byte  1   : 0x00  (reserved)
        Byte  2   : 0x01 if down else 0x00
        Bytes 3-4 : 0x0000 (reserved u16 big-endian)
        Bytes 5-8 : HID usage code (u32 big-endian)
        Bytes 9-17: 0x00 * 9 (padding)
    """

    def test_total_length_18(self):
        msg = build_aten_key_event(0x61, True)
        assert len(msg) == 18

    def test_message_type_4(self):
        msg = build_aten_key_event(0x61, True)
        assert msg[0] == 0x04

    def test_reserved_byte1_zero(self):
        msg = build_aten_key_event(0x61, True)
        assert msg[1] == 0x00

    def test_down_flag_press(self):
        msg = build_aten_key_event(0x61, True)
        assert msg[2] == 0x01

    def test_down_flag_release(self):
        msg = build_aten_key_event(0x61, False)
        assert msg[2] == 0x00

    def test_reserved_u16_zero(self):
        msg = build_aten_key_event(0x61, True)
        (reserved_u16,) = struct.unpack(">H", msg[3:5])
        assert reserved_u16 == 0

    def test_hid_code_field(self):
        # XK_a -> HID 4, stored at bytes 5-8 as big-endian u32
        msg = build_aten_key_event(0x61, True)
        (hid,) = struct.unpack(">I", msg[5:9])
        assert hid == 4

    def test_hid_code_enter(self):
        # XK_Return = 0xff0d -> HID 40
        msg = build_aten_key_event(0xff0d, True)
        (hid,) = struct.unpack(">I", msg[5:9])
        assert hid == 40

    def test_hid_code_ctrl(self):
        # XK_Control_L = 0xffe3 -> HID 224
        msg = build_aten_key_event(0xffe3, True)
        (hid,) = struct.unpack(">I", msg[5:9])
        assert hid == 224

    def test_padding_bytes_zero(self):
        # Bytes 9-17 must all be 0x00
        msg = build_aten_key_event(0x61, True)
        assert msg[9:18] == b"\x00" * 9

    def test_exact_bytes_a_press(self):
        # XK_a (0x61) -> HID 4; press
        # Expected: 04 00 01 00 00 00 00 00 04 00 00 00 00 00 00 00 00 00
        msg = build_aten_key_event(0x61, True)
        expected = bytes([
            0x04, 0x00, 0x01,     # type, reserved, down
            0x00, 0x00,           # reserved u16
            0x00, 0x00, 0x00, 0x04,  # HID=4 u32 big-endian
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # padding
        ])
        assert msg == expected

    def test_exact_bytes_enter_release(self):
        # XK_Return (0xff0d) -> HID 40 = 0x28; release
        msg = build_aten_key_event(0xff0d, False)
        expected = bytes([
            0x04, 0x00, 0x00,       # type, reserved, up
            0x00, 0x00,             # reserved u16
            0x00, 0x00, 0x00, 0x28, # HID=40=0x28 u32 big-endian
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ])
        assert msg == expected

    def test_exact_bytes_ctrl_press(self):
        # XK_Control_L (0xffe3) -> HID 224 = 0xe0; press
        msg = build_aten_key_event(0xffe3, True)
        expected = bytes([
            0x04, 0x00, 0x01,
            0x00, 0x00,
            0x00, 0x00, 0x00, 0xe0,  # HID=224=0xe0
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ])
        assert msg == expected


# ---------------------------------------------------------------------------
# build_aten_pointer_event byte layout
# ---------------------------------------------------------------------------


class TestBuildAtenPointerEvent:
    """Verify the 18-byte ATEN PointerEvent wire format.

    Expected layout (from rfb.js RFB.messages.pointerEventInsyde):
        Byte  0   : 0x05  (message_type)
        Byte  1   : 0x00  (reserved)
        Byte  2   : button_mask
        Bytes 3-4 : x (u16 big-endian)
        Bytes 5-6 : y (u16 big-endian)
        Bytes 7-17: 0x00 * 11 (padding)
    """

    def test_total_length_18(self):
        msg = build_aten_pointer_event(0, 0, 0)
        assert len(msg) == 18

    def test_message_type_5(self):
        msg = build_aten_pointer_event(0, 0, 0)
        assert msg[0] == 0x05

    def test_reserved_byte1_zero(self):
        msg = build_aten_pointer_event(100, 200, 1)
        assert msg[1] == 0x00

    def test_button_mask_no_buttons(self):
        msg = build_aten_pointer_event(0, 0, 0)
        assert msg[2] == 0

    def test_button_mask_left(self):
        # bit 0 = left button
        msg = build_aten_pointer_event(0, 0, 0b001)
        assert msg[2] == 1

    def test_button_mask_middle(self):
        # bit 1 = middle button
        msg = build_aten_pointer_event(0, 0, 0b010)
        assert msg[2] == 2

    def test_button_mask_right(self):
        # bit 2 = right button
        msg = build_aten_pointer_event(0, 0, 0b100)
        assert msg[2] == 4

    def test_x_coordinate_big_endian(self):
        msg = build_aten_pointer_event(0x0102, 0, 0)
        (x,) = struct.unpack(">H", msg[3:5])
        assert x == 0x0102

    def test_y_coordinate_big_endian(self):
        msg = build_aten_pointer_event(0, 0x0304, 0)
        (y,) = struct.unpack(">H", msg[5:7])
        assert y == 0x0304

    def test_padding_bytes_zero(self):
        msg = build_aten_pointer_event(100, 200, 1)
        assert msg[7:18] == b"\x00" * 11

    def test_exact_bytes_left_click(self):
        # x=100=0x0064, y=200=0x00c8, button_mask=1 (left)
        msg = build_aten_pointer_event(100, 200, 1)
        expected = bytes([
            0x05, 0x00, 0x01,       # type, reserved, left-button
            0x00, 0x64,             # x=100 big-endian u16
            0x00, 0xc8,             # y=200 big-endian u16
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ])
        assert msg == expected

    def test_exact_bytes_mouse_move_no_button(self):
        # x=512=0x0200, y=384=0x0180, button_mask=0
        msg = build_aten_pointer_event(512, 384, 0)
        expected = bytes([
            0x05, 0x00, 0x00,
            0x02, 0x00,
            0x01, 0x80,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ])
        assert msg == expected

    def test_exact_bytes_right_click(self):
        # x=0, y=0, button_mask=4 (right)
        msg = build_aten_pointer_event(0, 0, 4)
        expected = bytes([
            0x05, 0x00, 0x04,
            0x00, 0x00,
            0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ])
        assert msg == expected
