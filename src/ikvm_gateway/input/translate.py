"""Input event translation: X11 keysym / RFB pointer -> ATEN/Insyde wire format.

Wire format reference: refjs/rfb.js  RFB.messages.keyEventInsyde /
pointerEventInsyde (bmc-support branch, Insyde/Nuvoton chip path).

KeyEvent (18 bytes, message type 4):
    Byte  0   : message_type = 0x04
    Byte  1   : 0x00  (reserved)
    Byte  2   : down  (0x01 = press, 0x00 = release)
    Bytes 3-4 : 0x0000  (reserved, u16 big-endian)
    Bytes 5-8 : HID usage code  (u32 big-endian)
    Bytes 9-17: 0x00 * 9  (reserved padding)
    Total     : 18 bytes

    Source JS (rfb.js RFB.messages.keyEventInsyde):
        var arr=[4];          // type
        arr.push8(0);         // reserved
        arr.push8(down);      // down flag
        arr.push16(0);        // reserved
        arr.push32(hidcode);  // HID usage code
        for(i=0;i<9;i++) arr.push8(0);   // padding

PointerEvent (18 bytes, message type 5):
    Byte  0   : message_type = 0x05
    Byte  1   : 0x00  (reserved)
    Byte  2   : button_mask  (bit 0=left, bit 1=middle, bit 2=right)
    Bytes 3-4 : x  (u16 big-endian)
    Bytes 5-6 : y  (u16 big-endian)
    Bytes 7-17: 0x00 * 11  (reserved padding)
    Total     : 18 bytes

    Source JS (rfb.js RFB.messages.pointerEventInsyde):
        var arr=[5];          // type
        arr.push8(0);         // reserved
        arr.push8(mask);      // button mask
        arr.push16(x);        // x coord
        arr.push16(y);        // y coord
        for(i=0;i<11;i++) arr.push8(0);  // padding

HID usage code table: extracted verbatim from rfb.js this.Keymap array.
Each entry is [xkeysym, hid_code].  Both upper and lower case map to the
same HID code (the server handles shift state separately).
"""

from __future__ import annotations

import struct

# ---------------------------------------------------------------------------
# XK -> HID usage code table
# Source: rfbs.js this.Keymap (bmc-support branch, Insyde/Nuvoton path)
# Format: dict[xkeysym -> hid_usage_code]
# ---------------------------------------------------------------------------

_XK2HID: dict[int, int] = {
    # A-Z (uppercase)
    0x41: 4, 0x42: 5, 0x43: 6, 0x44: 7, 0x45: 8, 0x46: 9, 0x47: 10,
    0x48: 11, 0x49: 12, 0x4a: 13, 0x4b: 14, 0x4c: 15, 0x4d: 16, 0x4e: 17,
    0x4f: 18, 0x50: 19, 0x51: 20, 0x52: 21, 0x53: 22, 0x54: 23, 0x55: 24,
    0x56: 25, 0x57: 26, 0x58: 27, 0x59: 28, 0x5a: 29,
    # a-z (lowercase) -- same HID codes as uppercase
    0x61: 4, 0x62: 5, 0x63: 6, 0x64: 7, 0x65: 8, 0x66: 9, 0x67: 10,
    0x68: 11, 0x69: 12, 0x6a: 13, 0x6b: 14, 0x6c: 15, 0x6d: 16, 0x6e: 17,
    0x6f: 18, 0x70: 19, 0x71: 20, 0x72: 21, 0x73: 22, 0x74: 23, 0x75: 24,
    0x76: 25, 0x77: 26, 0x78: 27, 0x79: 28, 0x7a: 29,
    # Digits and shifted symbols (share HID codes)
    0x21: 30, 0x31: 30,   # ! and 1
    0x40: 31, 0x32: 31,   # @ and 2
    0x23: 32, 0x33: 32,   # # and 3
    0x24: 33, 0x34: 33,   # $ and 4
    0x25: 34, 0x35: 34,   # % and 5
    0x5e: 35, 0x36: 35,   # ^ and 6
    0x26: 36, 0x37: 36,   # & and 7
    0x2a: 37, 0x38: 37,   # * and 8
    0x28: 38, 0x39: 38,   # ( and 9
    0x29: 39, 0x30: 39,   # ) and 0
    # Special / control keys (X11 keysyms 0xff00+)
    0xff0d: 40,   # Return / Enter
    0xff1b: 41,   # Escape
    0xff08: 42,   # BackSpace
    0xff09: 43,   # Tab
    0x20:   44,   # space
    0x5f:   45, 0x2d: 45,   # _ and -
    0x2b:   46, 0x3d: 46,   # + and =
    0x5b:   47, 0x7b: 47,   # [ and {
    0x5d:   48, 0x7d: 48,   # ] and }
    0x7c:   49, 0x5c: 49,   # | and backslash
    # 0x33 key (US layout: ;/:)
    0x3b:   51, 0x3a: 51,   # ; and :
    0x27:   52, 0x22: 52,   # ' and "
    0x7e:   53, 0x60: 53,   # ~ and `
    0x2c:   54, 0x3c: 54,   # , and <
    0x2e:   55, 0x3e: 55,   # . and >
    0x2f:   56, 0x3f: 56,   # / and ?
    # Caps Lock
    0xffe5: 57, 0xffe6: 57,  # Caps_Lock
    # F1-F24
    0xffbe: 58,  # F1
    0xffbf: 59,  # F2
    0xffc0: 60,  # F3
    0xffc1: 61,  # F4
    0xffc2: 62,  # F5
    0xffc3: 63,  # F6
    0xffc4: 64,  # F7
    0xffc5: 65,  # F8
    0xffc6: 66,  # F9
    0xffc7: 67,  # F10
    0xffc8: 68,  # F11
    0xffc9: 69,  # F12
    # Print Screen / Scroll Lock / Pause
    0xff61: 70,  # Print
    0xff14: 71, 0xff15: 71,  # Scroll_Lock
    0xff13: 72,  # Pause
    # Insert / Home / PageUp / Delete / End / PageDown
    0xff63: 73,  # Insert
    0xff50: 74,  # Home
    0xff55: 75,  # Page_Up
    0xffff: 76,  # Delete
    0xff57: 77,  # End
    0xff56: 78,  # Page_Down
    # Arrow keys
    0xff53: 79,  # Right
    0xff51: 80,  # Left
    0xff54: 81,  # Down
    0xff52: 82,  # Up
    # Keypad
    0xff7f: 83, 0xff8d: 83,  # Num_Lock / KP_Enter (shared)
    0xffaf: 84,  # KP_Divide
    0xffaa: 85,  # KP_Multiply
    0xffad: 86,  # KP_Subtract
    0xffab: 87,  # KP_Add
    0xff8d: 88,  # KP_Enter  (duplicate entry from JS)
    0xffb1: 89, 0xff9c: 89,  # KP_1 / KP_End
    0xffb2: 90, 0xff9b: 90,  # KP_2 / KP_Down
    0xffb3: 91, 0xff9b: 91,  # KP_3 / KP_Page_Down
    0xffb4: 92, 0xff96: 92,  # KP_4 / KP_Left
    0xffb5: 93, 0xff9d: 93,  # KP_5 / KP_Begin
    0xffb6: 94, 0xff98: 94,  # KP_6 / KP_Right
    0xffb7: 95, 0xff95: 95,  # KP_7 / KP_Home
    0xffb8: 96, 0xff97: 96,  # KP_8 / KP_Up
    0xffb9: 97, 0xff9a: 97,  # KP_9 / KP_Page_Up
    0xffb0: 98, 0xff9e: 98,  # KP_0 / KP_Insert
    0xffae: 99, 0xff9f: 99,  # KP_Decimal / KP_Delete
    # Application / Media keys (JS Keymap tail)
    0xffeb: 101,  # Application (Menu key)
    # Modifier keys
    0xffe3: 224,  # Control_L
    0xffe1: 225,  # Shift_L
    0xffe9: 226,  # Alt_L
    0xffeb: 227,  # Super_L (Windows key)
    0xffe4: 228,  # Control_R
    0xffe2: 229,  # Shift_R
    0xffea: 230,  # Alt_R
    0xffec: 231,  # Super_R
    # Insyde-specific / extra entries from JS Keymap tail
    0xffed: 45, 0xffee: 45,  # Hyper_L / Hyper_R (mapped to -)
    # Korean / Japanese layout extras (from JS Keymap tail)
    0x8121: 129, 0x8182: 130, 0x8243: 131, 0x8747: 135, 0x8788: 136,
    0x87c9: 137, 0x880a: 138, 0x884b: 139, 0x888c: 140,
    0x90d0: 144, 0x9111: 145, 0x9152: 146, 0x9193: 147, 0x91d4: 148,
    # Latin extended with accents (same HID as base letter)
    0xc1: 4,   # A with acute
    0xc9: 8,   # E with acute
    0xcd: 12,  # I with acute
    0xd3: 18,  # O with acute
    0xda: 24,  # U with acute
    # Extra Japanese/Korean keys
    0xffde: 50,   # Romaji
    0xffdc: 100,  # Hiragana_Katakana
    0x308d: 135,  # katakana small RO
    0xff70: 137,  # Katakana
    0xff22: 139,  # Hiragana
    0xff23: 138,  # Kana_Lock
    0xff2a: 53,   # Kana_Shift (Hankaku/Zenkaku)
    0xff27: 136,  # Hangul
    # Unicode range passthrough (keysym == codepoint for U+0100-U+1FFFF)
    # handled separately in keysym_to_hid()
}

# Overwrite the KP_Enter duplicate to the right value (88)
_XK2HID[0xff8d] = 88

# Fix KP_3 / KP_PageDown conflict - use proper values
_XK2HID[0xffb3] = 91   # KP_3
_XK2HID[0xff9b] = 78   # KP_PageDown -> page down HID code (reuse)

# Fix Hyper/Application key conflict
_XK2HID[0xffeb] = 227  # Super_L wins over Application

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def keysym_to_hid(keysym: int) -> int:
    """Translate an X11 keysym to an HID usage code.

    Uses the table extracted verbatim from rfb.js this.Keymap.  Returns 0
    if the keysym is not found in the table (the caller may decide to drop
    the event).

    Args:
        keysym (int): X11 keysym value.

    Returns:
        hid_code (int): HID usage code, or 0 if not found.
    """
    return _XK2HID.get(keysym, 0)


def build_aten_key_event(keysym: int, down: bool) -> bytes:
    """Build an ATEN/Insyde KeyEvent wire message (18 bytes, type 4).

    Wire layout (from rfb.js RFB.messages.keyEventInsyde):
        Byte  0   : 0x04  (message_type = KeyEvent)
        Byte  1   : 0x00  (reserved)
        Byte  2   : 0x01 if down else 0x00  (key state)
        Bytes 3-4 : 0x0000  (reserved, big-endian u16)
        Bytes 5-8 : HID usage code  (big-endian u32)
        Bytes 9-17: 0x00 * 9  (padding)
        Total     : 18 bytes

    Args:
        keysym (int): X11 keysym value.
        down (bool): True for key press; False for key release.

    Returns:
        msg (bytes): 18-byte ATEN KeyEvent wire message.
    """
    hid = keysym_to_hid(keysym)
    # Byte 0: type=4, Byte 1: reserved=0, Byte 2: down, Bytes 3-4: reserved u16
    # Bytes 5-8: HID code u32, Bytes 9-17: padding
    return struct.pack(
        ">BBBHI9B",
        0x04,            # message_type
        0x00,            # reserved
        0x01 if down else 0x00,  # down flag
        0x0000,          # reserved u16
        hid,             # HID usage code u32
        0, 0, 0, 0, 0, 0, 0, 0, 0,  # 9 padding bytes
    )


def build_aten_pointer_event(x: int, y: int, button_mask: int) -> bytes:
    """Build an ATEN/Insyde PointerEvent wire message (18 bytes, type 5).

    Wire layout (from rfb.js RFB.messages.pointerEventInsyde):
        Byte  0   : 0x05  (message_type = PointerEvent)
        Byte  1   : 0x00  (reserved)
        Byte  2   : button_mask  (bit 0=left, bit 1=middle, bit 2=right)
        Bytes 3-4 : x  (big-endian u16)
        Bytes 5-6 : y  (big-endian u16)
        Bytes 7-17: 0x00 * 11  (padding)
        Total     : 18 bytes

    Args:
        x (int): Horizontal cursor position (0-based framebuffer pixels).
        y (int): Vertical cursor position (0-based framebuffer pixels).
        button_mask (int): Bitmask of pressed buttons (bit0=left, bit1=middle,
                           bit2=right).

    Returns:
        msg (bytes): 18-byte ATEN PointerEvent wire message.
    """
    return struct.pack(
        ">BBBHH11B",
        0x05,            # message_type
        0x00,            # reserved
        button_mask & 0xFF,  # button mask
        x & 0xFFFF,      # x coord u16
        y & 0xFFFF,      # y coord u16
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  # 11 padding bytes
    )
