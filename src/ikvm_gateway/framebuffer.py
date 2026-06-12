"""Shared FramebufferSource Protocol contract.

Both upstream clients and downstream adapters must satisfy this interface.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class FramebufferSource(Protocol):
    """Protocol satisfied by any upstream iKVM framebuffer source.

    Implementors must maintain an internal RGB888 buffer that is updated
    asynchronously.  snapshot_rgb() returns a consistent copy; the caller
    must not assume the returned bytes stay valid after the next update.
    """

    @property
    def width(self) -> int:
        """Current framebuffer width in pixels."""
        ...

    @property
    def height(self) -> int:
        """Current framebuffer height in pixels."""
        ...

    def snapshot_rgb(self) -> bytes:
        """Return the current framebuffer as RGB888 row-major bytes.

        The returned buffer has length ``width * height * 3``.  Pixels are
        stored left-to-right, top-to-bottom; each pixel is three consecutive
        bytes (R, G, B) with no padding or alignment.

        Returns:
            rgb (bytes): Row-major RGB888 snapshot, length ``width*height*3``.
        """
        ...

    async def send_pointer_event(
        self, x: int, y: int, button_mask: int
    ) -> None:
        """Send a pointer (mouse) event to the upstream BMC.

        Args:
            x (int): Horizontal cursor position in framebuffer coordinates.
            y (int): Vertical cursor position in framebuffer coordinates.
            button_mask (int): Bitmask of pressed buttons.
                bit 0 = left button
                bit 1 = middle button
                bit 2 = right button
        """
        ...

    async def send_key_event(self, keysym: int, down: bool) -> None:
        """Send a keyboard event to the upstream BMC.

        Args:
            keysym (int): X11 keysym value (e.g. 0x61 = 'a', 0xff0d = Return).
            down (bool): True for key-press; False for key-release.
        """
        ...
