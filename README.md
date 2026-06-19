# ikvm-gateway

A standalone transcoding proxy that bridges a **Supermicro HTML5 iKVM** console
(the proprietary Nuvoton/InsydeVNC protocol with an ATEN **AST2100** video codec)
to a **standard RFB/VNC stream over WebSocket**, so any stock **noVNC** client can
view and control the BMC console. Credentials never reach the browser.

```
[noVNC browser] <-- standard RFB 3.8 over WS, security None (our origin) --> [ikvm-gateway]
                                                                                   |
                                          InsydeVNC over WSS (SID cookie + token) / TLS
                                                                                   v
                                                                          [Supermicro BMC]
```

## How it works

1. **Upstream (`src/ikvm_gateway/upstream/`)** — authenticates to the BMC
   (web login -> SID cookie; Redfish OEM IKVM launch -> per-session `entry_value`
   token), opens `wss://<bmc>/`, completes the InsydeVNC type-16 handshake
   (echo `RFB 055.008`, security type `0x10`, send `token[24] + zero[24]`), then
   decodes each `0x57` AST2100 rectangle into an RGB framebuffer.
2. **Decoder (`rust/`, shipped as `ikvm_gateway._ast2100`)** — the AST2100 codec,
   implemented in Rust (PyO3), reimplemented from the board's own served decoder.
   Full-frame decode is ~1-3 ms. It is bundled into the same wheel as the Python
   package.
3. **Downstream (`src/ikvm_gateway/downstream/`)** — a standard RFB 3.8 server
   offering **security None**, serving the framebuffer as Raw over a binary
   WebSocket. Stock noVNC connects directly.
4. **Input (`src/ikvm_gateway/input/`)** — translates RFB key/pointer events
   (X11 keysyms) into ATEN HID KeyEvent/PointerEvent messages.

## Install

From PyPI (prebuilt wheels bundle the native decoder; no Rust toolchain needed):

```bash
pip install ikvm-gateway
```

For development, requires Python >= 3.12, [uv](https://docs.astral.sh/uv/), and a
Rust toolchain. The project builds as a single maturin mixed Rust/Python wheel:

```bash
uv sync
# build the Rust decoder into the venv (reads ./pyproject.toml + ./Cargo.toml)
VIRTUAL_ENV="$PWD/.venv" uv run maturin develop
```

## Run

Provide BMC credentials in a local `secret` file (git-ignored), three lines:

```
<bmc-host-or-ip>
<bmc-username>
<bmc-password>
```

Start the gateway (it prints a generated control API key to stderr):

```bash
uv run python -m ikvm_gateway --secret secret --bind-host 127.0.0.1 --bind-port 5700
```

## Use from noVNC

### Turnkey local viewer

```bash
uv run python -m tools.launch_viewer --api-key <key-printed-by-the-gateway>
# then open the printed http://127.0.0.1:8800/ URL in a browser
```

### Manual integration

The downstream is plain RFB 3.8 (security None) over a binary WebSocket, so
unmodified noVNC works. The one-time session ticket is presented via the
WebSocket subprotocol:

1. Server-side (never in the browser), fetch a ticket with the API key:
   ```
   GET http://<gateway>/sessions
   Authorization: Bearer <API_KEY>
   -> {"status":200,"message":"session ticket issued","data":{"ticket":"<ticket>"}}
   ```
2. Connect noVNC, passing the ticket as a WebSocket subprotocol:
   ```js
   new RFB(document.getElementById("screen"), "ws://<gateway>/vnc", {
     wsProtocols: ["<ticket>"],
   });
   ```

## Security model (per REQUIREMENTS.md §8)

- BMC credentials and the session token **never** reach the browser; the gateway
  terminates upstream auth and offers RFB security **None** downstream.
- The BMC host is **fixed from server configuration** (the `secret` file / config),
  never taken from a client request — no SSRF.
- The downstream control endpoint requires a **bearer API key** (constant-time
  compared). It issues **one-time, short-TTL tickets**; the ticket is consumed on
  the WebSocket handshake and never appears in a URL, query string, or log.
- Per-session and global concurrency caps, idle and max-duration timeouts, and
  send-side backpressure are enforced.
- Upstream TLS to the BMC uses an unverified context (self-signed BMC certs are
  the norm; the management network is the trust boundary).

## Status and limitations (v1)

- Verified end-to-end against a live Supermicro AST2500/2600 board: the console
  renders in a standard RFB client and keyboard input reaches the host.
- The decoder is **stateless**, so the upstream requests **full** (non-incremental)
  frames each refresh (a full AST2100 frame decodes in ~1-3 ms). Making the
  decoder stateful to support incremental/skip blocks is a planned optimization.
- Downstream encoding is **Raw** only; Tight/ZRLE is a planned optimization to cut
  bandwidth.
- Only the Supermicro HTML5 / AST2100 (`0x57`) path is implemented; the VQ /
  low-JPEG / skip block paths in the decoder are ported but not yet exercised on
  the wire.

## Tests

```bash
uv run pytest -q     # Python
cargo test           # Rust decoder
```

## Release

Tagging a version (e.g. `git tag v0.1.0 && git push --tags`) triggers
`.github/workflows/pypi.yaml`, which builds abi3 wheels (Linux x86_64/aarch64,
macOS x86_64/arm64, Windows x64) plus an sdist and publishes to PyPI via Trusted
Publishing (OIDC) — register the repo as a Trusted Publisher for the
`ikvm-gateway` project on PyPI first (environment `pypi`).

## License

GNU Lesser General Public License v3.0 or later (LGPL-3.0-or-later). See
[`COPYING.LESSER`](COPYING.LESSER) (LGPL terms) and [`COPYING`](COPYING) (the
GPL-3.0 text the LGPL builds on).

noVNC is loaded unmodified from a CDN at runtime and is not redistributed here
(noVNC is MPL-2.0).
