# Milestone 0 — Feasibility Spike Result

> Verdict: **PASS.** The protocol-transcoder architecture is viable. Proceed to M1.
> Date: 2026-06-12. Test board: Supermicro BMC `10.239.251.3` (HTML5 iKVM).

## 1. Summary

The full upstream authentication path was proven end-to-end against the real board:

```
web login (SID cookie)
  -> Redfish IKVM launch -> per-launch session token (entry_value)
  -> wss://<bmc>/ (SID cookie)
  -> RFB handshake: echo "RFB 055.008" -> select security type 16
  -> 24-byte opaque challenge -> send token[24] + zero[24]
  -> SecurityResult = 0 (OK)
  -> ClientInit -> ServerInit -> SetEncodings -> FramebufferUpdateRequest
  -> absorb message type 57 -> FramebufferUpdate rect: 1024x768, encoding 0x57
```

Success criteria (all met):
- SecurityResult == 0 on the WSS transport.
- ServerInit parsed (name = `ATEN iKVM Server`).
- First FramebufferUpdate rectangle captured: encoding `0x57` (ATEN_AST2100).
- Raw bytes dumped for the M1 codec work (`captures/m0_ws_insyde_token.bin`, 4471 bytes; git-ignored).

## 2. Corrections to REQUIREMENTS.md (verified against the board)

The previous recon hypotheses in REQUIREMENTS.md were partly wrong. Ground truth was
obtained by fetching the board's OWN served HTML5 client (Redfish `.IKVM` page +
`/novnc/include/rfb.js` + `/novnc/include/nav_ui.js`) and reading its auth code.

1. **Auth is InsydeVNC, not ATEN.** The served `rfb.js` sets `_nuvoton_chip = true` and
   routes security type 16 to `_negotiate_insyde_auth`, not an ATEN handler. That function:
   - reads a 24-byte challenge (discarded),
   - sends `username[24]` (NUL-padded) followed by 24 zero bytes,
   - **does not send the password at all** (`strPassword` is declared but unused).
   So the wire credential block is `username[24] + zero[24]`, 48 bytes total.

2. **The credential is a per-launch session token, NOT the BMC username/password and NOT
   the SID.** `nav_ui.js` sets `username = password = $("#entry_value").value`. The
   `entry_value` is a hidden input (a ~24-char base64 token) embedded in the console HTML
   that the Redfish OEM IKVM endpoint generates per launch. This token goes in the 24-byte
   username field. Earlier attempts failed because they sent the BMC user/pass or the SID.

3. **Version echo must be verbatim `RFB 055.008\n`.** REQUIREMENTS.md §4.2 was correct on
   this point: echoing `RFB 003.008\n` makes the server close immediately after the version
   exchange (confirmed live). The go-rfb / chicken-aten-ikvm / aten-proxy convention of
   downgrading to `003.008` does **not** apply to this firmware; the board's own client
   handles `055.008` natively (`case "055.008": this._rfb_version = 55.8`).

4. **Two different auth contexts.** The Redfish IKVM endpoint and the `.IKVM` page are
   authenticated by **HTTP Basic** (or `X-Auth-Token`); the WebSocket is authenticated by
   the **SID cookie** from web login. Both are needed.

5. **The 24-byte "opaque block" handling is incidental.** The go-rfb tunnels/magic-gate
   logic (read 4-byte `nt`; because `nt > 0x1000000` read 20 more) happens to consume the
   same 24 bytes that InsydeVNC reads flat as its challenge. Byte alignment is correct
   either way; the block is discarded.

## 3. Captured evidence (from `captures/m0_ws_insyde_token.bin`)

| Field | Value |
|---|---|
| Banner | `RFB 055.008\n` |
| Security types | `[0x10]` |
| 24-byte challenge | `70044075 be8aaf7e 00000000 bcbd0100 700d4075 e81c0300` (varies per connection; leaked uninitialized memory) |
| SecurityResult | `0` (OK) |
| ServerInit dims | advertises `480x640`, bpp 32, depth 24, truecolour, rgbmax 255/255/255, shifts 16/8/0 |
| ServerInit name | `ATEN iKVM Server` (16 bytes) |
| ServerInit +12 ATEN extra | `00000000 5dfd43d0` (8 unknown) + `01 01 01 01` (IKVMVideo/KM/Kick/VUSB all enabled) |
| Extra message before video | type `57` (skip 264) absorbed |
| First rectangle | x=0 y=0 **w=1024 h=768 encoding=0x57** (ATEN_AST2100) |
| First payload bytes | `00000000 0000400c 04 07 01a6 ...` (AST2100 header: quant selectors + `0x01A6` = 422 subsampling field) |

Note the dimension discrepancy: ServerInit advertises `480x640` but the real framebuffer
rectangle is `1024x768`. M1 must trust the rectangle / DesktopSize, not the ServerInit
dimensions, and must override the advertised 32-bit truecolour with RGB555 per the codec.

## 4. Implications for M1+

- The upstream client must: HTTP Basic -> Redfish IKVM -> `.IKVM` page -> scrape
  `entry_value`; web login -> SID; WSS with SID cookie; echo `055.008`; select 0x10; read
  24-byte challenge; send `token[24] + zero[24]`; read SecurityResult.
- The session token is **per-launch and short-lived** — fetch it fresh for every console
  session.
- Video codec is **ATEN AST2100 (0x57)** despite the InsydeVNC auth — the kelleyk
  `core/ast2100/` port plan in REQUIREMENTS.md §6 still applies. The board also serves
  `ast2100.js`, `display.js`, `input.js`, `keysym.js` under `/novnc/include/` — usable as
  decoder/input references (same origin as the kelleyk fork lineage).
- Extra server->client message types are real (type 57 observed); the absorption table is
  needed before the first FramebufferUpdate.

## 5. Reproduce

```
uv run pytest -q                 # 55 unit tests for the pure byte-layout helpers
uv run python -m spike.m0_probe  # live probe against the host in ./secret (3 lines)
```

The probe never logs or captures the password, SID, or session token (all `[REDACTED]`);
capture files contain only server-received bytes.
