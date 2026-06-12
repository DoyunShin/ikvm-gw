# ikvm-gateway — Requirements

> Status: DRAFT for a fresh implementation session. This document is self-contained:
> it captures every fact, decision, and reference gathered so far so the next session
> needs no prior context. Read it top to bottom before writing code.

## 1. Purpose

A **standalone, reusable** service/library that connects to a vendor BMC's **graphical
remote console** (KVM-over-IP) and re-exposes it as a **standard RFB (VNC) stream over
WebSocket**, so that any stock VNC/noVNC client can display it (video + keyboard + mouse).

The hard target is **Supermicro's modern HTML5 iKVM** (ASPEED AST2500/AST2600 BMCs),
whose console is a *proprietary ATEN protocol* that stock noVNC cannot render and whose
web UI cannot be iframed. The gateway terminates the vendor protocol server-side and
speaks plain RFB to the browser.

It is built as its own project ("anyone can use it"), and **Maru includes it** (the Maru
`kvm` plugin gains a driver that proxies to this gateway). It must work standalone too
(point any VNC client at it).

## 2. Why this is a separate project

- The work is large and vendor-protocol-specific (reverse-engineered ATEN codec + auth).
- It is independently useful (a Supermicro-HTML5-iKVM → VNC bridge has no maintained
  open-source equivalent; see §7).
- Keeping it out of the Maru monorepo keeps Maru's plugin thin and lets the gateway
  evolve / be reused on its own cadence.

## 3. Background — what is already solved vs. what this project solves

Maru already has a `kvm` plugin (merged) that embeds **standard-RFB** BMC consoles in the
Maru UI via noVNC, with a backend WebSocket proxy that **terminates the RFB security
handshake** (the BMC VNC password never reaches the browser), one-time WS tickets, and
SSRF-safe targeting. **Dell iDRAC works end-to-end today** (enable iDRAC VNC server, plain
RFB 003.008 + VNC Authentication on port 5901; verified live: framebuffer streamed to
noVNC). Generic standard-VNC BMCs work too.

**What does NOT work and motivates this project: Supermicro.** Supermicro's iKVM is the
proprietary **ATEN** protocol, not standard RFB. Stock noVNC + a byte-splice proxy cannot
display it. This gateway is the bridge that makes Supermicro (and potentially other
proprietary BMC consoles) show up as standard VNC.

## 4. Established protocol facts (Supermicro, verified against a real board)

Test board: Supermicro BMC at `10.239.251.3`, creds in `~/maru/tmp/test-targets.env`
(`TEST_TARGET_1_*`, user `elice`). It is the **HTML5 iKVM** generation (legacy Java
endpoints `/cgi/url_redirect.cgi?url_name=man_ikvm`, `/cgi/ikvm/ikvm.jnlp`,
`/cgi/CapMjpeg.cgi` all 404).

### 4.1 Transport (two listeners, same ATEN payload)
- **Raw TCP 5900 is TLS-from-start.** Plain connect yields no banner until a TLS
  ClientHello. After TLS: banner `RFB 055.008\n`.
- **Modern HTML5 path = WebSocket.** Browser opens `wss://<bmc>/` (root path),
  `Sec-WebSocket-Version: 13`, **no subprotocol**, authenticated **only by the `SID`
  cookie** from web login. (Primary source: real packet capture in
  https://github.com/caddyserver/caddy/issues/3778 .) The bytes inside the WS frames are
  the **same ATEN RFB protocol** (RFB 055.008, security-type 16), just tunneled over WS.
- Self-signed BMC TLS cert (use an unverified TLS context). Note 2025 reports that 5900
  may require a TLS client cert on some firmware (error 40) — verify on the target.
- The BMC web UI sends `X-Frame-Options: SAMEORIGIN`, so **iframing the BMC console is
  impossible** — this gateway (re-serving as our own-origin VNC) is the way around it.

### 4.2 Handshake / auth (ATEN security-type 16)
Observed: server sends `RFB 055.008\n`; client must **echo the exact same 12 bytes**
(sending `RFB 003.008` makes the server send 0 bytes). Then server sends `\x01\x10`
(1 security type, type 16). Client selects `\x10`. Server then sends a **24-byte opaque
block** (treated as discardable by all known clients; example bytes:
`4006a074be8aaf7e00000000bcbd0100c80ca074e81c0300`).

Auth credential block (CONFIRMED layout): **`username[24]` + `password[24]`, NUL-padded,
48 bytes total, plaintext** (TLS protects it). SecurityResult = standard 4-byte u32,
`0` = OK.

**IMPORTANT — what failed and the likely fix:** sending raw `username/password` OR the
web-login `SID` in those slots over **raw 5900** caused the server to immediately close.
Per flameeyes (2012), type-16 wants the **web-login `SID` placed in BOTH 24-byte slots**,
not a static password — and the value rotates per web session. The modern firmware also
has a **pre-auth step and an `aten1` variant** (a TightVNC-style "tunnels" read + a magic
gate `(nt & 0xffff0ff0) == 0xaff90fb0` that skips 20 bytes) — see
https://github.com/unistack-org/go-rfb/blob/master/security_aten.go (the cleanest auth
reference). The earlier attempts omitted the tunnels pre-step AND used raw 5900 instead of
the WSS-on-`/` + SID-cookie transport the real client uses. **The correct flow has not yet
been attempted** — proving it is Milestone 0 (§9).

Auth flow to attempt:
1. `POST https://<bmc>/cgi/login.cgi` with `name=&pwd=` → capture `SID` cookie. (Verified
   working: returns `Set-Cookie: SID=...`.)
2. `websockets.connect("wss://<bmc>/", ssl=<unverified>, additional_headers={"Cookie":
   "SID=<sid>"})`.
3. Over the WS, do the ATEN RFB handshake per go-rfb `security_aten.go`: version echo →
   read security types → select 16 → handle the tunnels/aten1 pre-step + 24-byte block →
   send `SID[24]+SID[24]` → read SecurityResult.
4. ClientInit → ServerInit (NOTE: ATEN ServerInit has **+12 extra bytes**: 8 unknown + 4
   capability flags) → then framebuffer.

Also available as a launch helper: `GET /redfish/v1/Managers/1/Oem/Supermicro/IKVM`
returns `{"URI": "/redfish/<random>.IKVM"}` (verified live). This is the documented
HTML5-console launch; opening `https://<bmc><URI>` serves the BMC's own HTML5 app. The
Redfish session is auth'd by Basic or `X-Auth-Token`.

### 4.3 Post-auth video = proprietary ATEN codec (the real work)
After auth the stream is NOT standard RFB:
- **Pixel format is RGB555** (15-bit), even though ServerInit advertises ~32-bit truecolor
  (a lie the client must override).
- **Encodings** are ATEN-proprietary, not Raw/Tight/Hextile/ZRLE:
  `0x57 ATEN_AST2100`, `0x58 ATEN_ASTJPEG`, `0x59 ATEN_HERMON`, `0x60 ATEN_YARKON`,
  `0x61 ATEN_PILOT3`; plus a remap where a `0x00` rectangle header means `0x59`.
- The AST2100/Hermon codec is a **JPEG-like scheme**: 4-byte header (quant-table selectors
  + 4:4:4 / 4:2:0 subsampling), then MCU blocks (8×8 in 4:4:4, 16×16 in 4:2:0) tagged by a
  4-bit flag — DCT blocks (AAN fast IDCT, YCbCr, Huffman) and vector-quantization blocks,
  `0x9` = end-of-frame. Older boards use simpler 16×16 RGB555 subrect tiles.
- **Extra server→client message types** beyond 0–3: 4 (skip 20), 22 (skip 1), 51 (skip 4),
  55 (skip 2), 57 (skip 264), 60 (skip 8).
- **Input** uses ATEN-custom KeyEvent (type 4, 18-byte) / PointerEvent (type 5, 18-byte)
  with **HID usage codes**, not X11 keysyms.

## 5. Architecture (DECISION: protocol transcoder)

User chose the **transcoding proxy** over the headless-browser approach.

```
[noVNC browser]  <-- standard RFB over WS (security None, our origin) -->  [ikvm-gateway]
                                                                                |
                                            ATEN-over-WSS (SID cookie) / TLS-5900
                                                                                v
                                                                       [Supermicro BMC]
```

The gateway:
1. **ATEN client (upstream):** WSS to `wss://<bmc>/` with injected SID (creds never leave
   the gateway), ATEN type-16 auth, parse ATEN ServerInit (+12), RGB555, decode 0x57/0x59
   frames into a raw framebuffer, absorb message types 4/22/51/55/57/60.
2. **RFB server (downstream):** standard RFB 3.8, offer security **None** (browser never
   sees BMC creds — preserves Maru's security model), real dimensions + standard pixel
   format, encode framebuffer as **Raw or Tight/ZRLE**, serve over WebSocket (binary) so
   noVNC connects directly.
3. **Input translation:** standard RFB KeyEvent/PointerEvent (X11 keysyms) → ATEN HID
   usage codes + ATEN input messages → BMC.

Fallback (only if the transcoder auth proves intractable on AST2600): **headless-browser
proxy** (Chromium loads the Redfish `.IKVM` URL with backend-injected SID, x11vnc captures,
serve to stock noVNC). Proven in production by OpenStack Ironic graphical-console and
`sciapp/nojava-ipmi-kvm`. Heavier per-session (container + CPU) but sidesteps auth + codec.
Keep this in the back pocket; do not build unless Milestone 0 fails.

## 6. Reusable references (do not reinvent)

| Piece | Reference | License | Use |
|---|---|---|---|
| ATEN type-16 auth byte layout (+ tunnels/aten1) | `unistack-org/go-rfb` `security_aten.go` | (check) | Port the auth exactly |
| ATEN 0x57/0x59 codec decoder | `kelleyk/noVNC` branch `bmc-support`, `core/ast2100/` | MPL-2.0 | Port decoder to Python (MPL ok) |
| ATEN→standard-RFB transcoder (legacy) | `thefloweringash/aten-proxy` (C++/LibVNCServer) | GPL | Decoder reference only — GPL would infect if linked; do NOT link, only learn |
| ATEN Mac client / 24-byte "unknown" field | `thefloweringash/chicken-aten-ikvm` | — | Decoder + lens reference |
| WS transport + SID-cookie capture | `caddyserver/caddy#3778` | — | Exact WS handshake |
| Original auth RE (SID in user+pass) | flameeyes.blog 2012-07-03 | — | Auth concept |
| Headless-browser fallback pattern | OpenStack Ironic graphical-console spec; `sciapp/nojava-ipmi-kvm` | Apache | Fallback architecture |
| Redfish OEM IKVM launch | Supermicro Redfish Reference Guide | — | `.IKVM` URI launch |

## 7. Prior art verdict
- No maintained open-source project transcodes the **modern (AST2600 + WS) Supermicro
  HTML5** console as a protocol. `aten-proxy` is X9-era, no WS/TLS/modern-auth.
- The **headless-browser** approach IS done (Ironic, nojava-ipmi-kvm, HOSTKEY prod).
- So this project's novel contribution = a clean, modern, reusable ATEN-HTML5 → RFB gateway.

## 8. Security requirements (carry over from Maru kvm plugin — NON-NEGOTIABLE)
- BMC creds (or SID) **never** reach the browser. The gateway terminates upstream auth and
  offers RFB security **None** downstream.
- The gateway connects ONLY to a configured/allowed BMC host (no client-supplied host/port
  → SSRF). When fronted by Maru, Maru passes the node's stored BMC IP.
- One-time, short-TTL session ticket for the downstream WS (mirror the kvm plugin's
  `Sec-WebSocket-Protocol` ticket pattern; no token in URL/logs).
- Per-session/concurrency caps, idle + max-duration timeouts, bounded buffering
  (backpressure), audit log of who opened which console.
- Upstream TLS to the BMC uses an unverified context (self-signed BMC certs are the norm);
  document this as an anti-eavesdrop-only trust assumption (management network trusted).

## 9. Milestones

**M0 — Feasibility spike (DO THIS FIRST, before any codec work).**
Prove the transcoder auth path on the real board: web login → SID → `wss://10.239.251.3/`
with SID cookie → ATEN type-16 auth (go-rfb style, with tunnels/aten1 pre-step) → reach
**SecurityResult OK → ServerInit → request a FramebufferUpdate → capture one frame's
encoding header (expect 0x57/0x59)**. Dump the raw bytes for the codec work.
- PASS → commit to the transcoder (M1+).
- FAIL (auth intractable) → switch to the headless-browser fallback (§5) and re-plan.
- A starting harness exists from the previous session's recon (read-only scripts that did
  TLS-5900 + web login + Redfish `.IKVM`); adapt them to the WSS-on-`/` transport.

**M1 — ATEN client (upstream):** WSS transport, auth, ATEN ServerInit, message-type
absorption, RGB555. Decode 0x57/0x59 into a raw RGB framebuffer (port kelleyk `ast2100`).
Validate by saving decoded frames as PNG and eyeballing the BIOS/POST screen.

**M2 — RFB server (downstream):** standard RFB 3.8 over WS, security None, serve decoded
framebuffer as Raw (then optimize to Tight/ZRLE). Connect stock noVNC, confirm video.

**M3 — Input:** translate RFB key/pointer → ATEN HID; confirm keyboard + mouse control.

**M4 — Packaging:** standalone runnable (Docker + CLI), config (BMC host/creds source),
the security controls of §8. Publish interface for Maru integration (§10).

**M5 — Maru integration:** Maru `kvm` plugin gets a `supermicro-html5` driver that, instead
of the direct RFB proxy, points the console WS at the gateway (passing node BMC IP + creds
server-side). The kvm plugin's frontend/noVNC is unchanged.

## 10. Maru integration contract (target)
- Gateway exposes: a downstream RFB-over-WS endpoint (security None) reachable by noVNC, and
  an admin/control call to start a session for `{bmc_host, credential_ref}` returning a
  one-time ticket. Exact shape: TBD in M4, but mirror the kvm plugin's
  `POST .../sessions` (ticket) + `WS .../vnc` (Sec-WebSocket-Protocol ticket) contract so
  the Maru frontend reuses its existing VncViewer with a different WS URL.
- Maru runs the gateway as a sidecar/dependency (pip package or Docker service in
  `compose.yaml`). Decide pip-vs-container in M4 (container is simpler given numpy/codec).
- Maru's kvm `drivers.py` adds driver `supermicro-html5` (detect: manufacturer Supermicro
  AND HTML5 iKVM / Redfish OEM IKVM present) → mode that routes to the gateway.

## 11. Tech stack (suggested)
- Python 3.13, asyncio. `websockets` (client to BMC + server to noVNC). `numpy` for the
  IDCT/colorspace/codec hot path (decode in a thread/process executor to avoid blocking the
  loop). Standard library `ssl` (unverified context upstream). Follow the user's Python /
  FastAPI / clean-code rules (type annotations, docstrings, `{action}_{name}` naming,
  `prompt_toolkit` for any logging, no `print`, no emoji).
- Performance: throttle FramebufferUpdateRequest cadence; consider Tight/ZRLE downstream to
  cut bandwidth (Raw 1024×768×4 ≈ 3 MB/frame).

## 12. Non-goals (v1)
- Vendors other than Supermicro HTML5/ATEN (Dell iDRAC + generic standard-VNC already work
  in Maru directly; iLO etc. = deep-link).
- Virtual media (ISO mount), session recording, multi-user view-sharing.
- AST2400/X8/X9 legacy boards unless trivially covered by the same decoder.

## 13. Open questions / risks
- Does WSS-on-`/` + SID + go-rfb-style type-16 auth actually pass on AST2500/2600? (M0
  answers this; it is the single biggest risk.)
- Exact `aten1` tunnels pre-step bytes on `RFB 055.008` firmware (go-rfb is the reference;
  may still need a Wireshark diff against a working browser session).
- Codec correctness (Hermon VQ blocks, chroma subsampling) — only one test board; AST2600
  wire format unconfirmed in public sources.
- Possible TLS client-cert requirement on port 5900 (does the WSS-on-`/` path avoid it?).
- Per-frame decode+re-encode CPU cost in Python (may need numpy / native accel).

## 14. Test assets
- Real board: Supermicro `10.239.251.3` (HTML5 iKVM), creds in `~/maru/tmp/test-targets.env`.
- Dell `10.239.251.4` is standard-RFB (already works in Maru) — useful as a sanity control,
  not a target here.
- Previous-session recon scripts (TLS-5900 handshake mapping, web login, Redfish `.IKVM`,
  ATEN auth attempts) are in the Claude job tmp dir; re-create as needed — they are
  read-only and safe to re-run.
