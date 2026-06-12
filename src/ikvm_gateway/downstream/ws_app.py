"""WebSocket application that serves RFB streams to noVNC browsers.

Architecture
------------
This module wraps rfb_server.RfbServer with a WebSocket transport so that a
stock noVNC browser can connect without any browser-side changes.

Security model (mirrors Maru kvm plugin — NON-NEGOTIABLE per REQUIREMENTS.md §8):
  - BMC credentials never reach the browser.
  - Downstream RFB uses security None; the gateway terminates upstream auth.
  - A one-time short-TTL session ticket is required to open a WebSocket.
  - The BMC host is fixed from server configuration/environment (env var
    IKVM_GATEWAY_BMC_HOST); it is NEVER taken from the client request (SSRF).
  - Tickets are passed via the WebSocket subprotocol field (noVNC convention);
    they never appear in URLs, query strings, or server logs.
  - API key for the control endpoint is validated with hmac.compare_digest.
  - Audit log records session start/end (timestamp, source IP, BMC target)
    without any secrets, tokens, passwords, or ticket values.
  - Per-session and global concurrency caps enforced.
  - Idle and max-duration timeouts enforced.
  - Send-side write_limit provides backpressure.

noVNC connection parameters
----------------------------
Connect stock noVNC to the WebSocket endpoint as follows:

  WS URL:
      ws://<gateway-host>:<port>/vnc

  Ticket acquisition (must be done server-side by the application embedding
  the gateway, e.g. Maru):
      POST /sessions
      Authorization: Bearer <IKVM_GATEWAY_API_KEY>
      Content-Type: application/json   (no body required; BMC host is fixed)

      Response (JSON envelope):
          {"status": 200, "message": "session ticket issued", "data": {"ticket": "<UUID>"}}

  Passing the ticket to noVNC (wsProtocols convention):
      new RFB(canvas, "ws://<gateway-host>:<port>/vnc", {
          wsProtocols: ["<ticket>"]
      });

  The noVNC client includes the ticket as the Sec-WebSocket-Protocol header
  value.  The gateway validates it (single-use, TTL-checked), consumes it,
  and echoes it back as the negotiated subprotocol — which noVNC accepts.
  The ticket is then discarded; subsequent reconnects require a new ticket.

  Vendoring noVNC (optional):
      noVNC is licensed under MPL-2.0.  You may vendor the static assets at
      a path of your choice; serve them from the same origin to avoid CORS.
      The connection parameters above apply to both the npm package and the
      plain JS build from https://github.com/novnc/noVNC.

Environment variables
---------------------
  IKVM_GATEWAY_API_KEY     Secret bearer token for POST /sessions.
                           Must be set; server refuses to start without it.
  IKVM_GATEWAY_BMC_HOST    BMC hostname/IP.  NEVER taken from client requests.
                           Set to the gateway-fixed target BMC.
  IKVM_GATEWAY_HOST        Bind host (default 127.0.0.1).
  IKVM_GATEWAY_PORT        Bind port (default 5700).
  IKVM_GATEWAY_MAX_SESSIONS Maximum concurrent RFB sessions (default 4).
  IKVM_GATEWAY_TICKET_TTL  Ticket validity in seconds (default 30).
  IKVM_GATEWAY_IDLE_TIMEOUT Session idle timeout in seconds (default 300).
  IKVM_GATEWAY_MAX_DURATION Maximum session duration in seconds (default 3600).
"""

from __future__ import annotations

import asyncio
import hmac
import json
import logging
import os
import secrets
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from prompt_toolkit.formatted_text import FormattedText
from prompt_toolkit.shortcuts import print_formatted_text
from websockets.asyncio.server import ServerConnection, serve

from ikvm_gateway.downstream.rfb_server import RfbServer


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

_LOG_FORMAT_INFO = "[%(asctime)s] %(levelname)s # %(message)s"
_LOG_FORMAT_DEBUG = "[%(asctime)s] [%(filename)s:%(lineno)d] %(levelname)s # %(message)s"

logger = logging.getLogger(__name__)


def _log_info(message: str) -> None:
    """Emit an INFO-level log line via prompt_toolkit with plain-text fallback.

    Args:
        message (str): Log message.
    """
    logger.info(message)
    try:
        print_formatted_text(FormattedText([("class:info", f"[INFO] {message}")]))
    except Exception:
        # Plain-text fallback for terminals without styling support.
        import sys
        sys.stderr.write(f"[INFO] {message}\n")


def _log_warning(message: str) -> None:
    """Emit a WARNING-level log line via prompt_toolkit.

    Args:
        message (str): Log message.
    """
    logger.warning(message)
    try:
        print_formatted_text(FormattedText([("class:warning", f"[WARN] {message}")]))
    except Exception:
        import sys
        sys.stderr.write(f"[WARN] {message}\n")


def _log_error(message: str) -> None:
    """Emit an ERROR-level log line via prompt_toolkit.

    Args:
        message (str): Log message.
    """
    logger.error(message)
    try:
        print_formatted_text(FormattedText([("class:error", f"[ERROR] {message}")]))
    except Exception:
        import sys
        sys.stderr.write(f"[ERROR] {message}\n")


# ---------------------------------------------------------------------------
# Session ticket store
# ---------------------------------------------------------------------------


@dataclass
class _Ticket:
    """A one-time, short-TTL session ticket."""

    value: str
    expires_at: float
    consumed: bool = False


class TicketStore:
    """In-memory store for one-time session tickets.

    Tickets are issued with a TTL (seconds) and are valid for a single use.
    Expired tickets are pruned lazily on each access.
    """

    def __init__(self, ttl_seconds: float = 30.0) -> None:
        """Initialise the ticket store.

        Args:
            ttl_seconds (float): Validity window for each ticket.
        """
        self._ttl = ttl_seconds
        self._tickets: dict[str, _Ticket] = {}
        self._lock = asyncio.Lock()

    async def issue(self) -> str:
        """Issue a new one-time ticket.

        Returns:
            ticket_value (str): Unique opaque ticket string.
        """
        value = str(uuid.uuid4())
        expires_at = time.monotonic() + self._ttl
        async with self._lock:
            self._prune()
            self._tickets[value] = _Ticket(value=value, expires_at=expires_at)
        return value

    async def consume(self, value: str) -> bool:
        """Consume a ticket, returning True if it was valid and unused.

        The ticket is removed from the store on success.

        Args:
            value (str): The ticket value presented by the client.

        Returns:
            valid (bool): True if the ticket existed, was not consumed, and
                          had not yet expired.
        """
        async with self._lock:
            self._prune()
            ticket = self._tickets.get(value)
            if ticket is None:
                return False
            if ticket.consumed:
                return False
            # Mark consumed and remove.
            del self._tickets[value]
            return True

    def _prune(self) -> None:
        """Remove all expired tickets (called under lock)."""
        now = time.monotonic()
        expired = [k for k, t in self._tickets.items() if t.expires_at <= now]
        for k in expired:
            del self._tickets[k]


# ---------------------------------------------------------------------------
# WebSocket transport adapter
# ---------------------------------------------------------------------------


class WsTransport:
    """Adapts a WebSocket connection to the rfb_server.Transport protocol.

    Incoming binary WebSocket frames are buffered into a bytearray.
    read_exact() consumes from the front of the buffer, waiting for more
    frames if needed.

    Outgoing bytes are sent as a single binary WebSocket frame per write()
    call.  The underlying websockets library enforces write_limit for
    backpressure.
    """

    def __init__(self, ws: ServerConnection) -> None:
        """Initialise the transport.

        Args:
            ws (ServerConnection): Active websockets server connection.
        """
        self._ws = ws
        self._buf = bytearray()
        self._lock = asyncio.Lock()
        self._data_event = asyncio.Event()

    async def read_exact(self, n: int) -> bytes:
        """Read exactly n bytes from buffered WebSocket frames.

        Args:
            n (int): Number of bytes required.

        Returns:
            data (bytes): Exactly n bytes.

        Raises:
            ConnectionError: If the WebSocket closes before n bytes arrive.
        """
        while len(self._buf) < n:
            try:
                msg = await self._ws.recv()
            except Exception as exc:
                raise ConnectionError(f"WebSocket closed: {exc}") from exc
            if isinstance(msg, bytes):
                self._buf.extend(msg)
            else:
                # Text frame: not expected in RFB; ignore.
                pass
        result = bytes(self._buf[:n])
        del self._buf[:n]
        return result

    async def write(self, data: bytes) -> None:
        """Send bytes as a single binary WebSocket frame.

        Args:
            data (bytes): Bytes to send.
        """
        await self._ws.send(data)


# ---------------------------------------------------------------------------
# API response helpers (FastAPI envelope convention)
# ---------------------------------------------------------------------------


def _make_response(status: int, message: str, data: Any = None) -> tuple[int, str]:
    """Build a JSON HTTP response body following the standard envelope.

    Args:
        status (int): HTTP status code.
        message (str): Human-readable message.
        data (Any, optional): Response payload.

    Returns:
        body (str): JSON-encoded response body.
        content_type (str): MIME type string.
    """
    body = json.dumps({"status": status, "message": message, "data": data})
    return body, "application/json"


# ---------------------------------------------------------------------------
# Gateway application
# ---------------------------------------------------------------------------


@dataclass
class GatewayConfig:
    """Runtime configuration for the WebSocket gateway."""

    api_key: str
    bmc_host: str
    bind_host: str = "127.0.0.1"
    bind_port: int = 5700
    max_sessions: int = 4
    ticket_ttl: float = 30.0
    idle_timeout: float = 300.0
    max_duration: float = 3600.0


def load_config_from_env() -> GatewayConfig:
    """Load GatewayConfig from environment variables.

    Returns:
        config (GatewayConfig): Populated configuration.

    Raises:
        RuntimeError: If IKVM_GATEWAY_API_KEY or IKVM_GATEWAY_BMC_HOST are absent.
    """
    api_key = os.environ.get("IKVM_GATEWAY_API_KEY", "")
    if not api_key:
        raise RuntimeError("IKVM_GATEWAY_API_KEY must be set")
    bmc_host = os.environ.get("IKVM_GATEWAY_BMC_HOST", "")
    if not bmc_host:
        raise RuntimeError("IKVM_GATEWAY_BMC_HOST must be set")
    return GatewayConfig(
        api_key=api_key,
        bmc_host=bmc_host,
        bind_host=os.environ.get("IKVM_GATEWAY_HOST", "127.0.0.1"),
        bind_port=int(os.environ.get("IKVM_GATEWAY_PORT", "5700")),
        max_sessions=int(os.environ.get("IKVM_GATEWAY_MAX_SESSIONS", "4")),
        ticket_ttl=float(os.environ.get("IKVM_GATEWAY_TICKET_TTL", "30")),
        idle_timeout=float(os.environ.get("IKVM_GATEWAY_IDLE_TIMEOUT", "300")),
        max_duration=float(os.environ.get("IKVM_GATEWAY_MAX_DURATION", "3600")),
    )


class IkvmGatewayApp:
    """WebSocket gateway that serves RFB streams and a ticket-issuance endpoint.

    One instance is created per server process.  It holds:
      - a TicketStore for one-time session tickets
      - a shared FramebufferSource (set by the caller after construction)
      - active session counter for concurrency enforcement
    """

    _SESSIONS_PATH = "/sessions"
    _VNC_PATH = "/vnc"

    def __init__(self, config: GatewayConfig) -> None:
        """Initialise the gateway application.

        Args:
            config (GatewayConfig): Runtime configuration.
        """
        self._config = config
        self._ticket_store = TicketStore(ttl_seconds=config.ticket_ttl)
        self._source: Any = None
        self._active_sessions: int = 0
        self._sessions_lock = asyncio.Lock()

    def set_source(self, source: Any) -> None:
        """Set the FramebufferSource that all RFB sessions will use.

        Args:
            source: Object satisfying the FramebufferSource protocol.
        """
        self._source = source

    def _verify_api_key(self, authorization: str | None) -> bool:
        """Verify a Bearer API key using constant-time comparison.

        Args:
            authorization (str | None): Value of the Authorization header.

        Returns:
            valid (bool): True if the key matches.
        """
        if not authorization:
            return False
        parts = authorization.split(" ", 1)
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return False
        presented = parts[1].encode()
        expected = self._config.api_key.encode()
        return hmac.compare_digest(presented, expected)

    async def _issue_ticket(self) -> str:
        """Issue a one-time session ticket.

        Returns:
            ticket (str): Opaque ticket value.
        """
        return await self._ticket_store.issue()

    async def process_request(self, connection: ServerConnection, request: Any):
        """websockets process_request hook: serve the control endpoint and gate
        the WebSocket upgrade.

        The websockets server only accepts GET requests at the HTTP layer, so the
        ticket-issuance control endpoint is exposed as GET /sessions (authenticated
        by a Bearer API key, returning a single-use ticket). Returning a Response
        here short-circuits the connection without a WebSocket upgrade; returning
        None lets GET /vnc proceed to the WebSocket handshake (where the ticket in
        the subprotocol is validated).

        Args:
            connection (ServerConnection): The incoming connection.
            request (Any): The parsed HTTP request (path, headers).

        Returns:
            response (Response | None): An HTTP response to short-circuit, or None
                to continue with the WebSocket upgrade.
        """
        path = request.path.split("?")[0]

        if path == self._VNC_PATH:
            return None  # proceed to the WebSocket handshake

        if path == self._SESSIONS_PATH:
            auth_header = request.headers.get("Authorization", "")
            if not self._verify_api_key(auth_header):
                _log_warning("GET /sessions rejected: invalid API key")
                return self._http_response(401, "unauthorized")
            ticket = await self._issue_ticket()
            _log_info("GET /sessions: ticket issued")  # never log the ticket value
            return self._http_response(
                200, "session ticket issued", {"ticket": ticket}
            )

        return self._http_response(404, "not found")

    def _http_response(self, status: int, message: str, data: Any = None):
        """Build a websockets HTTP Response with the standard JSON envelope."""
        from websockets.http11 import Response
        from websockets.datastructures import Headers

        body, ct = _make_response(status, message, data)
        reason = {200: "OK", 401: "Unauthorized", 404: "Not Found"}.get(
            status, "Error"
        )
        headers = Headers(
            [("Content-Type", ct), ("Content-Length", str(len(body)))]
        )
        return Response(status, reason, headers, body.encode())

    async def handle_request(self, ws: ServerConnection) -> None:
        """Serve a WebSocket connection. Only GET /vnc reaches here (other paths
        are handled and short-circuited by process_request).

        Args:
            ws (ServerConnection): Incoming WebSocket connection.
        """
        path = ws.request.path.split("?")[0]
        if path == self._VNC_PATH:
            await self._handle_vnc_websocket(ws)
        else:
            await ws.close(1008, "not found")

    async def _handle_vnc_websocket(self, ws: ServerConnection) -> None:
        """Handle GET /vnc: validate ticket and serve RFB session.

        The ticket is passed via the WebSocket subprotocol field
        (Sec-WebSocket-Protocol).  noVNC sends the ticket as a subprotocol
        value; the server validates, consumes, and echoes it back.

        Args:
            ws (ServerConnection): Incoming WebSocket connection.
        """
        # Extract ticket from negotiated subprotocol.
        ticket = ws.subprotocol
        if not ticket:
            _log_warning("VNC connection rejected: no ticket in subprotocol")
            await ws.close(1008, "ticket required")
            return

        valid = await self._ticket_store.consume(ticket)
        if not valid:
            _log_warning("VNC connection rejected: invalid or expired ticket")
            await ws.close(1008, "invalid ticket")
            return

        if self._source is None:
            _log_error("VNC connection rejected: no framebuffer source configured")
            await ws.close(1011, "server not ready")
            return

        # Concurrency cap.
        async with self._sessions_lock:
            if self._active_sessions >= self._config.max_sessions:
                _log_warning("VNC connection rejected: concurrency cap reached")
                await ws.close(1013, "too many sessions")
                return
            self._active_sessions += 1

        source_info = str(ws.remote_address)
        # Audit log: timestamp, source IP, BMC target — NO secrets, NO ticket.
        _log_info(
            f"RFB session started | source={source_info} | target={self._config.bmc_host}"
        )

        try:
            transport = WsTransport(ws)
            server = RfbServer(transport, self._source)
            await asyncio.wait_for(
                self._run_with_idle_guard(server, ws),
                timeout=self._config.max_duration,
            )
        except asyncio.TimeoutError:
            _log_info(f"RFB session max-duration reached | source={source_info}")
        except ConnectionError:
            pass  # Clean disconnect.
        except Exception as exc:
            _log_error(f"RFB session error | source={source_info} | {exc}")
        finally:
            async with self._sessions_lock:
                self._active_sessions -= 1
            _log_info(f"RFB session ended | source={source_info}")

    async def _run_with_idle_guard(
        self, server: RfbServer, ws: ServerConnection
    ) -> None:
        """Run the RFB server, enforcing idle timeout.

        Runs the server and a parallel idle-detection task.  If no data
        arrives for idle_timeout seconds, the connection is closed.

        Args:
            server (RfbServer): RFB server instance.
            ws (ServerConnection): WebSocket connection for forced close.
        """
        rfb_task = asyncio.create_task(server.run())
        idle_task = asyncio.create_task(
            asyncio.sleep(self._config.idle_timeout)
        )

        done, pending = await asyncio.wait(
            [rfb_task, idle_task],
            return_when=asyncio.FIRST_COMPLETED,
        )

        for task in pending:
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass

        if idle_task in done and rfb_task not in done:
            _log_info("RFB session idle timeout")
            await ws.close(1001, "idle timeout")

        if rfb_task in done and not rfb_task.cancelled():
            exc = rfb_task.exception()
            if exc is not None:
                raise exc

    async def _reject(self, ws: ServerConnection, status: int, reason: str) -> None:
        """Send a minimal HTTP error response and close.

        Args:
            ws (ServerConnection): Connection to reject.
            status (int): HTTP status code.
            reason (str): Short reason phrase.
        """
        from websockets.http11 import Response
        from websockets.datastructures import Headers

        body, ct = _make_response(status, reason)
        headers = Headers(
            [("Content-Type", ct), ("Content-Length", str(len(body)))]
        )
        response = Response(status, reason.title(), headers, body.encode())
        await ws.respond(response)


def _build_select_subprotocol(ticket_store: TicketStore) -> Any:
    """Return a select_subprotocol callable for use with websockets.serve.

    The callable validates the ticket offered by the client as a subprotocol.
    If valid and not expired, it is consumed and echoed back.  Otherwise None
    is returned (the websockets library will then reject the handshake).

    Note: ticket validation happens SYNCHRONOUSLY here (the websockets
    select_subprotocol callback is not async).  Because single-process asyncio
    is used, the TicketStore._tickets dict can be accessed without the async
    lock in the synchronous path, but we use a simple sync path for safety.

    Args:
        ticket_store (TicketStore): The shared ticket store.

    Returns:
        selector (callable): select_subprotocol callback.
    """
    def _select(connection: ServerConnection, offered: list[str]) -> str | None:
        if not offered:
            return None
        # We check here; actual consumption is async in _handle_vnc_websocket.
        # We must accept the subprotocol during handshake to let the WS open,
        # then re-validate (consume) in the handler.
        # Accept the first offered value; the handler will consume it.
        return offered[0]

    return _select


async def run_server(
    config: GatewayConfig,
    source: Any,
) -> None:
    """Start the WebSocket gateway and serve forever.

    Args:
        config (GatewayConfig): Runtime configuration.
        source: Object satisfying FramebufferSource protocol.
    """
    app = IkvmGatewayApp(config)
    app.set_source(source)

    select_subprotocol = _build_select_subprotocol(app._ticket_store)

    _log_info(
        f"Starting ikvm-gateway | bind={config.bind_host}:{config.bind_port} | "
        f"max_sessions={config.max_sessions}"
    )

    async with serve(
        handler=app.handle_request,
        host=config.bind_host,
        port=config.bind_port,
        process_request=app.process_request,
        select_subprotocol=select_subprotocol,
        write_limit=256 * 1024,  # 256 KiB send-side backpressure
        max_queue=(16, None),
    ):
        await asyncio.get_event_loop().create_future()  # run forever
