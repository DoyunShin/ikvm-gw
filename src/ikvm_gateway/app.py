"""Top-level wiring for the ikvm-gateway.

One upstream BMC console session (AtenUpstreamClient) is decoded into a live
framebuffer and re-served to standard noVNC clients through the downstream
RFB-over-WebSocket gateway (security None). Credentials/token stay server-side.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

from .downstream.ws_app import GatewayConfig, run_server
from .upstream.client import AtenUpstreamClient

log = logging.getLogger(__name__)


async def run_gateway(secret_path: Path, config: GatewayConfig) -> None:
    """Start the upstream client and the downstream gateway together.

    The upstream authentication (web login + token fetch) is blocking I/O and
    runs in a worker thread; the framebuffer read loop and the downstream WS
    server then run concurrently. If either stops, the other is cancelled.

    Args:
        secret_path (Path): Path to the credential file (host/user/pass).
        config (GatewayConfig): Downstream gateway configuration. Its bmc_host
            is used only for the SSRF-safe fixed target and audit logging.
    """
    client = await asyncio.to_thread(AtenUpstreamClient.from_secret, secret_path)
    await client.connect()
    log.info("Upstream connected: %dx%d", client.width, client.height)

    upstream_task = asyncio.create_task(client.run(), name="upstream-run")
    server_task = asyncio.create_task(run_server(config, client), name="downstream-server")

    done, pending = await asyncio.wait(
        {upstream_task, server_task}, return_when=asyncio.FIRST_COMPLETED
    )
    for task in pending:
        task.cancel()
    await asyncio.gather(*pending, return_exceptions=True)
    for task in done:
        exc = task.exception()
        if exc is not None:
            raise exc
