"""CLI entry point: python -m ikvm_gateway.

Reads BMC credentials from a local secret file (3 lines: host, user, password),
starts one upstream console session, and serves it to stock noVNC over a
standard RFB-over-WebSocket endpoint with security None.

The downstream control endpoint (POST /sessions) is protected by a bearer API
key. If --api-key / IKVM_GATEWAY_API_KEY is not provided, a random key is
generated and logged at startup so an operator/orchestrator can use it.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import secrets
import sys
from pathlib import Path

from prompt_toolkit import print_formatted_text
from prompt_toolkit.formatted_text import FormattedText

from .app import run_gateway
from .downstream.ws_app import GatewayConfig


class _PromptToolkitHandler(logging.Handler):
    """Log handler using prompt_toolkit with a plain-text fallback."""

    _STYLE = {
        logging.DEBUG: "ansicyan",
        logging.INFO: "ansigreen",
        logging.WARNING: "ansiyellow",
        logging.ERROR: "ansired",
        logging.CRITICAL: "ansired bold",
    }

    def emit(self, record: logging.LogRecord) -> None:
        """Format and write one log record."""
        try:
            msg = self.format(record)
            if hasattr(sys.stdout, "isatty") and sys.stdout.isatty():
                print_formatted_text(
                    FormattedText([(self._STYLE.get(record.levelno, ""), msg)])
                )
            else:
                sys.stderr.write(msg + "\n")
                sys.stderr.flush()
        except Exception:
            self.handleError(record)


def _configure_logging(debug: bool) -> None:
    """Configure root logging via the prompt_toolkit handler."""
    root = logging.getLogger()
    root.handlers.clear()
    handler = _PromptToolkitHandler()
    if debug:
        root.setLevel(logging.DEBUG)
        fmt = "[%(asctime)s] [%(filename)s:%(lineno)d] %(levelname)s # %(message)s"
    else:
        root.setLevel(logging.INFO)
        fmt = "[%(asctime)s] %(levelname)s # %(message)s"
    handler.setFormatter(logging.Formatter(fmt))
    root.addHandler(handler)


def _read_bmc_host(secret_path: Path) -> str:
    """Read the BMC host (first line) from the secret file."""
    lines = [ln.strip() for ln in secret_path.read_text().splitlines() if ln.strip()]
    if not lines:
        raise RuntimeError(f"secret file {secret_path} is empty")
    return lines[0]


def _parse_args(argv: list[str]) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(prog="ikvm_gateway")
    parser.add_argument("--secret", type=Path, default=Path("secret"),
                        help="path to credential file (host/user/password)")
    parser.add_argument("--bind-host", default="127.0.0.1")
    parser.add_argument("--bind-port", type=int, default=5700)
    parser.add_argument("--api-key", default=None,
                        help="bearer key for POST /sessions; random if omitted")
    parser.add_argument("--max-sessions", type=int, default=4)
    parser.add_argument("--debug", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    """CLI entry point."""
    args = _parse_args(argv if argv is not None else sys.argv[1:])
    _configure_logging(args.debug)
    log = logging.getLogger(__name__)

    bmc_host = _read_bmc_host(args.secret)
    api_key = args.api_key or secrets.token_urlsafe(24)
    if not args.api_key:
        # Print the generated key to stderr only, never through the logger
        # (which may be routed to a log file or SIEM where a secret must not land).
        sys.stderr.write(f"Generated control API key (not logged): {api_key}\n")
        sys.stderr.flush()

    config = GatewayConfig(
        api_key=api_key,
        bmc_host=bmc_host,
        bind_host=args.bind_host,
        bind_port=args.bind_port,
        max_sessions=args.max_sessions,
    )
    log.info("ikvm-gateway target BMC %s | noVNC ws://%s:%d/vnc",
             bmc_host, args.bind_host, args.bind_port)

    try:
        asyncio.run(run_gateway(args.secret, config))
    except KeyboardInterrupt:
        log.info("Shutting down")


if __name__ == "__main__":
    main()
