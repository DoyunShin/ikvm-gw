"""Packaging-integrity tests.

These guard against the shipped wheel importing modules that are NOT part of the
distribution (e.g. the repo-only ``spike``/``tools``/``tests`` directories, which
are excluded from the wheel by ``python-source = "src"``). Such a leak makes
``pip install ikvm-gw`` importable in the dev tree but broken once installed.

The import is run in a SUBPROCESS from a directory outside the repo, so the
current-working-directory entry on ``sys.path`` cannot mask a missing module.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile


def _import_in_clean_cwd(script: str) -> subprocess.CompletedProcess:
    """Run a Python snippet in a subprocess from a temp dir (repo root off path)."""
    with tempfile.TemporaryDirectory() as tmp:
        return subprocess.run(
            [sys.executable, "-c", script],
            cwd=tmp,
            capture_output=True,
            text=True,
        )


def test_package_imports_without_repo_only_modules() -> None:
    """Importing the package must not pull in repo-only modules (spike/tools/tests)."""
    script = (
        "import sys\n"
        "import ikvm_gateway\n"
        "import ikvm_gateway.app\n"
        "import ikvm_gateway.upstream.client\n"
        "import ikvm_gateway.upstream.protocol\n"
        "import ikvm_gateway.upstream.auth\n"
        "import ikvm_gateway.downstream.ws_app\n"
        "import ikvm_gateway.downstream.rfb_server\n"
        "import ikvm_gateway.input.translate\n"
        "from ikvm_gateway import _ast2100\n"
        "leaked = sorted(m for m in sys.modules if m.split('.')[0] in {'spike', 'tools', 'tests'})\n"
        "assert not leaked, f'package imports repo-only modules: {leaked}'\n"
    )
    result = _import_in_clean_cwd(script)
    assert result.returncode == 0, (
        f"clean import failed:\nstdout={result.stdout}\nstderr={result.stderr}"
    )


def test_protocol_module_is_self_contained() -> None:
    """ikvm_gateway.upstream.protocol must define its helpers, not re-export spike."""
    script = (
        "import sys\n"
        "from ikvm_gateway.upstream import protocol\n"
        "for name in ('build_credential_block', 'parse_server_init',\n"
        "             'parse_rectangle_header', 'parse_aten_rect_extra',\n"
        "             'build_set_encodings', 'build_framebuffer_update_request',\n"
        "             'ATEN_ENCODINGS', 'ATEN_EXTRA_MESSAGE_SKIP'):\n"
        "    assert hasattr(protocol, name), name\n"
        "assert 'spike' not in sys.modules\n"
        "blk = protocol.build_credential_block('tok', '')\n"
        "assert len(blk) == 48 and blk[:3] == b'tok' and blk[3:] == b'\\x00' * 45\n"
    )
    result = _import_in_clean_cwd(script)
    assert result.returncode == 0, (
        f"protocol self-containment check failed:\nstdout={result.stdout}\nstderr={result.stderr}"
    )
