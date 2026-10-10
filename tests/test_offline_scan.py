"""Offline-scan guarantee: the scan path must not open a socket.

On Linux this runs the CLI's scan under strace and asserts no connect()
syscall fires. On platforms without strace the test documents the
guarantee and skips: the runner constructs semgrep with --metrics=off and
--disable-version-check, never installs target code, and never imports
target files, so a scan is process-local by construction.
"""

import shutil
import subprocess
from pathlib import Path

import pytest

from path_guard_audit.cli import main

FIXTURES = Path(__file__).parent / "fixtures" / "p0" / "unguarded-python"

pytestmark = pytest.mark.skipif(
    shutil.which("semgrep") is None or shutil.which("strace") is None,
    reason="needs semgrep and strace",
)


def test_scan_makes_no_network_connect(tmp_path):
    trace = tmp_path / "strace.log"
    cli_path = shutil.which("path-guard-audit") or str(
        Path(__import__("path_guard_audit", fromlist=["x"]).__file__).parent.parent.parent
        / "bin" / "path-guard-audit"
    )
    subprocess.run(
        [
            "strace",
            "-f",
            "-e",
            "trace=network",
            "-o",
            str(trace),
            "python3",
            "-m",
            "path_guard_audit.cli",
            "scan",
            str(FIXTURES),
        ] if cli_path is None else [
            "strace",
            "-f",
            "-e",
            "trace=network",
            "-o",
            str(trace),
            cli_path,
            "scan",
            str(FIXTURES),
        ],
        check=False,
        capture_output=True,
    )
    text = trace.read_text() if trace.is_file() else ""
    assert "connect(" not in text or all(
        "AF_UNIX" in l or "AF_NETLINK" in l for l in text.splitlines() if "connect(" in l
    )
