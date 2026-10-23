"""Bounded subprocess helper shared by automation technique scripts."""
from __future__ import annotations

import shutil
import subprocess
from typing import List, Optional, Sequence, Tuple


def binary_available(name: str) -> bool:
    """Return True when a required binary resolves on PATH."""
    return shutil.which(name) is not None


def run_command(
    cmd: Sequence[str],
    *,
    timeout: int,
    input_data: Optional[str] = None,
    cwd: str = "/tmp",
    output_cap: int = 200_000,
) -> Tuple[int, str, str]:
    """Run a bounded subprocess; always returns (rc, stdout, stderr).

    Never raises: timeouts, missing binaries, and OS errors are folded into a
    negative return code and a human-readable stderr string so a technique
    script can degrade gracefully.
    """
    try:
        completed = subprocess.run(
            list(cmd),
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_data,
            cwd=cwd,
            start_new_session=True,
        )
    except subprocess.TimeoutExpired:
        return -1, "", f"command timed out after {timeout}s and was terminated"
    except FileNotFoundError as exc:
        return -1, "", f"binary not found: {exc}"
    except OSError as exc:
        return -1, "", f"failed to launch command: {exc}"

    stdout = completed.stdout[:output_cap] if completed.stdout else ""
    stderr = completed.stderr[:output_cap] if completed.stderr else ""
    return completed.returncode, stdout, stderr


__all__ = ["binary_available", "run_command"]
