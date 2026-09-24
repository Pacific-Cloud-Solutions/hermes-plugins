"""pcs-security-auth-posture — read-only local authentication posture audit.

Tool surface: exactly one tool, `auth_posture`. It reads a fixed list of
well-known authentication files and returns a structured `Report`.

Three properties that are design constraints, not accidents:

1. **Read-only.** Nothing here writes, executes, or connects. There is no
   remediation path — findings are advisory text for a human to act on.
2. **No target selection.** The tool audits the local host (or a `root` prefix
   for a mounted filesystem) against a FIXED list of relative paths. It is not a
   file reader and cannot be talked into becoming one: an attacker who can
   specify the path can make the tool print /etc/shadow, an SSH key, or a
   credential store. `_resolve()` refuses anything outside the list.
3. **No silent passes.** A file that cannot be read is recorded in
   `coverage.checks_skipped` with its reason. Unreadable is not the same as safe,
   and a report must never imply otherwise.
"""
from __future__ import annotations

from .tools import register_all


def register(ctx) -> None:  # noqa: ANN001 — PluginContext, typed by the SDK
    """Plugin entry point.

    Deliberately lets `bootstrap.load()` raise. A security tool that runs without
    the taint model is the exact failure this suite exists to prevent, so a
    missing pcs-security-core must fail the load, not degrade quietly.
    """
    register_all(ctx)