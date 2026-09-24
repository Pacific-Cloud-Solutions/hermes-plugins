"""pcs-security-log-triage — read-only triage of local system logs.

Tool surface: exactly one tool, `log_triage`. It reads a fixed list of well-known
log paths and returns a structured `Report`.

This plugin exists to demonstrate the property the whole suite is built around.
Log content is the most hostile input an agent can be handed: a username, an HTTP
User-Agent, a request path or a referrer can contain anything at all, including
text crafted to read like an instruction. That text arrives here as DATA. It is
quarantined at the boundary, its instruction-like patterns are recorded, and it
is reported as a finding — never executed, never stripped, never promoted into
anything the agent might act on.

Three properties that are design constraints, not accidents:

1. **Read-only.** Nothing here writes, executes, or connects. There is no
   remediation path — findings are advisory text for a human to act on.
2. **No target selection.** The tool reads the local host (or a `root` prefix for
   a mounted filesystem) against a FIXED list of relative log paths. It is not an
   arbitrary file reader: a caller who can specify the path can make the tool
   print a credential store. `Audit.path()` refuses anything outside the root.
3. **No silent passes.** A log that is missing or unreadable is recorded in
   `coverage.checks_skipped` with its reason. Unreadable is not the same as
   clean, and a report must never imply otherwise.
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