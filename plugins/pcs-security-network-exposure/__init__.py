"""pcs-security-network-exposure — read-only local network exposure audit.

Tool surface: exactly one tool, `network_exposure`.

Three properties that are design constraints, not accidents:

1. **Read-only, and specifically it does not touch the network.** Nothing here
   writes, executes, connects, or opens a socket. It does not run `ss`, `netstat`,
   `lsof`, or any subprocess. It reads the kernel's own socket tables from `/proc`
   and, when those are unavailable, the services' own configuration files. A tool
   that probed a network would be a different product with an entirely different
   liability profile — it would be scanning, and scanning has legal and
   operational consequences this plugin deliberately does not have.
2. **No target selection.** The tool audits the local host (or a `root` prefix for
   a mounted filesystem) against a FIXED list of relative paths. It is not an
   arbitrary file reader: `Audit.path()` refuses anything outside the root.
3. **No silent passes.** If neither tier yields data, that is recorded in
   `coverage.checks_skipped` with its reason. **No data is not the same as no
   exposure**, and a report must never imply otherwise.
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