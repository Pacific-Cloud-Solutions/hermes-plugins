"""pcs-security-tls-posture — read-only local TLS posture audit.

Tool surface: exactly one tool, `tls_posture`. It reads a fixed list of
well-known certificate paths and server TLS directives and returns a
structured `Report`.

Three properties that are design constraints, not accidents:

1. **Read-only.** Nothing here writes, executes, or connects. Critically, it
   does not *speak TLS* to anything: it parses certificate files and config
   on disk. There is no handshake, no socket, no remote target. A tool that
   connected to a host would be a network scanner wearing this schema, and
   would inherit every liability of one.
2. **No target selection.** The tool audits the local host (or a `root` prefix
   for a mounted filesystem) against a FIXED list of relative paths and globs.
   It is not a file reader and cannot be talked into becoming one: an attacker
   who can specify the path can make the tool print a private key or a
   credential store. `Audit.path()` refuses anything outside the root.
3. **No silent passes.** A certificate that cannot be read or parsed is recorded
   in `coverage.checks_skipped` with its reason. Unparseable is not the same as
   valid, and a report must never imply otherwise.

A note on the crypto backend: full certificate detail needs an X.509 parser.
`cryptography` is used when importable; when it is not, the standard library's
certificate decoder supplies dates and names but NOT key size or signature
algorithm. That gap is recorded in coverage rather than papered over — a check
that could not run is reported as skipped, never as passing.
"""
from __future__ import annotations

from .tools import register_all


def register(ctx) -> None:  # noqa: ANN001 — PluginContext, typed by the SDK
    """Plugin entry point.

    Deliberately lets `bootstrap.load()` raise. A security tool that runs
    without the taint model is the exact failure this suite exists to prevent,
    so a missing pcs-security-core must fail the load, not degrade quietly.
    """
    register_all(ctx)