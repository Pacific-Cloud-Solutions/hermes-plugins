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


def _ensure_host_registrations(ctx) -> None:
    """Register the suite's host-level pieces unless pcs-security-core will do it.

    core owns secret redaction and the hostile-input prompt section whenever it is
    installed. When it is NOT — a catalog install of this plugin alone — nothing
    else registers them, and the taint *rule* would be missing even though the
    contract is bundled and the code enforces it. Bundling alone is not enough.

    `has_plugin()` answers the real question ("will someone else do this?") instead
    of guessing from load order, and it side-steps the duplicate-id ValueError the
    system-prompt-section registry raises on a second registration.
    """
    import logging

    logger = logging.getLogger(__name__)

    has_plugin = getattr(ctx, "has_plugin", None)
    if callable(has_plugin):
        try:
            if has_plugin("pcs-security-core"):
                return
        except Exception as exc:  # noqa: BLE001
            logger.debug("%s: has_plugin probe failed: %s", __name__, exc)

    try:
        from . import _contract
        _contract.register(ctx)
    except Exception as exc:  # noqa: BLE001
        logger.warning("%s: host registration failed: %s", __name__, exc)


def register(ctx) -> None:  # noqa: ANN001 — PluginContext, typed by the SDK
    """Plugin entry point.

    The contract is bundled (see bootstrap.py), so neither this entry point nor
    `load()` depends on a sibling plugin being installed. What a bundle cannot
    supply is the host-level half — the redaction patterns and the system-prompt
    section — so that is registered here when core is absent, and left to core
    when core is present.
    """
    _ensure_host_registrations(ctx)
    register_all(ctx)