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