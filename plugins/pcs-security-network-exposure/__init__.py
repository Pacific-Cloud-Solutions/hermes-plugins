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