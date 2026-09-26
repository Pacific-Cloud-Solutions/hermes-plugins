"""pcs-security-web-headers — read-only audit of declared HTTP security headers.

Tool surface: exactly one tool, `web_headers`.

It reads the *declared* security headers in local web server configuration. It
does not fetch a page and does not test a URL — that would require a network
connection this suite does not make, and it would report on one route of one
host. Configuration is where the intent lives and where a fix belongs.

Three properties that are design constraints, not accidents:

1. **Read-only.** Nothing here writes, executes, or connects.
2. **No target selection.** A FIXED list of relative configuration paths and
   globs under the root. `Audit.path()` refuses anything that escapes the root.
3. **No silent passes.** A configuration that is missing or unreadable is
   recorded in `coverage.checks_skipped` with its reason. **Absence of a header
   declaration is reported as a coverage-shaped gap, not as a passing host** —
   and no report ever says the site is secure.
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