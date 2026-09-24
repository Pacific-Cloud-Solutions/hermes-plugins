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


def register(ctx) -> None:  # noqa: ANN001 — PluginContext, typed by the SDK
    """Plugin entry point.

    Deliberately lets `bootstrap.load()` raise. A security tool that runs without
    the taint model is the exact failure this suite exists to prevent, so a
    missing pcs-security-core must fail the load, not degrade quietly.
    """
    register_all(ctx)