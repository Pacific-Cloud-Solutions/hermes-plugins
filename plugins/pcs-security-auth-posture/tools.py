"""Tool handlers. Every handler returns a JSON string and never raises."""
from __future__ import annotations

import json
import logging

from . import checks
from .checks import run_all
from .schemas import AUTH_POSTURE_SCHEMA, TOOL_NAME

logger = logging.getLogger(__name__)

_TOOLSET = "security"


def auth_posture(args, **kwargs) -> str:
    """Run the read-only local authentication posture audit.

    `**kwargs` is mandatory: additive payload fields must never break this handler.

    `checks.core()` raises when pcs-security-core is absent, and that lands in the
    except below — so an unconfigured install gets an explicit error, never a
    report produced outside the taint model.
    """
    try:
        core = checks.core()
        args = args or {}
        root = str(args.get("root") or "/")
        include_info = bool(args.get("include_info", False))

        audit = run_all(root, include_info)
        report = core.Report(
            tool="pcs-security-auth-posture",
            target=str(audit.root),
            findings=tuple(audit.findings),
            coverage=core.Coverage(
                checks_run=tuple(audit.checks_run),
                checks_skipped=tuple(audit.checks_skipped),
                inputs_read=tuple(audit.inputs_read),
                # dict.fromkeys: a limitation repeated per-check should read once.
                limitations=tuple(dict.fromkeys(audit.limitations)),
            ),
        )
        return json.dumps(core.render_json(report), indent=2)
    except Exception as exc:  # never raise into the registry
        return json.dumps({
            "tool": TOOL_NAME,
            "error": f"{type(exc).__name__}: {exc}",
            "verdict": "audit could not run — this is NOT a statement about the target",
        })


def register_all(ctx) -> None:  # noqa: ANN001 — PluginContext
    """Register the tool.

    Probes pcs-security-core and WARNS — but still registers — when it is missing.
    Registering anyway is what lets `hermes plugins doctor` and
    `hermes plugins validate` pass, since both run the plugin in isolation with no
    sibling pcs-security-core on disk. The safety property lives in the handler, which
    refuses to produce a report without the contract.
    """
    try:
        checks.core()
    except Exception as exc:
        logger.warning(
            "pcs-security-auth-posture: pcs-security-core is unavailable (%s). %s will register "
            "but refuse to run until it is installed — no report is produced without the "
            "taint model.", exc, TOOL_NAME,
        )

    ctx.register_tool(
        name=TOOL_NAME,
        toolset=_TOOLSET,
        schema=AUTH_POSTURE_SCHEMA,
        handler=auth_posture,
        emoji="🛡",
    )