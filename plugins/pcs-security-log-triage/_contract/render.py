"""Rendering — one shape for every tool in the suite.

Two rules the renderer exists to enforce:

- Untrusted evidence is visually quarantined in the human view, always, with its
  instruction-like flags surfaced rather than hidden. A reader should be able to
  see at a glance that a string came from a log line and tried to look like a
  directive.
- The text view and the JSON view carry the SAME information. If a caveat is
  visible to a human it is present for the model too, and vice versa.
"""
from __future__ import annotations

from typing import Sequence

from .schema import Grade, Report, Severity, report_payload

_SEV_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
_GRADE_LABEL = {
    Grade.ACTION_REQUIRED: "ACTION REQUIRED",
    Grade.REVIEW: "REVIEW",
    Grade.HARDEN: "HARDEN",
    Grade.NO_FINDINGS: "NO FINDINGS (for these checks)",
    Grade.INCONCLUSIVE: "INCONCLUSIVE",
}


def render_text(report: Report, *, evidence_limit: int = 3) -> str:
    """Human-facing summary. Deterministic — same report, same bytes."""
    out: list[str] = []
    out.append(f"{report.tool} — {report.target}")
    out.append(f"{_GRADE_LABEL[report.grade]}  |  {report.verdict()}")

    if report.findings:
        out.append("")
        counts = report.by_severity
        out.append("severity: " + "  ".join(f"{k}={v}" for k, v in counts.items()))

    for sev in _SEV_ORDER:
        group = [f for f in report.findings if f.severity is sev]
        if not group:
            continue
        out.append("")
        out.append(f"── {sev.value.upper()} ──")
        for f in group:
            out.append(f"  [{f.check_id}] {f.title}   (id {f.id})")
            out.append(f"    {f.assertion}")
            out.append(f"    why it matters: {f.rationale}")
            if f.reachability.value != "local":
                out.append(f"    reachability: {f.reachability.value}")
            if f.preconditions:
                out.append(f"    only matters if: {'; '.join(f.preconditions)}")
            for e in f.evidence[:evidence_limit]:
                mark = " ⚠ INSTRUCTION-LIKE" if e.observed.hostile else ""
                rd = " [redacted]" if e.observed.redacted else ""
                tr = " [truncated]" if e.observed.truncated else ""
                out.append(f"    evidence {e.source}:{e.locator}{rd}{tr}{mark}")
                out.append(f"      <<UNTRUSTED DATA: {e.observed.raw}>>")
            extra = len(f.evidence) - evidence_limit
            if extra > 0:
                out.append(f"    (+{extra} more evidence item(s))")
            out.append(f"    fix: {f.remediation}")
            if f.false_positive_notes:
                out.append(f"    may be wrong when: {f.false_positive_notes}")

    cov = report.coverage
    out.append("")
    out.append("── COVERAGE ──")
    out.append(f"  checks run: {len(cov.checks_run)}   skipped: {len(cov.checks_skipped)}")
    for cid, why in cov.checks_skipped:
        out.append(f"  skipped [{cid}]: {why}")
    for lim in cov.limitations:
        out.append(f"  limitation: {lim}")
    return "\n".join(out)


def render_compact(report: Report) -> str:
    """One-liner for a status bar or a log line. Still refuses to claim safety."""
    return f"{report.tool}: {_GRADE_LABEL[report.grade]} — {report.verdict()}"


def render_json(report: Report) -> dict:
    """The tool-facing payload. Handlers return this; they never return raw text."""
    return report_payload(report)


def summarize_tool_result(payload: dict) -> str:
    """Extract the fields a model should always quote when reporting back.

    Exists so every tool in the suite surfaces grade, verdict and coverage
    identically — the failure mode this prevents is a tool reporting its
    findings while dropping the caveats.
    """
    cov = payload.get("coverage", {})
    return (
        f"{payload.get('grade')} | {payload.get('verdict')} | "
        f"checks_run={len(cov.get('checks_run', []))} "
        f"checks_skipped={len(cov.get('checks_skipped', []))}"
    )