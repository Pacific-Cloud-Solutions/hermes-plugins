"""The finding schema — what every security-suite tool returns.

Design rules this encodes, in priority order:

1. **Never a bare number.** A finding that reports a risk without the artifact it
   came from is an opinion. Every `Finding` carries `Evidence` pointing at the
   exact source and locator.
2. **Coverage is part of the result, not a footnote.** A report says what it
   checked AND what it could not. `verdict()` has no code path that returns
   "secure" — only findings-per-check plus unreviewed surface.
3. **Severity is environment-relative.** `severity` is what the check is worth
   in principle; `reachability` and `preconditions` are what it is worth *here*.
   A scary finding behind an unreachable precondition must be able to say so.
4. **Stable identity.** `Finding.id` is deterministic over (check, source,
   locator), so a finding can be tracked, diffed and suppressed across runs.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping, Sequence

from .taint import Provenance, Quarantined, summarize_flags, trusted


class Severity(str, Enum):
    CRITICAL = "critical"   # directly exploitable; act now
    HIGH = "high"           # exploitable with a common precondition
    MEDIUM = "medium"       # requires local access, or a chain
    LOW = "low"             # hardening gap; defense in depth
    INFO = "info"           # observation, no action implied


class Reachability(str, Enum):
    """How an attacker would actually get here. Downgrades severity in practice."""

    REMOTE_UNAUTH = "remote_unauthenticated"
    REMOTE_AUTH = "remote_authenticated"
    LOCAL = "local"
    REQUIRES_CHAIN = "requires_chain"     # a second finding must land first
    THEORETICAL = "theoretical"           # no demonstrated path in this environment


class Confidence(str, Enum):
    CONFIRMED = "confirmed"   # observed directly
    LIKELY = "likely"         # inferred from strong signal
    SUSPECTED = "suspected"   # heuristic; a human should look


class Grade(str, Enum):
    """Overall posture, deliberately coarse. Five buckets, never a percentage."""

    ACTION_REQUIRED = "action_required"
    REVIEW = "review"
    HARDEN = "harden"
    NO_FINDINGS = "no_findings_for_these_checks"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True)
class Evidence:
    """One artifact a finding rests on. `observed` is the ONLY untrusted field."""

    source: str                     # trusted: "/etc/ssh/sshd_config" — plugin-supplied path
    locator: str                    # trusted: "line 42" / "offset 1180" / "entry 3"
    observed: Quarantined           # UNTRUSTED: the raw value, held inert
    note: str = ""                  # trusted: what about this value matters

    def __post_init__(self) -> None:
        trusted(self.source)
        trusted(self.locator)
        trusted(self.note)
        if not isinstance(self.observed, Quarantined):
            raise TypeError(
                "Evidence.observed must be a Quarantined value. Construct it with "
                "taint.quarantine(text, Provenance.UNTRUSTED) so its origin is recorded."
            )


@dataclass(frozen=True)
class Finding:
    """A single defensible claim about a system, with its evidence attached."""

    check_id: str                   # "SSH-001" — stable per check, across versions
    title: str                      # trusted: one line, no untrusted interpolation
    severity: Severity
    assertion: str                  # trusted: WHAT we claim
    rationale: str                  # trusted: why it matters IN THIS environment
    remediation: str                # trusted: advisory; never executed by the suite
    reachability: Reachability = Reachability.LOCAL
    confidence: Confidence = Confidence.CONFIRMED
    evidence: tuple[Evidence, ...] = ()
    preconditions: tuple[str, ...] = ()      # what must also be true for this to matter
    false_positive_notes: str = ""           # when this check fires wrongly
    references: tuple[str, ...] = ()         # CIS / CVE / vendor docs
    attacked_via: tuple[str, ...] = ()       # MITRE ATT&CK technique ids
    tags: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for field_name, value in (
            ("check_id", self.check_id), ("title", self.title),
            ("assertion", self.assertion), ("rationale", self.rationale),
            ("remediation", self.remediation), ("false_positive_notes", self.false_positive_notes),
        ):
            trusted(value)  # raises if a Quarantined was smuggled in
            if not value and field_name in ("check_id", "title", "assertion"):
                raise ValueError(f"Finding.{field_name} is required")

    @property
    def id(self) -> str:
        """Deterministic across runs: same check at the same place is the same finding."""
        basis = "|".join(
            [self.check_id]
            + [f"{e.source}#{e.locator}" for e in sorted(self.evidence, key=lambda e: (e.source, e.locator))]
        )
        return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]

    @property
    def instruction_like(self) -> Sequence[str]:
        """Instruction-like patterns found inside this finding's own evidence.

        Non-empty here is itself a notable result: it means attacker-controlled
        text reached the tool's input, which is expected — the question is only
        whether it stayed inert.
        """
        return summarize_flags(e.observed for e in self.evidence)


@dataclass(frozen=True)
class Coverage:
    """What was looked at, and what was not. The antidote to false confidence."""

    checks_run: tuple[str, ...] = ()
    checks_skipped: tuple[tuple[str, str], ...] = ()   # (check_id, reason)
    inputs_read: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()

    @property
    def skipped_ids(self) -> tuple[str, ...]:
        return tuple(cid for cid, _ in self.checks_skipped)


@dataclass(frozen=True)
class Report:
    """One tool's result against one target."""

    tool: str
    target: str                     # trusted: operator-supplied or a local path
    findings: tuple[Finding, ...] = ()
    coverage: Coverage = field(default_factory=Coverage)
    started_at: str = ""
    finished_at: str = ""

    def __post_init__(self) -> None:
        trusted(self.tool)
        trusted(self.target)
        if not self.started_at:
            object.__setattr__(self, "started_at", _now())

    @property
    def by_severity(self) -> Mapping[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return {k: v for k, v in counts.items() if v}

    @property
    def grade(self) -> Grade:
        """Coarse posture. Note what is NOT here: a percentage, or the word 'secure'."""
        if not self.coverage.checks_run:
            return Grade.INCONCLUSIVE
        sev = {f.severity for f in self.findings}
        if Severity.CRITICAL in sev or Severity.HIGH in sev:
            return Grade.ACTION_REQUIRED
        if Severity.MEDIUM in sev:
            return Grade.REVIEW
        if Severity.LOW in sev:
            return Grade.HARDEN
        if self.coverage.checks_skipped:
            return Grade.INCONCLUSIVE
        return Grade.NO_FINDINGS

    def verdict(self) -> str:
        """One sentence. Never claims safety — only what was and wasn't checked."""
        n = len(self.findings)
        run, skipped = len(self.coverage.checks_run), len(self.coverage.checks_skipped)
        head = (
            f"{n} finding{'s' if n != 1 else ''} across {run} check{'s' if run != 1 else ''}"
            if n else f"no findings for the {run} check{'s' if run != 1 else ''} run"
        )
        tail = f"; {skipped} check{'s' if skipped != 1 else ''} could not run" if skipped else ""
        return f"{head}{tail} — this is not a statement that the target is secure"

    @property
    def hostile_evidence(self) -> Sequence[Finding]:
        """Findings whose own evidence carried instruction-like content."""
        return tuple(f for f in self.findings if f.instruction_like)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def merge(reports: Sequence[Report]) -> Report:
    """Fold several tools' reports into one, preserving every coverage caveat."""
    if not reports:
        return Report(tool="pcs-security-core", target="(none)")
    findings: list[Finding] = []
    seen: set[str] = set()
    checks: list[str] = []
    skipped: list[tuple[str, str]] = []
    inputs: list[str] = []
    limits: list[str] = []
    for r in reports:
        for f in r.findings:
            if f.id not in seen:
                seen.add(f.id)
                findings.append(f)
        for c in r.coverage.checks_run:
            if c not in checks:
                checks.append(c)
        skipped.extend(r.coverage.checks_skipped)
        for i in r.coverage.inputs_read:
            if i not in inputs:
                inputs.append(i)
        for lim in r.coverage.limitations:
            if lim not in limits:
                limits.append(lim)
    order = {s: i for i, s in enumerate(
        [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO])}
    findings.sort(key=lambda f: (order[f.severity], f.check_id))
    return Report(
        tool="+".join(r.tool for r in reports),
        target=reports[0].target,
        findings=tuple(findings),
        coverage=Coverage(tuple(checks), tuple(skipped), tuple(inputs), tuple(limits)),
        started_at=min(r.started_at for r in reports),
    )


def finding_payload(f: Finding) -> dict[str, Any]:
    """JSON-serializable form. Untrusted text keeps its provenance and flags."""
    return {
        "id": f.id,
        "check_id": f.check_id,
        "title": f.title,
        "severity": f.severity.value,
        "reachability": f.reachability.value,
        "confidence": f.confidence.value,
        "assertion": f.assertion,
        "rationale": f.rationale,
        "remediation": f.remediation,
        "preconditions": list(f.preconditions),
        "false_positive_notes": f.false_positive_notes,
        "references": list(f.references),
        "attacked_via": list(f.attacked_via),
        "tags": list(f.tags),
        "evidence": [
            {
                "source": e.source,
                "locator": e.locator,
                "note": e.note,
                "observed": e.observed.raw,
                "provenance": e.observed.provenance.value,
                "instruction_like": list(e.observed.flags),
                "truncated": e.observed.truncated,
                "redacted": e.observed.redacted,
            }
            for e in f.evidence
        ],
    }


def report_payload(r: Report) -> dict[str, Any]:
    return {
        "tool": r.tool,
        "target": r.target,
        "grade": r.grade.value,
        "verdict": r.verdict(),
        "by_severity": dict(r.by_severity),
        "findings": [finding_payload(f) for f in r.findings],
        "coverage": {
            "checks_run": list(r.coverage.checks_run),
            "checks_skipped": [{"check_id": c, "reason": why} for c, why in r.coverage.checks_skipped],
            "inputs_read": list(r.coverage.inputs_read),
            "limitations": list(r.coverage.limitations),
        },
        "started_at": r.started_at,
        "finished_at": r.finished_at or _now(),
    }