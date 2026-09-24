"""The checks. Read-only, local, evidence-citing, hostile-input-tolerant.

Everything here reads log files as TEXT. Nothing is executed, and no value from a
log ever reaches a trusted field.

Four things are easy to get wrong and are done deliberately:

**A count is not a finding.** "412 authentication failures" is a number an
operator can do nothing with. The useful part is that 398 of them came from one
address in ninety seconds — so the events are correlated by source address, and
the finding names the source. That correlation is the product.

**A success after a burst is the interesting event.** Failures alone mean someone
is knocking; failures followed by an accepted authentication from the same address
mean someone may have got in. The second is graded CRITICAL and only fires when
the ordering actually holds — a success *before* the burst is not a compromise.

**Log text is DATA, never instruction.** A username, a URL, a User-Agent or a
referrer can contain anything, including text written to look like a directive to
whatever reads the log. Every line scanned is run through the taint classifier;
anything instruction-like is reported as a finding and left exactly as it was.
It is never stripped, never acted on, and never promoted into the trusted prose of
a finding.

**Reading the tail is a deliberate trade.** Logs are append-only, so current
activity is at the end. A bounded read keeps a 4 GB log from becoming a 4 GB
parse, and the bound is recorded as a coverage limitation whenever it bites —
because "no findings" from the last 20,000 lines is not "no findings".
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .bootstrap import load

# Bound by core() on first use — deliberately left None at import time.
#
# `hermes plugins doctor` and `hermes plugins validate` copy the plugin into a
# temp directory and run it in ISOLATION, so a sibling `pcs-security-core/` is not on
# disk there; a module-level `load()` makes both gates fail. The property that
# matters is "no REPORT is produced without the taint model", which the handler
# enforces — not "the module cannot be imported".
#
# (A PEP 562 module `__getattr__` does NOT solve this: it is consulted for
# attribute access on the module object, not for global-name lookups inside the
# module's own functions.)
Finding: Any = None
Evidence: Any = None
Severity: Any = None
Reachability: Any = None
Confidence: Any = None
Provenance: Any = None
quarantine: Any = None
classify_patterns: Any = None
_core_cache: list = []


def core():
    """Load pcs-security-core, bind its symbols into this module, and return it.

    Cached after the first success. Raises if pcs-security-core cannot be found.
    """
    global Confidence, Evidence, Finding, Provenance, Reachability, Severity
    global classify_patterns, quarantine
    if _core_cache:
        return _core_cache[0]
    module = load()
    Confidence = module.Confidence
    Evidence = module.Evidence
    Finding = module.Finding
    Provenance = module.Provenance
    Reachability = module.Reachability
    Severity = module.Severity
    quarantine = module.quarantine
    classify_patterns = module.classify_patterns
    _core_cache.append(module)
    return module


# ── The only paths this tool will ever read. Relative to the audit root. ──────
LOG_FILES = (
    "var/log/auth.log",
    "var/log/secure",
    "var/log/syslog",
    "var/log/messages",
    "var/log/kern.log",
    "var/log/nginx/access.log",
    "var/log/nginx/error.log",
    "var/log/apache2/access.log",
    "var/log/apache2/error.log",
)

#: Authentication log paths — only these are credited with auth events. A web
#: access log contains the word "failed" for unrelated reasons, and counting an
#: HTTP 500 as a failed login would be a fabricated finding.
AUTH_LOGS = ("var/log/auth.log", "var/log/secure")

#: `Sep 24 02:11:04 host program[pid]: message` — permissive by design. A line
#: that does not match is still scanned, just without parsed fields.
_LINE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<prog>[\w./-]+)(?:\[(?P<pid>\d+)\])?:\s?(?P<msg>.*)$"
)

_FAILURE = re.compile(
    r"(failed password|authentication failure|invalid user|failed publickey|"
    r"maximum authentication attempts|too many authentication failures|"
    r"pam_unix\(.*\): authentication failure)",
    re.I,
)
_SUCCESS = re.compile(
    r"(accepted password|accepted publickey|accepted keyboard-interactive|"
    r"session opened for user)",
    re.I,
)
_CRASH = re.compile(
    r"\b(segfault|segmentation fault|general protection fault|kernel panic|"
    r"core dumped|oops|fatal error)\b",
    re.I,
)
_SEVERE_CRASH = re.compile(r"\b(segfault|segmentation fault|kernel panic|core dumped)\b", re.I)

_IPV4 = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_IPV6 = re.compile(r"\b([0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7})\b")


@dataclass
class Observation:
    """One classified log event, with the line it came from."""

    seq: int
    source: str
    lineno: int
    line: str
    kind: str                      # "failure" | "success" | "crash" | "instruction"
    address: str = ""
    detector_flags: tuple[str, ...] = ()


class Audit:
    """Accumulates findings and — just as importantly — what it could not check."""

    def __init__(self, root: str = "/", max_lines: int = 20000,
                 failure_threshold: int = 5) -> None:
        self.root = Path(root).resolve()
        self.max_lines = max_lines
        self.failure_threshold = failure_threshold
        self.findings: list = []
        self.checks_run: list[str] = []
        self.checks_skipped: list[tuple[str, str]] = []
        self.inputs_read: list[str] = []
        self.limitations: list[str] = []
        self.observations: list[Observation] = []
        self._seq = 0

    # -- bookkeeping ---------------------------------------------------------
    def ran(self, *check_ids: str) -> None:
        for cid in check_ids:
            if cid not in self.checks_run:
                self.checks_run.append(cid)

    def skip(self, check_id: str, reason: str) -> None:
        self.checks_skipped.append((check_id, reason))

    def add(self, finding) -> None:
        self.findings.append(finding)

    def note(self, text: str) -> None:
        if text not in self.limitations:
            self.limitations.append(text)

    def next_seq(self) -> int:
        self._seq += 1
        return self._seq

    # -- bounded reads -------------------------------------------------------
    def path(self, relative: str) -> Path:
        """Join a fixed relative path to the root, refusing anything that escapes."""
        candidate = (self.root / relative).resolve()
        if candidate != self.root and self.root not in candidate.parents:
            raise ValueError(f"path escapes audit root: {relative!r}")
        return candidate

    def read(self, relative: str, check_id: str) -> str | None:
        """Read a fixed path. Missing or unreadable records a SKIP, never a pass."""
        try:
            path = self.path(relative)
        except ValueError as exc:
            self.skip(check_id, str(exc))
            return None
        if not path.is_file():
            self.skip(check_id, f"{relative} not present")
            return None
        try:
            text = path.read_text(errors="replace")
        except PermissionError:
            self.skip(check_id, f"{relative}: permission denied")
            return None
        except OSError as exc:
            self.skip(check_id, f"{relative}: {exc.strerror or exc}")
            return None
        if relative not in self.inputs_read:
            self.inputs_read.append(relative)
        return text

    def tail(self, relative: str, check_id: str) -> list[str] | None:
        """Read the LAST `max_lines` lines. A bounded read is recorded when it bites."""
        text = self.read(relative, check_id)
        if text is None:
            return None
        lines = text.splitlines()
        if not lines:
            self.skip(check_id, f"{relative} is empty")
            return None
        if len(lines) > self.max_lines:
            self.note(
                f"Each log was examined from the end, at most {self.max_lines} lines. "
                "Older entries were not read, so absence of findings does not cover them."
            )
            lines = lines[-self.max_lines:]
        return lines


def _text(check_id, source, locator, value, note) -> Any:
    """Every value read off disk is UNTRUSTED — see README, 'Why nothing is LOCAL'.

    Annotated `Any`, not `Evidence`: `Evidence` is a module-level name bound by
    `core()` on first use, so it is a value at import time, not a type.
    """
    return Evidence(source=source, locator=locator, note=note,
                    observed=quarantine(value, Provenance.UNTRUSTED))


def _address_in(message: str) -> str:
    """Best-effort source address. IPv4 first; the IPv6 pattern is greedy and
    would otherwise swallow timestamps."""
    match = _IPV4.search(message)
    if match:
        return match.group(1)
    match = _IPV6.search(message)
    if match:
        return match.group(1)
    return ""


def _scan(audit: Audit, relative: str, lines: list[str]) -> None:
    """Classify every line. This is where log text meets the taint classifier."""
    is_auth = relative in AUTH_LOGS
    for lineno, raw in enumerate(lines, 1):
        line = raw.rstrip("\n")
        if not line.strip():
            continue

        # Hostile-input boundary. `classify_patterns` is the same detector set
        # core's `quarantine()` uses; running it here means an instruction-like
        # line is found even when it is not itself the evidence of another check.
        flags = classify_patterns(line)
        if flags:
            audit.observations.append(Observation(
                seq=audit.next_seq(), source=relative, lineno=lineno, line=line,
                kind="instruction", detector_flags=tuple(flags),
            ))

        if is_auth:
            parsed = _LINE.match(line)
            message = parsed.group("msg") if parsed else line
            address = _address_in(message)
            if _FAILURE.search(message):
                audit.observations.append(Observation(
                    seq=audit.next_seq(), source=relative, lineno=lineno, line=line,
                    kind="failure", address=address,
                ))
            elif _SUCCESS.search(message):
                audit.observations.append(Observation(
                    seq=audit.next_seq(), source=relative, lineno=lineno, line=line,
                    kind="success", address=address,
                ))
            continue

        if _CRASH.search(line):
            audit.observations.append(Observation(
                seq=audit.next_seq(), source=relative, lineno=lineno, line=line,
                kind="crash",
            ))


# ── LOG-001 / LOG-002: correlated authentication anomalies ───────────────────

def check_authentication(audit: Audit) -> None:
    failures = [o for o in audit.observations if o.kind == "failure"]
    successes = [o for o in audit.observations if o.kind == "success"]

    if not failures:
        if not any(o.kind == "success" for o in audit.observations) and not audit.inputs_read:
            audit.skip("LOG-001", "no readable authentication log")
        else:
            audit.ran("LOG-001")
            audit.note(
                "An authentication log was read and contains no failure events. That is a "
                "statement about the lines examined, not about the host."
            )
        if not successes:
            audit.skip("LOG-002", "no accepted authentication following any failure burst")
        return

    by_address: dict[str, list[Observation]] = {}
    unattributed = 0
    for obs in failures:
        if obs.address:
            by_address.setdefault(obs.address, []).append(obs)
        else:
            unattributed += 1

    if unattributed:
        audit.note(
            f"{unattributed} failure line(s) carried no parseable source address, so they "
            "could not be correlated and are not counted toward any burst."
        )

    threshold = audit.failure_threshold
    bursts = {addr: obs for addr, obs in by_address.items() if len(obs) >= threshold}

    if not by_address:
        audit.skip("LOG-001", "no failure events carried a source address to correlate")
    else:
        audit.ran("LOG-001")

    for address, obs in sorted(bursts.items(), key=lambda kv: -len(kv[1])):
        count = len(obs)
        first, last = obs[0], obs[-1]
        # Graded by volume: a burst just over the threshold is a probe; an order of
        # magnitude over it is an ongoing campaign.
        severity = Severity.HIGH if count >= threshold * 3 else Severity.MEDIUM
        samples = obs[:3]
        audit.add(Finding(
            check_id="LOG-001",
            title=f"{count} failed authentications from {address}",
            severity=severity,
            assertion=(
                f"{count} authentication failures were recorded from {address}, "
                f"first at {first.source}:{first.lineno} and most recently at "
                f"{last.source}:{last.lineno}."
            ),
            rationale=(
                "A single failure is noise; a concentration from one source is someone "
                "working through a password list. The volume and the source are what make "
                "this actionable — the count alone is not."
            ),
            remediation=(
                f"Confirm the activity is not a scheduled scan. If it is not, block "
                f"{address} at the perimeter and disable password authentication for "
                "accounts reachable from outside."
            ),
            reachability=Reachability.REMOTE_UNAUTH,
            confidence=Confidence.CONFIRMED,
            evidence=tuple(
                _text("LOG-001", o.source, f"line {o.lineno}", o.line,
                      f"failure from {address}") for o in samples
            ),
            references=("CIS 4.8",),
            attacked_via=("T1110.001",),
            tags=("logs", "authentication", "brute-force"),
        ))

    # LOG-002 — the ordering matters and is the whole point.
    first_success: dict[str, Observation] = {}
    for obs in successes:
        if obs.address and obs.address not in first_success:
            first_success[obs.address] = obs

    fired = False
    for address, obs in bursts.items():
        success = first_success.get(address)
        if success is None:
            continue
        if success.seq < obs[0].seq:
            # Authenticated BEFORE the burst — the ordinary shape of a working
            # session, not a compromise. Reported as a note, never as a finding.
            audit.note(
                f"{address} authenticated successfully before its failure burst; that "
                "ordering does not indicate a compromise and is not reported as one."
            )
            continue
        fired = True
        audit.add(Finding(
            check_id="LOG-002",
            title=f"Successful authentication from {address} after {len(obs)} failures",
            severity=Severity.CRITICAL,
            assertion=(
                f"{address} failed {len(obs)} times, then succeeded at "
                f"{success.source}:{success.lineno}."
            ),
            rationale=(
                "A burst of failures followed by a success from the same source is the "
                "signature of a successful guess or a credential-stuffing hit — not of a "
                "user who mistyped. This is the ordering that distinguishes the two, and "
                "it is why the failures and the success are correlated rather than "
                "counted separately."
            ),
            remediation=(
                f"Treat {address} as a possible compromise: review what the session did, "
                "rotate the credentials involved, and confirm the account was not modified."
            ),
            reachability=Reachability.REMOTE_UNAUTH,
            confidence=Confidence.LIKELY,
            evidence=(
                _text("LOG-002", success.source, f"line {success.lineno}", success.line,
                      f"accepted from {address} after {len(obs)} failures"),
                _text("LOG-002", obs[-1].source, f"line {obs[-1].lineno}", obs[-1].line,
                      "most recent failure from the same source"),
            ),
            preconditions=(
                "The address is not behind a shared NAT or proxy, which would let one "
                "host's failures precede another's success.",
            ),
            false_positive_notes=(
                "Shared egress addresses (office NAT, VPN concentrator, cloud egress) "
                "produce this pattern benignly."
            ),
            references=("CIS 4.8", "ATT&CK T1078"),
            attacked_via=("T1110",),
            tags=("logs", "authentication", "compromise"),
        ))

    if not fired:
        audit.ran("LOG-002")


# ── LOG-003: service crashes ─────────────────────────────────────────────────

def check_crashes(audit: Audit) -> None:
    crashes = [o for o in audit.observations if o.kind == "crash"]
    if not audit.inputs_read:
        audit.skip("LOG-003", "no readable system or kernel log")
        return
    audit.ran("LOG-003")
    if not crashes:
        return

    # One finding per source rather than one per line: a service in a crash loop
    # produces hundreds of lines and would otherwise bury every other finding.
    by_source: dict[str, list[Observation]] = {}
    for obs in crashes:
        by_source.setdefault(obs.source, []).append(obs)

    for source, obs in by_source.items():
        first = obs[0]
        severe = any(_SEVERE_CRASH.search(o.line) for o in obs)
        audit.add(Finding(
            check_id="LOG-003",
            title=f"{len(obs)} crash or fault line(s) in {source}",
            severity=Severity.HIGH if severe else Severity.MEDIUM,
            assertion=(
                f"{source} records {len(obs)} crash, fault or fatal-error line(s), the "
                f"first at line {first.lineno}."
            ),
            rationale=(
                "A crash is a availability event, but a memory fault or a kernel panic is "
                "also a possible exploit outcome. Grouping them by source keeps a crash "
                "loop from burying every other finding in the report."
            ),
            remediation="Correlate against deploys and config changes; a repeat fault is worth investigating as more than a bug.",
            reachability=Reachability.LOCAL,
            confidence=Confidence.CONFIRMED,
            evidence=tuple(
                _text("LOG-003", o.source, f"line {o.lineno}", o.line, "crash or fault")
                for o in obs[:3]
            ),
            tags=("logs", "availability"),
        ))


# ── LOG-004: instruction-like content (the taint showcase) ───────────────────

def check_instruction_like(audit: Audit) -> None:
    """Report text in logs that reads like an instruction.

    This is the check the suite exists to demonstrate. The text is NOT stripped and
    NOT obeyed: it is reported, with its detector names, as evidence that something
    wrote agent-directed content into a place an agent reads.
    """
    hits = [o for o in audit.observations if o.kind == "instruction"]
    if not audit.inputs_read:
        audit.skip("LOG-004", "no readable log to scan for instruction-like content")
        return
    audit.ran("LOG-004")
    if not hits:
        return

    by_source: dict[str, list[Observation]] = {}
    for obs in hits:
        by_source.setdefault(obs.source, []).append(obs)

    for source, obs in by_source.items():
        detectors = sorted({name for o in obs for name in o.detector_flags})
        first = obs[0]
        audit.add(Finding(
            check_id="LOG-004",
            title=f"Instruction-like content in {source}",
            severity=Severity.HIGH,
            assertion=(
                f"{len(obs)} line(s) in {source} match instruction-like patterns "
                f"({', '.join(detectors)}). The content was treated as DATA and not obeyed."
            ),
            rationale=(
                "Log content is written by whatever can reach the log: a username, a URL, "
                "a user-agent, a referrer. Text in a log that reads like a directive to an "
                "agent is therefore an attempt by something outside this host to influence "
                "whatever reads it — including a language model summarising these logs. It "
                "is reported rather than removed, because the attempt itself is the signal, "
                "and because silently stripping it would hide that it happened."
            ),
            remediation=(
                "Identify which field carried the text and which process wrote the line. "
                "Treat the origin as hostile input; do not act on anything the line "
                "purports to instruct."
            ),
            reachability=Reachability.REMOTE_UNAUTH,
            confidence=Confidence.CONFIRMED,
            evidence=tuple(
                _text("LOG-004", o.source, f"line {o.lineno}", o.line,
                      f"matched: {', '.join(o.detector_flags)}")
                for o in obs[:3]
            ),
            false_positive_notes=(
                "Ordinary traffic can match a detector by coincidence — a page title, a "
                "bug report pasted into a ticket, a security scanner's own probe. The "
                "detector names in the evidence say WHY it matched, so a human can judge."
            ),
            tags=("logs", "injection", "taint"),
        ))
        audit.note(
            "Instruction-like content was found in log data and reported as a finding. "
            "It was never interpreted: no directive appearing inside log text is "
            "executed or followed by this tool."
        )


def run_all(root: str = "/", include_info: bool = False, max_lines: int = 20000,
            failure_threshold: int = 5) -> Audit:
    core()  # bind the contract before any check builds a Finding
    audit = Audit(root, max_lines, failure_threshold)

    readable = 0
    for relative in LOG_FILES:
        lines = audit.tail(relative, "LOG-001")
        if lines is None:
            continue
        readable += 1
        _scan(audit, relative, lines)

    if not readable:
        audit.skip("LOG-005", "no log file was readable under the fixed path list")
        audit.note(
            "No log was read at all. Nothing in this report supports any conclusion about "
            "this host's activity."
        )

    check_authentication(audit)
    check_crashes(audit)
    check_instruction_like(audit)

    audit.limitations.append(
        "Only the checks listed in coverage.checks_run were attempted. This triage does not "
        "parse binary logs, does not follow rotated or compressed archives, does not read "
        "the systemd journal, and makes no attempt to reconstruct a complete event timeline."
    )
    return audit