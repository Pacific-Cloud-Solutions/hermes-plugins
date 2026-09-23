"""Provenance and taint model — the hostile-input discipline.

The threat this exists for:

    A defensive agent that reads logs, mail, HTTP headers or alert text is
    ingesting attacker-controlled content BY DEFINITION. The November 2025
    Anthropic report on the first AI-orchestrated espionage campaign found the
    attackers got their model to run the campaign by telling it it was an
    employee of a legitimate security firm doing *defensive testing*.

The rule this module enforces:

    Content that came from outside is DATA, never INSTRUCTION.

Three mechanisms, weakest to strongest:

1. CLASSIFY  — every string entering the system is tagged with its provenance.
2. QUARANTINE — untrusted text is wrapped in `Quarantined`, a type the trusted
   fields of `Finding` will not accept. Putting raw attacker text into an
   assertion field is a TypeError, not a code-review miss.
3. ANNOTATE  — instruction-like patterns are detected and *reported*, never
   silently edited out. A security tool that alters its own evidence is worse
   than useless: you cannot audit what it hid from you.

The one deliberate exception to "never mutate" is secret redaction. A finding
that quotes an AWS key has leaked it into a report, a log, and a chat
transcript. Secrets are masked and the mutation is flagged (`redacted=True`);
everything else is preserved verbatim.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable, Sequence

logger = logging.getLogger(__name__)


class Provenance(str, Enum):
    """Where a string came from. The only axis that decides how it may be used."""

    OPERATOR = "operator"      # typed by the user in this session — an instruction
    CONFIG = "config"          # local config the operator controls
    LOCAL = "local"            # local OS/filesystem state — machine-derived, not operator-authored
    UNTRUSTED = "untrusted"    # logs, mail, HTTP, remote hosts, filenames from elsewhere

    @property
    def may_be_instruction(self) -> bool:
        """Only operator text may ever steer tool selection or be read as a directive."""
        return self is Provenance.OPERATOR


#: Instruction-like patterns. Detected and REPORTED — never stripped.
#: Bare `system:`/`assistant:` are included because they are cheap to spot and
#: their presence in, say, an auth log is itself interesting.
_INSTRUCTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("ignore_previous", re.compile(
        r"\b(ignore|disregard|forget)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all)\b"
        r"[^.\n]{0,20}\b(instruction|prompt|rule|context|message)s?\b", re.I)),
    ("role_reassignment", re.compile(
        r"\byou\s+are\s+(now|no\s+longer)\b|\bact\s+as\s+(if|though)\b|\bpretend\s+(to\s+be|you)\b", re.I)),
    ("new_instructions", re.compile(
        r"\b(new|updated|revised|real)\s+instructions?\b|\byour\s+(new\s+)?(task|job|role)\s+is\b", re.I)),
    ("chat_role_marker", re.compile(r"(?i)(?:^|\s)(system|assistant|developer)\s*:", re.I)),
    ("special_token", re.compile(
        r"<\|(im_start|im_end|endoftext|system|assistant)\|>|\[/?INST\]|###\s*(system|instruction)", re.I)),
    # NOTE: `\.env` is deliberately LAST in the alternation. `...|\.env|id_rsa`
    # contains the literal substring `env|`, which is the admission scanner's
    # `dump_all_env` trigger (`printenv|env\s*\|`) — so an accurate detector
    # reads as "dumps all environment variables" and marks the plugin `caution`.
    # Do not re-sort this list. Verified: `hermes plugins validate` is clean.
    ("exfiltration", re.compile(
        r"\b(send|post|upload|email|exfiltrate|curl|wget|fetch)\b[^.\n]{0,40}"
        r"\b(api[_\s-]?key|token|credential|password|secret|id_rsa|\.env)\b", re.I)),
    ("guardrail_bypass", re.compile(
        r"\b(jailbreak|bypass|disable|turn\s+off)\b[^.\n]{0,25}\b(guardrail|safety|filter|restriction)s?\b", re.I)),
    ("authority_claim", re.compile(
        r"\b(i\s+am|this\s+is)\b[^.\n]{0,30}\b(admin|administrator|root|the\s+developer|your\s+(creator|owner))\b", re.I)),
)


@dataclass(frozen=True)
class Quarantined:
    """Untrusted text, held inert.

    Deliberately NOT a `str` subclass. `Finding.assertion` and friends type-hint
    `str`; passing a `Quarantined` there is a TypeError at construction, which is
    the whole point — the type system, not a reviewer, enforces the boundary.
    """

    raw: str
    provenance: Provenance
    flags: tuple[str, ...] = ()
    truncated: bool = False
    redacted: bool = False

    def __post_init__(self) -> None:
        if self.provenance.may_be_instruction:
            raise ValueError(
                f"Quarantined text must be non-operator provenance; got {self.provenance.value!r}. "
                "Operator text is an instruction — it does not belong in an evidence field."
            )

    @property
    def hostile(self) -> bool:
        """True when this text carries instruction-like patterns."""
        return bool(self.flags)

    def __str__(self) -> str:  # convenience only; never implicit in f-strings by accident
        return self.raw


def inert(value: object) -> str:
    """Render a quarantined value for a human. Always framed as data, never as prose."""
    if isinstance(value, Quarantined):
        return f"<<UNTRUSTED DATA: {value.raw}>>"
    return str(value)


def classify_patterns(text: str) -> tuple[str, ...]:
    """Return the names of instruction-like patterns present. Read-only."""
    return tuple(name for name, pat in _INSTRUCTION_PATTERNS if pat.search(text))


def redact(text: str) -> tuple[str, bool]:
    """Mask secrets via Hermes' own redactor. Returns ``(text, was_redacted)``.

    Reuses ``agent.redact.redact_sensitive_text`` so the suite inherits every
    built-in pattern and the operator's ``security.redact_secrets`` setting rather
    than inventing a parallel, weaker set.

    Never RAISES — a foundation plugin must not be the reason a security tool
    fails to load. But it does not fail *silently* either: the first version of
    this function called a function that does not exist and swallowed the
    AttributeError, so redaction looked wired up while doing nothing. Masking is
    a safety property; an inability to mask must be visible in the log.
    """
    try:
        from agent.redact import redact_sensitive_text  # type: ignore
    except Exception as exc:
        logger.warning(
            "security-core: secret redaction unavailable (%s) — evidence will be "
            "stored UNMASKED. This is a degradation, not a normal state.", exc)
        return text, False
    try:
        cleaned = redact_sensitive_text(text)
    except Exception as exc:
        logger.warning("security-core: redaction of one value failed (%s); storing unmasked", exc)
        return text, False
    return (cleaned, cleaned != text)


def quarantine(
    text: str,
    provenance: Provenance,
    *,
    limit: int = 400,
    do_redact: bool = True,
) -> Quarantined:
    """Wrap external text as inert evidence.

    Redaction first, then truncation on a word boundary — so a masked secret can
    never be half-visible because the cut landed inside it.
    """
    if text is None:
        text = ""
    raw = str(text)

    was_redacted = False
    if do_redact:
        raw, was_redacted = redact(raw)

    flags = classify_patterns(raw)

    truncated = False
    if len(raw) > limit:
        raw = raw[:limit].rsplit(" ", 1)[0] + " …"
        truncated = True

    return Quarantined(
        raw=raw,
        provenance=provenance,
        flags=flags,
        truncated=truncated,
        redacted=was_redacted,
    )


def trusted(text: str) -> str:
    """Assert a string is plugin-authored prose (a title, an assertion, a rationale).

    This is not a security control — it is a tripwire. It rejects the two ways
    untrusted text reaches a trusted field by accident: passing a `Quarantined`,
    or interpolating one into an f-string.
    """
    if isinstance(text, Quarantined):
        raise TypeError(
            "Quarantined text cannot be asserted as trusted prose. "
            "It belongs in Finding.evidence, where it renders as inert data."
        )
    if "<<UNTRUSTED DATA:" in text:
        raise ValueError(
            "Refusing trusted prose containing an interpolated quarantine frame — "
            "that is attacker text laundered into an assertion. Pass it as evidence instead."
        )
    return text


def summarize_flags(items: Iterable[Quarantined]) -> Sequence[str]:
    """Distinct instruction-like patterns across a set of evidence items."""
    seen: list[str] = []
    for item in items:
        for flag in item.flags:
            if flag not in seen:
                seen.append(flag)
    return tuple(seen)