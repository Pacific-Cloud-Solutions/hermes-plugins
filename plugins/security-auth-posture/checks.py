"""The checks. Read-only, local, evidence-citing.

Two things here are easy to get wrong and are done deliberately:

**sshd_config is first-match-wins, with Include processed in place.** OpenSSH
uses the FIRST obtained value for each keyword. A parser that keeps the last
occurrence reports the wrong effective setting, and — because most distributions
put `Include /etc/ssh/sshd_config.d/*.conf` at the TOP of the file — it inverts
the answer for drop-in-managed hosts.

**The path list is fixed.** `_resolve()` will not return anything outside it, so
the tool cannot be talked into reading /etc/shadow or an SSH private key by a
caller that supplies a path. That is the difference between an audit tool and an
arbitrary-file-read primitive wearing an audit tool's schema.
"""
from __future__ import annotations

import base64
import re
import stat
from pathlib import Path

from typing import Any

from .bootstrap import load

# Bound by core() on first use — deliberately left None at import time.
#
# `hermes plugins doctor` and `hermes plugins validate` copy the plugin into a
# temp directory and run it in ISOLATION, so a sibling `security-core/` is not on
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
_core_cache: list = []


def core():
    """Load security-core, bind its symbols into this module, and return it.

    Cached after the first success. Raises if security-core cannot be found.
    """
    global Confidence, Evidence, Finding, Provenance, Reachability, Severity, quarantine
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
    _core_cache.append(module)
    return module

# ── The only paths this tool will ever read. Relative to the audit root. ──────
SSHD_CONFIG = "etc/ssh/sshd_config"
SSHD_DROPIN_GLOB = "etc/ssh/sshd_config.d/*.conf"
SUDOERS = "etc/sudoers"
SUDOERS_GLOB = "etc/sudoers.d/*"
PASSWD = "etc/passwd"
HOME_PARENTS = ("home", "Users")

_KEY_TYPES = (
    "ssh-rsa", "ssh-dss", "ssh-ed25519", "ssh-ed448",
    "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com",
)
_WEAK_CIPHERS = ("3des-cbc", "arcfour", "arcfour128", "arcfour256", "blowfish-cbc", "cast128-cbc")
_WEAK_MACS = ("hmac-md5", "hmac-md5-96", "hmac-sha1-96", "umac-64@openssh.com", "hmac-ripemd160")
_WEAK_KEX = ("diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1")


class Audit:
    """Accumulates findings and — just as importantly — what it could not check."""

    def __init__(self, root: str = "/") -> None:
        self.root = Path(root).resolve()
        self.findings: list = []
        self.checks_run: list[str] = []
        self.checks_skipped: list[tuple[str, str]] = []
        self.inputs_read: list[str] = []
        self.limitations: list[str] = []

    # -- bookkeeping ---------------------------------------------------------
    def ran(self, *check_ids: str) -> None:
        for cid in check_ids:
            if cid not in self.checks_run:
                self.checks_run.append(cid)

    def skip(self, check_id: str, reason: str) -> None:
        self.checks_skipped.append((check_id, reason))

    def add(self, finding) -> None:
        self.findings.append(finding)

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

    def glob(self, pattern: str) -> list[str]:
        """Expand a FIXED glob under the root, returning relative paths."""
        base = self.root / Path(pattern).parent
        if not base.is_dir():
            return []
        out = []
        for p in sorted(base.glob(Path(pattern).name)):
            if p.is_file():
                out.append(str(p.relative_to(self.root)))
        return out


def _text(check_id, source, locator, value, note) -> Evidence:
    """Every value read off disk is UNTRUSTED — see README, 'Why nothing is LOCAL'."""
    return Evidence(source=source, locator=locator, note=note,
                    observed=quarantine(value, Provenance.UNTRUSTED))


# ── sshd_config ──────────────────────────────────────────────────────────────

_INCLUDE = re.compile(r"^include\s+(.+)$", re.I)


def _sshd_lines(audit: Audit, relative: str, depth: int = 0):
    """Yield (source, lineno, text) with Include expanded in place."""
    if depth > 4:
        audit.limitations.append(f"Include nesting deeper than 4 at {relative}; not followed")
        return
    text = audit.read(relative, "SSH-CONFIG")
    if text is None:
        return
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = _INCLUDE.match(line)
        if m:
            target = m.group(1).strip()
            if target.startswith("/"):
                base_rel = target.lstrip("/")
                for rel in audit.glob(base_rel):
                    yield from _sshd_lines(audit, rel, depth + 1)
            else:
                parent = str(Path(relative).parent)
                for rel in audit.glob(str(Path(parent) / target)):
                    yield from _sshd_lines(audit, rel, depth + 1)
            continue
        yield relative, lineno, line


def effective_sshd(audit: Audit) -> dict:
    """{keyword: (value, source, lineno)} using OpenSSH's first-match-wins rule."""
    options: dict = {}
    for source, lineno, line in _sshd_lines(audit, SSHD_CONFIG):
        parts = line.split(None, 1)
        key = parts[0].lower()
        value = parts[1].strip() if len(parts) > 1 else ""
        if key not in options:          # FIRST wins
            options[key] = (value, source, lineno)
    return options


def check_ssh(audit: Audit, include_info: bool) -> None:
    options = effective_sshd(audit)
    if not options:
        audit.skip("SSH-001", "no readable sshd_config; SSH posture not evaluated")
        audit.limitations.append("SSH checks depend on sshd_config, which was unavailable.")
        return

    def val(key):
        return options.get(key, (None, None, None))[0]

    def ev(key, note):
        value, source, lineno = options[key]
        return _text("SSH", source, f"line {lineno}", f"{key} {value}", note)

    password_auth = (val("passwordauthentication") or "").lower() == "yes"
    permit_root = (val("permitrootlogin") or "").lower()

    # `without-password` is an alias for `prohibit-password` (key-only) — NOT a finding.
    if permit_root == "yes":
        severity = Severity.CRITICAL if password_auth else Severity.HIGH
        audit.add(Finding(
            check_id="SSH-001",
            title="SSH allows direct root login",
            severity=severity,
            assertion="PermitRootLogin is set to `yes`, so the root account can authenticate over SSH.",
            rationale=(
                "Root is the first account every SSH brute-force attempt tries, and a "
                "success is immediate full control with no privilege escalation step."
            ),
            remediation="Set `PermitRootLogin prohibit-password` (or `no`) and use a named account with sudo.",
            reachability=Reachability.REMOTE_UNAUTH if password_auth else Reachability.REMOTE_AUTH,
            evidence=(ev("permitrootlogin", "root login explicitly permitted"),),
            preconditions=(("Port 22 is reachable from an untrusted network",) if password_auth else
                           ("The attacker holds a key authorised for root",)),
            false_positive_notes=(
                "Fires only on the literal value `yes`. `prohibit-password` and "
                "`without-password` are key-only and are not reported."
            ),
            references=("CIS 5.2.8", "MITRE T1078.003"),
            attacked_via=("T1078.003", "T1110"),
            tags=("ssh", "credentials"),
        ))
    audit.ran("SSH-001")

    if password_auth:
        audit.add(Finding(
            check_id="SSH-002",
            title="SSH accepts password authentication",
            severity=Severity.MEDIUM,
            assertion="PasswordAuthentication is set to `yes`.",
            rationale=(
                "Password auth makes every account on the host brute-forceable, and one "
                "credential reused anywhere else becomes a way in."
            ),
            remediation="Set `PasswordAuthentication no` once key-based access is confirmed working.",
            reachability=Reachability.REMOTE_UNAUTH,
            evidence=(ev("passwordauthentication", "password auth enabled"),),
            false_positive_notes="Not reported when the keyword is absent (the modern default is `no`).",
            references=("CIS 5.2.10",),
            attacked_via=("T1110",),
            tags=("ssh", "credentials"),
        ))
    audit.ran("SSH-002")

    if (val("permitemptypasswords") or "").lower() == "yes":
        audit.add(Finding(
            check_id="SSH-003",
            title="SSH permits empty passwords",
            severity=Severity.CRITICAL,
            assertion="PermitEmptyPasswords is set to `yes`.",
            rationale="Any account with a blank password becomes an unauthenticated login.",
            remediation="Set `PermitEmptyPasswords no` and give every account a password or lock it.",
            reachability=Reachability.REMOTE_UNAUTH,
            evidence=(ev("permitemptypasswords", "empty passwords permitted"),),
            references=("CIS 5.2.11",),
            attacked_via=("T1078.003",),
            tags=("ssh", "credentials"),
        ))
    audit.ran("SSH-003")

    if (val("permituserenvironment") or "").lower() == "yes":
        audit.add(Finding(
            check_id="SSH-004",
            title="SSH reads per-user environment files",
            severity=Severity.MEDIUM,
            assertion="PermitUserEnvironment is set to `yes`, so ~/.ssh/environment can set variables for the session.",
            rationale=(
                "An attacker who can write to a home directory can influence the "
                "session environment — a common step in LD_PRELOAD-style escalation."
            ),
            remediation="Set `PermitUserEnvironment no` unless a specific application requires it.",
            reachability=Reachability.REQUIRES_CHAIN,
            evidence=(ev("permituserenvironment", "user environment accepted"),),
            preconditions=("Attacker already has write access to a user's home directory",),
            references=("CIS 5.2.12",),
            attacked_via=("T1574",),
            tags=("ssh", "environment"),
        ))
    audit.ran("SSH-004")

    if (val("x11forwarding") or "").lower() == "yes":
        audit.add(Finding(
            check_id="SSH-005",
            title="SSH X11 forwarding is enabled",
            severity=Severity.LOW,
            assertion="X11Forwarding is set to `yes`.",
            rationale="Forwarded X11 sessions can be abused to read the display and keystrokes of other sessions.",
            remediation="Set `X11Forwarding no` unless graphical forwarding is required.",
            reachability=Reachability.REMOTE_AUTH,
            evidence=(ev("x11forwarding", "X11 forwarding enabled"),),
            tags=("ssh", "hardening"),
        ))
    audit.ran("SSH-005")

    weak = []
    for key, bad in (("ciphers", _WEAK_CIPHERS), ("macs", _WEAK_MACS),
                     ("kexalgorithms", _WEAK_KEX), ("hostkeyalgorithms", ("ssh-dss",)),
                     ("pubkeyacceptedkeytypes", ("ssh-dss",)), ("pubkeyacceptedalgorithms", ("ssh-dss",))):
        value = val(key)
        if not value:
            continue
        hits = [alg for alg in bad if alg in value.lower()]
        if hits:
            weak.append((key, hits))
    if weak:
        detail = "; ".join(f"{k} includes {', '.join(v)}" for k, v in weak)
        audit.add(Finding(
            check_id="SSH-006",
            title="SSH explicitly allows deprecated cryptographic algorithms",
            severity=Severity.MEDIUM,
            assertion=f"They are named in the configuration: {detail}.",
            rationale="These algorithms are broken or downgradeable; naming them re-enables them for every client.",
            remediation="Remove the weak entries and rely on the modern defaults, or pin a strong explicit list.",
            reachability=Reachability.REMOTE_UNAUTH,
            evidence=tuple(_text("SSH", options[k][1], f"line {options[k][2]}",
                                 f"{k} {options[k][0]}", f"names weak algorithm(s): {', '.join(v)}")
                           for k, v in weak),
            confidence=Confidence.CONFIRMED,
            false_positive_notes="Only reported when the keyword is explicitly set to include a weak algorithm.",
            references=("CIS 5.2.13",),
            tags=("ssh", "crypto"),
        ))
    audit.ran("SSH-006")

    if not include_info:
        return

    if (val("maxauthtries") or "6").strip().isdigit() and int(val("maxauthtries") or 6) > 6:
        audit.add(Finding(
            check_id="SSH-007",
            title="SSH raises the maximum authentication attempts",
            severity=Severity.INFO,
            assertion=f"MaxAuthTries is set to {val('maxauthtries')}.",
            rationale="More attempts per connection widens the window for password guessing.",
            remediation="Leave MaxAuthTries at its default of 6 or lower.",
            evidence=(ev("maxauthtries", "above the default of 6"),),
            tags=("ssh", "hardening"),
        ))
    audit.ran("SSH-007")


# ── file permissions ─────────────────────────────────────────────────────────

def check_permissions(audit: Audit) -> None:
    targets = [SSHD_CONFIG, SUDOERS, PASSWD] + [p for p in audit.glob(SSHD_DROPIN_GLOB)]
    targets += [f"{parent}/{name}/.ssh/authorized_keys"
                for parent in HOME_PARENTS
                for name in _home_names(audit, parent)]
    targets.append("root/.ssh/authorized_keys")
    for rel in targets:
        try:
            path = audit.path(rel)
        except ValueError:
            continue
        if not path.is_file():
            continue
        mode = path.stat().st_mode
        loose = mode & (stat.S_IWGRP | stat.S_IWOTH)
        if loose:
            who = "group" if mode & stat.S_IWGRP else "other"
            audit.add(Finding(
                check_id="PERM-001",
                title=f"{rel} is writable by {who}",
                severity=Severity.HIGH if "authorized_keys" in rel else Severity.HIGH,
                assertion=f"{rel} has mode {stat.filemode(mode)}, so a non-owner can modify it.",
                rationale=(
                    "Whoever can write this file controls authentication. A writable "
                    "authorized_keys is a direct account takeover; a writable sshd_config "
                    "or sudoers is a privilege escalation."
                ),
                remediation=f"chown root:root and chmod 600 {rel} (0644 for sudoers/sshd_config).",
                reachability=Reachability.LOCAL,
                evidence=(Evidence(source=rel, locator=f"mode {oct(mode & 0o7777)}",
                                   note=f"writable by {who}",
                                   observed=quarantine(stat.filemode(mode), Provenance.LOCAL)),),
                references=("CIS 5.1.1", "MITRE T1222"),
                attacked_via=("T1222",),
                tags=("permissions",),
            ))
            audit.ran("PERM-001")
    if "PERM-001" not in audit.checks_run and not audit.checks_skipped:
        audit.ran("PERM-001")


def _home_names(audit: Audit, parent: str) -> list[str]:
    base = audit.root / parent
    if not base.is_dir():
        return []
    return [p.name for p in sorted(base.iterdir()) if p.is_dir()]


# ── authorized_keys ──────────────────────────────────────────────────────────

def _ssh_string(blob: bytes, offset: int) -> tuple[bytes, int]:
    length = int.from_bytes(blob[offset:offset + 4], "big")
    start = offset + 4
    return blob[start:start + length], start + length


def _rsa_bits(blob: bytes) -> int | None:
    """Modulus bit length from an ssh-rsa public key blob."""
    try:
        _, off = _ssh_string(blob, 0)      # "ssh-rsa"
        _, off = _ssh_string(blob, off)    # e
        modulus, _ = _ssh_string(blob, off)
        if not modulus:
            return None
        return int.from_bytes(modulus, "big").bit_length()
    except Exception:
        return None


def check_authorized_keys(audit: Audit) -> None:
    files = [f"{parent}/{name}/.ssh/authorized_keys"
             for parent in HOME_PARENTS for name in _home_names(audit, parent)]
    files.append("root/.ssh/authorized_keys")
    seen = set()
    for rel in files:
        if rel in seen:
            continue
        seen.add(rel)
        text = audit.read(rel, "KEY-001")
        if text is None:
            continue
        for lineno, raw in enumerate(text.splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            tokens = line.split()
            idx = next((i for i, t in enumerate(tokens) if t in _KEY_TYPES), None)
            if idx is None:
                continue
            key_type = tokens[idx]
            blob = tokens[idx + 1] if idx + 1 < len(tokens) else ""
            reason = None
            if key_type == "ssh-dss":
                reason = "DSA keys are fixed at 1024 bits and are no longer considered safe"
            elif key_type == "ssh-rsa" and blob:
                try:
                    bits = _rsa_bits(base64.b64decode(blob, validate=True))
                except Exception:
                    bits = None
                if bits is not None and bits < 2048:
                    reason = f"RSA key is {bits} bits, below the 2048-bit minimum"
            if reason:
                audit.add(Finding(
                    check_id="KEY-001",
                    title=f"Weak public key authorised in {rel}",
                    severity=Severity.HIGH,
                    assertion=f"An {key_type} key on line {lineno} is accepted: {reason}.",
                    rationale=(
                        "A weak key in authorized_keys is an authentication bypass for anyone "
                        "who can factor it — it grants that account directly."
                    ),
                    remediation="Remove the key, and re-issue at least ed25519 or RSA-3072.",
                    reachability=Reachability.REMOTE_AUTH,
                    evidence=(_text("KEY-001", rel, f"line {lineno}",
                                    # Key type + comment identifies the key for a human without
                                    # dumping several hundred characters of base64. The line
                                    # number is the locator if the raw blob is ever needed.
                                    f"{key_type} ({tokens[idx + 2] if len(tokens) > idx + 2 else 'no comment'})",
                                    reason),),
                    confidence=Confidence.CONFIRMED,
                    references=("CIS 5.2.18",),
                    attacked_via=("T1110.001",),
                    tags=("ssh", "keys"),
                ))
        audit.ran("KEY-001")


# ── sudoers ──────────────────────────────────────────────────────────────────

def check_sudoers(audit: Audit) -> None:
    sources = [SUDOERS] + audit.glob(SUDOERS_GLOB)
    parsed_any = False
    for rel in sources:
        text = audit.read(rel, "SUDO-001")
        if text is None:
            continue
        parsed_any = True
        for lineno, raw in enumerate(text.splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith("#") or line.lower().startswith("defaults"):
                continue
            if "nopasswd" in line.lower():
                allcmds = re.search(r"nopasswd\s*:\s*all\b", line, re.I) or re.search(r"\ball\b\s*$", line.strip(), re.I)
                audit.add(Finding(
                    check_id="SUDO-001",
                    title=f"Passwordless sudo entry in {rel}",
                    severity=Severity.HIGH if allcmds else Severity.MEDIUM,
                    assertion="A sudoers rule grants commands without requiring the user's password.",
                    rationale=(
                        "NOPASSWD turns any compromise of that account — or of a process running "
                        "as it — into unattended privilege escalation."
                    ),
                    remediation="Remove NOPASSWD where possible, or restrict the entry to one exact command path.",
                    reachability=Reachability.LOCAL,
                    evidence=(_text("SUDO-001", rel, f"line {lineno}", line,
                                    "grants sudo without a password"),),
                    false_positive_notes=(
                        "Common and intentional on some hosts (CI runners, kiosks, break-glass "
                        "accounts). Treat as a deliberate-risk finding, not a defect."
                    ),
                    references=("CIS 1.3.1",),
                    attacked_via=("T1548.003",),
                    tags=("sudo", "privilege"),
                ))
            if "*" in line and "=" in line:
                audit.add(Finding(
                    check_id="SUDO-002",
                    title=f"Wildcard in a sudoers command path in {rel}",
                    severity=Severity.HIGH,
                    assertion="A sudoers rule authorises a command path containing a wildcard.",
                    rationale=(
                        "A wildcard such as /usr/bin/vim* matches sibling binaries and argument "
                        "tricks, which is a well-known route from a narrow rule to a root shell."
                    ),
                    remediation="Replace the wildcard with the exact, fully-qualified command path.",
                    reachability=Reachability.LOCAL,
                    evidence=(_text("SUDO-002", rel, f"line {lineno}", line,
                                    "command path contains a wildcard"),),
                    confidence=Confidence.LIKELY,
                    false_positive_notes="Argument wildcards inside a quoted command are legitimate; review the entry.",
                    references=("CIS 1.3.1",),
                    attacked_via=("T1548.003",),
                    tags=("sudo", "privilege"),
                ))
    if parsed_any:
        audit.ran("SUDO-001", "SUDO-002")
        audit.limitations.append(
            "sudoers is parsed line-oriented: aliases, Defaults and multi-line entries are "
            "not resolved, so a rule expressed through an alias may not be reported."
        )
    else:
        audit.skip("SUDO-001", "no readable sudoers file")


# ── accounts ─────────────────────────────────────────────────────────────────

def check_accounts(audit: Audit) -> None:
    text = audit.read(PASSWD, "ACCT-001")
    if text is None:
        return
    for lineno, raw in enumerate(text.splitlines(), 1):
        parts = raw.split(":")
        if len(parts) < 7:
            continue
        name, _, uid, _, _, _, shell = parts[:7]
        if uid == "0" and name != "root":
            audit.add(Finding(
                check_id="ACCT-001",
                title=f"Non-root account with UID 0: {name}",
                severity=Severity.CRITICAL,
                assertion=f"Account {name} has UID 0 and is therefore a second root account.",
                rationale=(
                    "UID 0 bypasses every file permission check. It is also how a "
                    "backdoor account is normally placed, and it survives password changes to root."
                ),
                remediation=f"Confirm {name} is intentional. If not, remove or re-UID the account immediately.",
                reachability=Reachability.LOCAL,
                evidence=(_text("ACCT-001", PASSWD, f"line {lineno}", raw,
                                f"UID 0 account named {name}"),),
                references=("CIS 5.4.1",),
                attacked_via=("T1136.001",),
                tags=("accounts", "persistence"),
            ))
        elif parts[1] == "" and name != "root":
            audit.add(Finding(
                check_id="ACCT-002",
                title=f"Account with an empty password field: {name}",
                severity=Severity.CRITICAL,
                assertion=f"/etc/passwd has no password hash for {name}.",
                rationale="An empty password field means no password is required to log in.",
                remediation=f"Lock the account (`usermod -L {name}`) or set a password.",
                reachability=Reachability.REMOTE_UNAUTH if "sh" in shell else Reachability.LOCAL,
                evidence=(_text("ACCT-002", PASSWD, f"line {lineno}", raw,
                                "no password hash present"),),
                references=("CIS 6.2.1",),
                attacked_via=("T1078.003",),
                tags=("accounts",),
            ))
    audit.ran("ACCT-001", "ACCT-002")


def run_all(root: str = "/", include_info: bool = False) -> Audit:
    core()  # bind the contract before any check builds a Finding
    audit = Audit(root)
    check_ssh(audit, include_info)
    check_permissions(audit)
    check_authorized_keys(audit)
    check_sudoers(audit)
    check_accounts(audit)
    audit.limitations.append(
        "Only the checks listed in coverage.checks_run were attempted. This audit does not "
        "inspect PAM configuration, SSH host keys, running services, open ports, or packages."
    )
    return audit