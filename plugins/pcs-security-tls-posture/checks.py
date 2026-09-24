"""The checks. Read-only, local, evidence-citing.

Everything here reads files. Nothing connects to anything: this parses
certificates and TLS directives on disk, and never performs a handshake. That is
a deliberate scope line — a tool that negotiated TLS with a host would be a
network scanner with a different liability profile entirely.

Three things are easy to get wrong and are done deliberately:

**An expired certificate is not always the interesting one.** A certificate with
three days left is a scheduled outage; one that expired two years ago belongs to
a service nobody is running. Both are reported, but the near-expiry case is
graded higher, because a human can still act on it.

**A cipher string is a list of OFFERS and EXCLUSIONS.** `HIGH:!aNULL:!MD5` is a
hardened configuration that names MD5 *in order to disable it*. A scanner that
greps the line for `MD5` and files a finding has reported the fix as the bug.
Exclusions (`!`), removals (`-`) and modifiers (`+`, `@`) are skipped.

**Absent is not permissive here, and not safe either.** A server with no
`ssl_protocols` directive falls back to its own default, which this tool cannot
see. That is recorded as a coverage limitation, never as a pass.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
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
_core_cache: list = []


def core():
    """Load pcs-security-core, bind its symbols into this module, and return it.

    Cached after the first success. Raises if pcs-security-core cannot be found.
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
CERT_GLOBS = (
    "etc/ssl/certs/*.pem",
    "etc/ssl/certs/*.crt",
    "etc/pki/tls/certs/*.pem",
    "etc/pki/tls/certs/*.crt",
    "etc/pki/tls/certs/localhost.crt",
    "etc/letsencrypt/live/*/cert.pem",
)
CONFIG_FILES = (
    "etc/nginx/nginx.conf",
    "etc/apache2/apache2.conf",
    "etc/httpd/conf/httpd.conf",
)
CONFIG_GLOBS = (
    "etc/nginx/conf.d/*.conf",
    "etc/nginx/sites-enabled/*",
    "etc/apache2/sites-enabled/*.conf",
    "etc/apache2/mods-enabled/ssl.conf",
    "etc/httpd/conf.d/*.conf",
    "etc/httpd/conf.modules.d/*.conf",
)

_PROTOCOL_DIRECTIVE = re.compile(r"^\s*(ssl_protocols|SSLProtocol)\s+(.+?);?\s*$")
_CIPHER_DIRECTIVE = re.compile(r"^\s*(ssl_ciphers|SSLCipherSuite)\s+(.+?);?\s*$")

#: Exact tokens, compared after case-folding. Matching these as substrings would
#: flag `TLSv1.2` on the `TLSv1` pattern — the mistake that makes a scanner
#: report a hardened host as broken.
_WEAK_PROTOCOLS = {
    "SSLV2": "SSL 2.0",
    "SSLV3": "SSL 3.0",
    "TLSV1": "TLS 1.0",
    "TLSV1.0": "TLS 1.0",
    "TLSV1.1": "TLS 1.1",
}

#: Substrings looked for inside an OFFERED cipher (never inside an exclusion).
_WEAK_CIPHER_TOKENS = ("RC4", "3DES", "DES", "NULL", "EXPORT", "MD5", "ANON", "ADH")

#: Signature algorithms that are broken or deprecated for certificate signing.
_WEAK_SIGNATURE_ALGOS = ("md5", "sha1")

#: A key this short is factorable; below the first threshold it is a finding
#: regardless, below the second it is urgent.
_RSA_CRITICAL_BITS = 1024
_RSA_MIN_BITS = 2048
_EC_MIN_BITS = 224


@dataclass
class CertInfo:
    """What could be established about one certificate.

    `detail` records HOW MUCH was established, so a check with no input can be
    recorded as skipped rather than silently treated as passing.
    """

    subject: str = ""
    issuer: str = ""
    not_before: datetime | None = None
    not_after: datetime | None = None
    key_type: str = ""
    key_bits: int | None = None
    sig_algo: str = ""
    self_signed: bool = False
    detail: str = "dates"      # "full" when a real X.509 parser ran


class Audit:
    """Accumulates findings and — just as importantly — what it could not check."""

    def __init__(self, root: str = "/", expiry_days: int = 30) -> None:
        self.root = Path(root).resolve()
        self.expiry_days = expiry_days
        self.findings: list = []
        self.checks_run: list[str] = []
        self.checks_skipped: list[tuple[str, str]] = []
        self.inputs_read: list[str] = []
        self.limitations: list[str] = []
        self._evaluated: set[str] = set()

    # -- bookkeeping ---------------------------------------------------------
    def ran(self, *check_ids: str) -> None:
        """Record that a check RAN — i.e. had real input to evaluate."""
        for cid in check_ids:
            if cid not in self.checks_run:
                self.checks_run.append(cid)

    def evaluated(self, *check_ids: str) -> None:
        """Note a check had input; promoted to `checks_run` by `settle()`."""
        self._evaluated.update(check_ids)

    def skip(self, check_id: str, reason: str) -> None:
        self.checks_skipped.append((check_id, reason))

    def add(self, finding) -> None:
        self.findings.append(finding)

    def note(self, text: str) -> None:
        if text not in self.limitations:
            self.limitations.append(text)

    def settle(self) -> None:
        """Promote evaluated checks to 'ran'.

        Called once at the end, so a check that had input but produced no finding
        is still reported as having run — 'no findings for these checks' must mean
        the checks actually executed, or the verdict is a lie.
        """
        self.ran(*sorted(self._evaluated))

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
        """Expand a FIXED glob under the root, returning relative paths.

        Uses `root.glob(pattern)` rather than globbing the parent directory: a
        pattern with a `*` in the MIDDLE (`etc/letsencrypt/live/*/cert.pem`) has a
        literal `*` in `Path(pattern).parent`, which is not a directory, so
        parent-relative globbing silently returns nothing — and the check then
        reports "no certificate material found" for a host that has some.
        """
        out: list[str] = []
        for candidate in sorted(self.root.glob(pattern)):
            if not candidate.is_file():
                continue
            resolved = candidate.resolve()
            if self.root not in resolved.parents:
                continue                  # a symlink pointing outside the audit root
            out.append(str(candidate.relative_to(self.root)))
        return out

    def cert_files(self) -> list[str]:
        """Expand the certificate glob list, de-duplicated and ordered."""
        seen: list[str] = []
        for pattern in CERT_GLOBS:
            for rel in self.glob(pattern):
                if rel not in seen:
                    seen.append(rel)
        return seen

    def config_files(self) -> list[str]:
        """Expand the server-config list: fixed paths plus fixed globs."""
        out: list[str] = []
        for rel in CONFIG_FILES:
            if self.path(rel).is_file() and rel not in out:
                out.append(rel)
        for pattern in CONFIG_GLOBS:
            for rel in self.glob(pattern):
                if rel not in out:
                    out.append(rel)
        return out

    # -- certificate decoding ------------------------------------------------
    def load_cert(self, relative: str) -> CertInfo | None:
        """Decode one certificate. Records a SKIP (never a pass) when it cannot."""
        path = self.path(relative)
        try:
            raw = path.read_bytes()
        except PermissionError:
            self.skip("TLS-001", f"{relative}: permission denied")
            return None
        except OSError as exc:
            self.skip("TLS-001", f"{relative}: {exc.strerror or exc}")
            return None

        if relative not in self.inputs_read:
            self.inputs_read.append(relative)

        info = _decode_full(raw)
        if info is not None:
            return info

        info = _decode_dates_only(path)
        if info is not None:
            self.note(
                "A full X.509 parser (the `cryptography` package) is not importable, so "
                "key size and signature algorithm could not be read; only certificate "
                "validity was evaluated for every certificate in this run."
            )
            return info

        self.skip("TLS-001", f"{relative}: not a decodable PEM certificate")
        return None


def _text(check_id, source, locator, value, note) -> Any:
    """Every value read off disk is UNTRUSTED — see README, 'Why nothing is LOCAL'.

    Annotated `Any`, not `Evidence`: `Evidence` is a module-level name bound by
    `core()` on first use, so it is a value at import time, not a type.
    """
    return Evidence(source=source, locator=locator, note=note,
                    observed=quarantine(value, Provenance.UNTRUSTED))


def _as_utc(value) -> datetime | None:
    """Normalise whatever a parser returned into an aware UTC datetime."""
    if value is None:
        return None
    if isinstance(value, str):
        from email.utils import parsedate_to_datetime
        try:
            value = parsedate_to_datetime(value)
        except (TypeError, ValueError):
            return None
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _decode_full(raw: bytes) -> CertInfo | None:
    """Decode with `cryptography` when available — the only path giving key size."""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
    except Exception:
        return None
    try:
        cert = x509.load_pem_x509_certificate(raw)
    except Exception:
        return None

    def stamp(*names):
        for name in names:
            value = getattr(cert, name, None)
            if value is not None:
                return _as_utc(value)
        return None

    key_type = ""
    key_bits: int | None = None
    try:
        pub = cert.public_key()
        if isinstance(pub, rsa.RSAPublicKey):
            key_type, key_bits = "RSA", pub.key_size
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            key_type, key_bits = "EC", pub.key_size
        elif isinstance(pub, dsa.DSAPublicKey):
            key_type, key_bits = "DSA", pub.key_size
        else:
            key_type = type(pub).__name__
            key_bits = getattr(pub, "key_size", None)
    except Exception:
        pass

    sig_algo = ""
    try:
        digest = cert.signature_hash_algorithm
        sig_algo = getattr(digest, "name", "") or ""
    except Exception:
        # Ed25519/Ed448 have no separate hash; that is not a weakness.
        pass

    def name_of(attribute) -> str:
        try:
            return attribute.rfc4514_string()
        except Exception:
            return ""

    subject, issuer = name_of(cert.subject), name_of(cert.issuer)
    return CertInfo(
        subject=subject,
        issuer=issuer,
        not_before=stamp("not_valid_before_utc", "not_valid_before"),
        not_after=stamp("not_valid_after_utc", "not_valid_after"),
        key_type=key_type,
        key_bits=key_bits,
        sig_algo=sig_algo,
        self_signed=bool(subject) and subject == issuer,
        detail="full",
    )


def _decode_dates_only(path: Path) -> CertInfo | None:
    """Standard-library fallback. Gives validity and names, NOT key size or sig."""
    import ssl
    decode = getattr(getattr(ssl, "_ssl", None), "_test_decode_cert", None)
    if decode is None:
        return None
    try:
        info = decode(str(path))
    except Exception:
        return None

    def flat(field) -> str:
        parts = []
        for rdn in info.get(field, ()) or ():
            for key, value in rdn:
                parts.append(f"{key}={value}")
        return ", ".join(parts)

    subject, issuer = flat("subject"), flat("issuer")
    return CertInfo(
        subject=subject,
        issuer=issuer,
        not_before=_as_utc(info.get("notBefore")),
        not_after=_as_utc(info.get("notAfter")),
        self_signed=bool(subject) and subject == issuer,
        detail="dates",
    )


# ── certificates ─────────────────────────────────────────────────────────────

def check_certificates(audit: Audit) -> None:
    files = audit.cert_files()
    if not files:
        audit.skip("TLS-001", "no certificate files found under the fixed search paths")
        audit.note(
            "No certificate material was found in the standard locations. On macOS the "
            "system trust store lives in the Keychain and is not a directory of PEM "
            "files, so it is not covered by this check."
        )
        return

    now = datetime.now(timezone.utc)
    full_detail = False

    for rel in files:
        info = audit.load_cert(rel)
        if info is None:
            continue
        if info.detail == "full":
            full_detail = True

        # TLS-003 — not yet valid
        if info.not_before is not None:
            audit.evaluated("TLS-003")
            if info.not_before > now:
                audit.add(Finding(
                    check_id="TLS-003",
                    title="Certificate is not valid yet",
                    severity=Severity.MEDIUM,
                    assertion=f"{rel} has a notBefore in the future.",
                    rationale=(
                        "A certificate presented before its validity window is rejected by "
                        "every conforming client, so whatever service holds it fails TLS "
                        "for every visitor until the window opens."
                    ),
                    remediation="Check the issuing clock and reissue, or correct the system time on the issuer.",
                    reachability=Reachability.REMOTE_UNAUTH,
                    evidence=(_text("TLS-003", rel, "notBefore",
                                    info.not_before.isoformat(), "start of validity"),),
                    references=("RFC 5280 4.1.2.5",),
                    tags=("tls", "certificate"),
                ))

        # TLS-001 — expired
        if info.not_after is not None:
            audit.evaluated("TLS-001")
            if info.not_after < now:
                age = (now - info.not_after).days
                audit.add(Finding(
                    check_id="TLS-001",
                    title="Certificate has expired",
                    severity=Severity.HIGH,
                    assertion=f"{rel} expired {age} day(s) ago.",
                    rationale=(
                        "An expired certificate is refused by conforming clients, so the "
                        "service fails closed. It is reported as a posture finding rather "
                        "than an outage because the same file indicates whether anything "
                        "is still serving it."
                    ),
                    remediation="Renew the certificate, or remove the file if the service it belonged to is gone.",
                    reachability=Reachability.REMOTE_UNAUTH,
                    evidence=(_text("TLS-001", rel, "notAfter",
                                    info.not_after.isoformat(), f"expired {age} day(s) ago"),),
                    references=("RFC 5280 4.1.2.5",),
                    tags=("tls", "certificate"),
                ))
            elif (info.not_after - now).days <= audit.expiry_days:
                # `.days` floors: with 9 days 23 hours left this reports 9. That
                # understates the remaining time by less than a day, erring toward
                # urgency rather than complacency, which is the right direction for
                # a renewal deadline.
                remaining = (info.not_after - now).days
                audit.evaluated("TLS-002")
                audit.add(Finding(
                    check_id="TLS-002",
                    title=f"Certificate expires in {remaining} day(s)",
                    severity=Severity.HIGH if remaining <= 7 else Severity.MEDIUM,
                    assertion=f"{rel} expires on {info.not_after.date().isoformat()}.",
                    rationale=(
                        "Renewal is a scheduled action, and the lead time is the whole "
                        "point: at seven days or fewer this becomes an outage the operator "
                        "can no longer plan around. Reported here while it is still fixable."
                    ),
                    remediation="Renew before expiry and confirm the renewal is automated.",
                    reachability=Reachability.REMOTE_UNAUTH,
                    evidence=(_text("TLS-002", rel, "notAfter",
                                    info.not_after.isoformat(), f"{remaining} day(s) remaining"),),
                    references=("CIS 3.10",),
                    tags=("tls", "certificate", "expiry"),
                ))

        # TLS-004 — key strength (needs a full parser)
        if info.key_bits is not None and info.key_type in ("RSA", "DSA", "EC"):
            audit.evaluated("TLS-004")
            weak = False
            if info.key_type in ("RSA", "DSA") and info.key_bits < _RSA_MIN_BITS:
                weak = True
            if info.key_type == "EC" and info.key_bits < _EC_MIN_BITS:
                weak = True
            if weak:
                critical = info.key_type in ("RSA", "DSA") and info.key_bits < _RSA_CRITICAL_BITS
                audit.add(Finding(
                    check_id="TLS-004",
                    title=f"{info.key_type} key is only {info.key_bits} bits",
                    severity=Severity.CRITICAL if critical else Severity.HIGH,
                    assertion=f"{rel} is signed with a {info.key_bits}-bit {info.key_type} key.",
                    rationale=(
                        "Key size sets the cost of recovering the private key. Below the "
                        "threshold an adversary with modest resources can forge signatures "
                        "for this certificate, which breaks trust for every client that "
                        "accepts it."
                    ),
                    remediation="Reissue with an RSA key of at least 2048 bits, or an EC key on P-256 or stronger.",
                    reachability=Reachability.REMOTE_UNAUTH,
                    evidence=(_text("TLS-004", rel, f"{info.key_type} key size",
                                    f"{info.key_bits} bits", "below the accepted minimum"),),
                    references=("NIST SP 800-57", "CIS 3.3"),
                    attacked_via=("T1552.004",),
                    tags=("tls", "crypto", "certificate"),
                ))
        elif info.detail == "dates":
            audit.skip("TLS-004", f"{rel}: key size needs a full X.509 parser (not importable)")

        # TLS-005 — signature algorithm (needs a full parser)
        if info.sig_algo:
            audit.evaluated("TLS-005")
            if info.sig_algo.lower() in _WEAK_SIGNATURE_ALGOS:
                audit.add(Finding(
                    check_id="TLS-005",
                    title=f"Certificate is signed with {info.sig_algo.upper()}",
                    severity=Severity.HIGH,
                    assertion=f"{rel} carries a {info.sig_algo.upper()} signature.",
                    rationale=(
                        "Chosen-prefix collisions in these digests allow an attacker to "
                        "produce a second certificate with the same signature, so a "
                        "certificate can no longer be relied on to be the one that was "
                        "issued."
                    ),
                    remediation="Reissue using SHA-256 or stronger.",
                    reachability=Reachability.REMOTE_UNAUTH,
                    evidence=(_text("TLS-005", rel, "signatureAlgorithm",
                                    info.sig_algo, "deprecated digest"),),
                    references=("CIS 3.3",),
                    tags=("tls", "crypto", "certificate"),
                ))
        elif info.detail == "dates":
            audit.skip("TLS-005", f"{rel}: signature algorithm needs a full X.509 parser (not importable)")

        # TLS-006 — self-signed
        if info.self_signed and info.subject:
            audit.evaluated("TLS-006")
            audit.add(Finding(
                check_id="TLS-006",
                title="Certificate is self-signed",
                severity=Severity.LOW,
                assertion=f"{rel} has an issuer identical to its subject.",
                rationale=(
                    "No public client trusts this certificate, so it can only be serving "
                    "internal traffic. That is legitimate in some deployments and an "
                    "unmanaged hand-rolled certificate in others — the distinction needs "
                    "a human, which is why this is reported rather than graded."
                ),
                remediation="Confirm the certificate is intended for internal use, or issue one from a trusted authority.",
                reachability=Reachability.REQUIRES_CHAIN,
                confidence=Confidence.LIKELY,
                evidence=(_text("TLS-006", rel, "issuer", info.issuer, "issuer equals subject"),),
                false_positive_notes="Legitimate for internal-only services, development, and pinned clients.",
                tags=("tls", "certificate"),
            ))

    if not full_detail:
        audit.note(
            "Certificate validity was evaluated for every file found, but key size and "
            "signature algorithm were not — those checks are recorded as skipped, not passed."
        )


# ── server TLS directives ────────────────────────────────────────────────────

def _offered_ciphers(value: str) -> list[str]:
    """Ciphers a config actually OFFERS.

    Exclusions (`!`), removals (`-`) and modifiers (`+`, `@`) are not offers: a
    string that names a weak cipher in order to disable it is hardened, and
    reporting it would be reporting the fix as the bug.
    """
    out: list[str] = []
    for token in value.split(":"):
        token = token.strip().strip('";')
        if not token or token[0] in "!-+@":
            continue
        upper = token.upper()
        if any(weak in upper for weak in _WEAK_CIPHER_TOKENS):
            out.append(token)
    return out


def _named_protocols(value: str) -> list[tuple[str, str]]:
    """Protocols a config actually ENABLES, as (raw token, human label).

    Two traps here, and both were caught by the harness rather than by review:

    **Substring matching is wrong.** `TLSv1` is a substring of `TLSv1.2`, so a
    regex tuned for the weak name flags hardened hosts. Tokens are compared
    whole.

    **The two servers use opposite polarity.** nginx writes the versions it
    ENABLES (`ssl_protocols TLSv1.2 TLSv1.3;`). Apache writes `SSLProtocol all
    -SSLv3 -TLSv1 -TLSv1.1` — a hardened config that names the weak versions in
    order to REMOVE them. A leading `-` (removal) or `!` (exclusion) means the
    version is disabled, so reporting it would be reporting the fix as the bug.
    A bare or `+`-prefixed token is enabled.
    """
    out: list[tuple[str, str]] = []
    for token in re.split(r"[\s,:;]+", value):
        token = token.strip().strip('";')
        if not token:
            continue
        if token[0] in "-!":
            continue                      # removed / excluded, not enabled
        bare = token.lstrip("+").upper()
        if bare in _WEAK_PROTOCOLS:
            out.append((token, _WEAK_PROTOCOLS[bare]))
    return out


def check_server_config(audit: Audit, include_info: bool) -> None:
    files = audit.config_files()
    if not files:
        audit.skip("TLS-010", "no nginx or Apache configuration found under the fixed paths")
        audit.note(
            "No server configuration was found, so nothing is known about which TLS "
            "protocol versions or cipher suites anything on this host offers."
        )
        return

    saw_protocol_directive = False
    saw_cipher_directive = False

    for rel in files:
        text = audit.read(rel, "TLS-010")
        if text is None:
            continue
        for lineno, raw in enumerate(text.splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            m = _PROTOCOL_DIRECTIVE.match(line)
            if m:
                directive, value = m.group(1), m.group(2).strip()
                weak = _named_protocols(value)
                if weak:
                    saw_protocol_directive = True
                    labels = ", ".join(sorted({label for _, label in weak}))
                    audit.evaluated("TLS-010")
                    worst = "TLS 1.1"
                    severity = Severity.HIGH if any(
                        label != worst for _, label in weak) else Severity.MEDIUM
                    audit.add(Finding(
                        check_id="TLS-010",
                        title=f"Deprecated TLS version enabled: {labels}",
                        severity=severity,
                        assertion=f"`{directive}` at {rel}:{lineno} permits {labels}.",
                        rationale=(
                            "Each of these versions has published protocol-level breaks "
                            "(renegotiation, padding, or downgrade) that a client cannot "
                            "defend against on its own. A server that will still negotiate "
                            "them can be steered down to one."
                        ),
                        remediation=f"Remove the deprecated versions from `{directive}` and require TLS 1.2 or later.",
                        reachability=Reachability.REMOTE_UNAUTH,
                        evidence=(_text("TLS-010", rel, f"line {lineno}", line,
                                        f"permits {labels}"),),
                        preconditions=("The server must be reachable on this listener for the downgrade to be attempted.",),
                        references=("CIS 3.1", "RFC 7525"),
                        attacked_via=("T1040",),
                        tags=("tls", "configuration"),
                    ))
                elif value:
                    saw_protocol_directive = True
                    audit.evaluated("TLS-010")
                continue

            m = _CIPHER_DIRECTIVE.match(line)
            if m:
                directive, value = m.group(1), m.group(2).strip()
                if value:
                    saw_cipher_directive = True
                    audit.evaluated("TLS-011")
                offered = _offered_ciphers(value)
                if offered:
                    shown = ", ".join(offered[:4])
                    if len(offered) > 4:
                        shown += f" (+{len(offered) - 4} more)"
                    # Substring, not equality: the served token is the full suite
                    # name (`RC4-SHA`), never the bare marker. An equality test here
                    # silently downgrades every finding to MEDIUM — caught by
                    # inspecting real handler output, not by the harness.
                    severity = Severity.HIGH if any(
                        marker in suite.upper()
                        for suite in offered
                        for marker in ("RC4", "NULL", "EXPORT", "ANON", "ADH")
                    ) else Severity.MEDIUM
                    audit.add(Finding(
                        check_id="TLS-011",
                        title=f"Weak cipher suite offered: {shown}",
                        severity=severity,
                        assertion=f"`{directive}` at {rel}:{lineno} offers {len(offered)} weak suite(s).",
                        rationale=(
                            "These suites are either breakable with feasible effort or "
                            "provide no authentication at all. Because a client chooses "
                            "from what the server offers, a broken suite left enabled is a "
                            "downgrade target for anyone who can influence the handshake."
                        ),
                        remediation=f"Remove the weak suites from `{directive}`; keep the modern set and any `!` exclusions.",
                        reachability=Reachability.REMOTE_UNAUTH,
                        evidence=(_text("TLS-011", rel, f"line {lineno}", line,
                                        f"offers {shown}"),),
                        preconditions=("The server must be reachable on this listener for the downgrade to be attempted.",),
                        false_positive_notes=(
                            "Only OFFERED suites are reported. A `!` exclusion names a suite in order to "
                            "disable it and is never counted."
                        ),
                        references=("CIS 3.2", "RFC 7525"),
                        attacked_via=("T1040",),
                        tags=("tls", "crypto", "configuration"),
                    ))
                continue

    if include_info and not saw_protocol_directive:
        if any(_is_tls_server_config(audit, rel) for rel in files):
            audit.ran("TLS-012")
            audit.add(Finding(
                check_id="TLS-012",
                title="No explicit TLS version restriction found",
                severity=Severity.INFO,
                assertion="A TLS-enabled server configuration was found with no protocol directive.",
                rationale=(
                    "The effective protocol set is whatever the server's own compiled "
                    "default is, which this tool cannot read. An explicit directive is the "
                    "only way to know, and to be able to say so later."
                ),
                remediation="State the permitted protocols explicitly so the posture is auditable.",
                reachability=Reachability.REMOTE_UNAUTH,
                confidence=Confidence.SUSPECTED,
                false_positive_notes="A default that already excludes old versions is still a hidden dependency on the build.",
                tags=("tls", "configuration"),
            ))

    if not saw_cipher_directive:
        audit.skip("TLS-011", "no cipher directive found in any readable server configuration")


def _is_tls_server_config(audit: Audit, rel: str) -> bool:
    """Cheap check that a config actually concerns TLS before filing an INFO."""
    text = audit.read(rel, "TLS-012")
    if not text:
        return False
    lowered = text.lower()
    return any(marker in lowered for marker in (
        "ssl_protocols", "ssl_certificate", "ssl_ciphers",
        "sslprotocol", "sslciphersuite", "sslcertificatefile", "listen 443",
    ))


def run_all(root: str = "/", include_info: bool = False, expiry_days: int = 30) -> Audit:
    core()  # bind the contract before any check builds a Finding
    audit = Audit(root, expiry_days)
    check_certificates(audit)
    check_server_config(audit, include_info)
    audit.settle()
    audit.limitations.append(
        "Only the checks listed in coverage.checks_run were attempted. This audit does not "
        "connect to any service, does not perform a handshake, does not enumerate listeners, "
        "and does not read private key material."
    )
    return audit