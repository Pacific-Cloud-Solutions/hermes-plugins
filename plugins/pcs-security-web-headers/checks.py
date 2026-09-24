"""The checks. Read-only, local, evidence-citing.

Everything here reads web server configuration. Nothing connects to anything:
this does not fetch a page or test a URL. Configuration is where the intent
lives, it covers every route rather than one, and it is where a fix belongs.

Four things are easy to get wrong and are done deliberately:

**nginx `add_header` does not merge — it replaces.** A `location` block that
declares ANY `add_header` of its own **discards every `add_header` inherited from
its `server` and `http` parents**. So a hardened server-level configuration plus
one innocuous `add_header X-Robots-Tag` inside a location silently un-hardens that
location. This is the single most common way a site looks protected and is not,
and it is invisible to any check that merely greps for the header's name. It is
reported as `HDR-010`, and it is the reason this plugin parses blocks rather than
lines.

**HSTS is only meaningful over TLS.** Reporting a missing HSTS header on a
plaintext listener is noise. The check is scoped to server blocks that actually
declare TLS.

**`Header set` and `Header always set` are not the same in Apache.** Without
`always`, the header is not applied to error responses — so a 500 page is served
without the protections the rest of the site has. Recorded, not treated as
equivalent.

**A policy that names `unsafe-inline` is mostly decorative.** A CSP that permits
inline script still blocks nothing that matters, because inline injection is the
primary vector. Naming the directive is not the same as enforcing it.
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
CONFIG_FILES = (
    "etc/nginx/nginx.conf",
    "etc/apache2/apache2.conf",
    "etc/apache2/conf-enabled/security.conf",
    "etc/httpd/conf/httpd.conf",
    "etc/httpd/conf.d/security.conf",
)
CONFIG_GLOBS = (
    "etc/nginx/conf.d/*.conf",
    "etc/nginx/sites-enabled/*",
    "etc/apache2/sites-enabled/*.conf",
    "etc/apache2/conf-enabled/*.conf",
    "etc/httpd/conf.d/*.conf",
)

#: The headers this audit cares about, keyed lowercase.
SECURITY_HEADERS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "CSP",
    "x-content-type-options": "MIME-sniffing protection",
    "x-frame-options": "clickjacking protection",
    "referrer-policy": "referrer leakage control",
    "permissions-policy": "feature restriction",
}

#: HSTS is only meaningful over TLS, and the minimum useful max-age is six months.
_HSTS_MIN_AGE = 15552000          # 180 days, the value browsers honour for preload
_HSTS_STRONG_AGE = 31536000       # 1 year

_NGINX_BLOCK = re.compile(r"^(server|location|http|if)\b\s*([^{]*?)\s*\{\s*$", re.I)
_NGINX_ADD_HEADER = re.compile(
    r"^add_header\s+([A-Za-z0-9_\-]+)\s+(.*?)(?:\s+always)?\s*;\s*$", re.I)
_NGINX_TLS = re.compile(r"\b(listen\s+[^;]*\bssl\b|ssl_certificate\b|ssl_protocols\b)", re.I)
_NGINX_TOKENS_ON = re.compile(r"^server_tokens\s+(on|build|string)", re.I)

_APACHE_VHOST = re.compile(r"^<VirtualHost\s+([^>]*)>", re.I)
_APACHE_VHOST_END = re.compile(r"^</VirtualHost>", re.I)
_APACHE_HEADER = re.compile(
    r"^Header\s+(?:(always|onsuccess)\s+)?(set|add|append|unset)\s+"
    r"([A-Za-z0-9_\-]+)\s*(.*?)\s*$", re.I)
_APACHE_TLS = re.compile(r"\b(SSLEngine\s+on|SSLCertificateFile\b)", re.I)
_APACHE_TOKENS = re.compile(r"^ServerTokens\s+(Full|OS|Minimal|Major|Prod|Minor)", re.I)

_CSP_WEAKNESSES = (
    ("unsafe-inline", "permits inline script or style, which is the primary injection vector"),
    ("unsafe-eval", "permits dynamic code evaluation"),
    ("*", "allows any origin"),
    ("data:", "allows data: URIs as a script source"),
    ("http:", "allows plaintext origins"),
)


@dataclass
class Block:
    """One configuration block, with the headers it declares itself."""

    kind: str                    # "server" | "vhost" | "location" | "global"
    arg: str = ""
    source: str = ""
    lineno: int = 0
    raw: str = ""
    tls: bool = False
    headers: dict = field(default_factory=dict)   # lowercase name -> (value, source, lineno, raw)
    parent: Any = None           # enclosing Block, or None at the top level

    def describe(self) -> str:
        return f"{self.kind} {self.arg}".strip()


class Audit:
    """Accumulates findings and — just as importantly — what it could not check."""

    def __init__(self, root: str = "/") -> None:
        self.root = Path(root).resolve()
        self.findings: list = []
        self.checks_run: list[str] = []
        self.checks_skipped: list[tuple[str, str]] = []
        self.inputs_read: list[str] = []
        self.limitations: list[str] = []
        self.blocks: list[Block] = []
        self.tokens_on: list[tuple[str, int, str]] = []
        self._evaluated: set[str] = set()

    # -- bookkeeping ---------------------------------------------------------
    def ran(self, *check_ids: str) -> None:
        for cid in check_ids:
            if cid not in self.checks_run:
                self.checks_run.append(cid)

    def evaluated(self, *check_ids: str) -> None:
        self._evaluated.update(check_ids)

    def skip(self, check_id: str, reason: str) -> None:
        self.checks_skipped.append((check_id, reason))

    def add(self, finding) -> None:
        self.findings.append(finding)

    def note(self, text: str) -> None:
        if text not in self.limitations:
            self.limitations.append(text)

    def settle(self) -> None:
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
            return None                     # absence is reported by the caller
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
        """Expand a FIXED glob under the root.

        Uses `root.glob(pattern)` rather than globbing the parent directory: a
        pattern with a `*` in the MIDDLE has a literal `*` in
        `Path(pattern).parent`, which is not a directory, so parent-relative
        globbing silently returns nothing.
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

    def config_files(self) -> list[str]:
        out: list[str] = []
        for rel in CONFIG_FILES:
            try:
                if self.path(rel).is_file():
                    out.append(rel)
            except ValueError:
                continue
        for pattern in CONFIG_GLOBS:
            for rel in self.glob(pattern):
                if rel not in out:
                    out.append(rel)
        return out


def _text(check_id, source, locator, value, note) -> Any:
    """Every value read off disk is UNTRUSTED — see README, 'Why nothing is LOCAL'.

    Annotated `Any`, not `Evidence`: `Evidence` is a module-level name bound by
    `core()` on first use, so it is a value at import time, not a type.
    """
    return Evidence(source=source, locator=locator, note=note,
                    observed=quarantine(value, Provenance.UNTRUSTED))


# ── parsing ──────────────────────────────────────────────────────────────────

def parse_nginx(audit: Audit, relative: str) -> None:
    """Block-aware nginx parse.

    Line-oriented and brace-tracked. Single-line blocks (`location / { add_header
    X Y; }`) are not decomposed — recorded as a limitation rather than guessed at.
    """
    text = audit.read(relative, "HDR-001")
    if text is None:
        return
    stack: list[Block] = []
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        while line.startswith("}"):
            if stack:
                stack.pop()
            line = line[1:].strip()
        if not line:
            continue

        opened = _NGINX_BLOCK.match(line)
        if opened:
            block = Block(kind=opened.group(1).lower(), arg=opened.group(2),
                          source=relative, lineno=lineno, raw=line)
            block.parent = stack[-1] if stack else None      # type: ignore[attr-defined]
            stack.append(block)
            audit.blocks.append(block)
            continue

        declared = _NGINX_ADD_HEADER.match(line)
        if declared:
            name, value = declared.group(1).lower(), (declared.group(2) or "").strip()
            if stack:
                stack[-1].headers[name] = (value, relative, lineno, line)
            continue

        if _NGINX_TLS.search(line) and stack:
            stack[-1].tls = True
        if _NGINX_TOKENS_ON.match(line):
            audit.tokens_on.append((relative, lineno, line))


def parse_apache(audit: Audit, relative: str) -> None:
    """Apache parse. VirtualHost blocks become 'server' blocks with TLS scoping."""
    text = audit.read(relative, "HDR-001")
    if text is None:
        return
    current: Block | None = None
    global_block = Block(kind="global", source=relative, lineno=1, raw="(global)")
    audit.blocks.append(global_block)

    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        opened = _APACHE_VHOST.match(line)
        if opened:
            current = Block(kind="server", arg=opened.group(1), source=relative,
                            lineno=lineno, raw=line)
            current.parent = global_block                    # type: ignore[attr-defined]
            audit.blocks.append(current)
            continue
        if _APACHE_VHOST_END.match(line):
            current = None
            continue

        declared = _APACHE_HEADER.match(line)
        if declared:
            modifier, action, name, value = (
                declared.group(1) or "", declared.group(2).lower(),
                declared.group(3).lower(), (declared.group(4) or "").strip().strip('"'))
            target = current or global_block
            if action != "unset":
                target.headers[name] = (value, relative, lineno, line)
            if modifier and modifier.lower() != "always":
                audit.note(
                    f"{relative}:{lineno} declares a header with `{modifier}` rather than "
                    "`always`, so it is not applied to error responses."
                )
            continue

        if _APACHE_TLS.search(line):
            (current or global_block).tls = True
        if _APACHE_TOKENS.match(line):
            audit.tokens_on.append((relative, lineno, line))


def server_blocks(audit: Audit) -> list[Block]:
    return [b for b in audit.blocks if b.kind == "server"]


def _effective_headers(audit: Audit, block: Block) -> dict:
    """Headers in force for a block.

    Apache `Header` set in the global scope applies to a vhost unless the vhost
    overrides the same name, so the two merge. nginx `add_header` does NOT merge
    across levels — that replacement rule is reported by HDR-010 rather than being
    silently folded in here, because "the parent declares it" and "the route sends
    it" are different facts and conflating them is the bug this plugin exists to
    catch.
    """
    inherited: dict = {}
    global_block = next((b for b in audit.blocks if b.kind == "global"), None)
    if global_block is not None and global_block is not block:
        inherited.update(global_block.headers)
    inherited.update(block.headers)
    return inherited


# ── HDR-001..009: the declared headers themselves ────────────────────────────

def check_block(audit: Audit, block: Block, include_info: bool) -> None:
    headers = _effective_headers(audit, block)
    where = f"{block.source}:{block.lineno}"

    def declared(name: str):
        return headers.get(name)

    # HDR-001 / HDR-002 — HSTS, only where TLS is actually configured.
    if block.tls:
        hsts = declared("strict-transport-security")
        audit.evaluated("HDR-001")
        if hsts is None:
            audit.add(Finding(
                check_id="HDR-001",
                title="HSTS is not declared on a TLS server",
                severity=Severity.HIGH,
                assertion=f"{where} serves TLS but declares no Strict-Transport-Security header.",
                rationale=(
                    "Without HSTS a client may reach the site over plaintext first, and every "
                    "request in that window is exposed to interception and stripping. HSTS is "
                    "what makes the TLS requirement unremovable from the client's side."
                ),
                remediation="Declare `Strict-Transport-Security: max-age=31536000; includeSubDomains` on every TLS server block.",
                reachability=Reachability.REMOTE_UNAUTH,
                confidence=Confidence.CONFIRMED,
                evidence=(_text("HDR-001", block.source, f"line {block.lineno}", block.raw,
                                "TLS server block declares no HSTS"),),
                references=("RFC 6797", "CIS 3.9"),
                tags=("http", "headers", "tls"),
            ))
        else:
            value, source, lineno, raw = hsts
            found = re.search(r"max-age\s*=\s*(\d+)", value, re.I)
            age = int(found.group(1)) if found else 0
            if age < _HSTS_MIN_AGE:
                audit.evaluated("HDR-002")
                audit.add(Finding(
                    check_id="HDR-002",
                    title=f"HSTS max-age is only {age} second(s)",
                    severity=Severity.MEDIUM,
                    assertion=f"{source}:{lineno} sets an HSTS max-age below the 180-day minimum.",
                    rationale=(
                        "A short max-age is repeatedly refreshed by the server, so it works in "
                        "practice — but it provides no protection during the first visit, and it "
                        "disqualifies the host from the preload list, which is the only way to "
                        "protect a user who has never visited the site."
                    ),
                    remediation=f"Raise max-age to at least {_HSTS_STRONG_AGE} (one year).",
                    reachability=Reachability.REMOTE_UNAUTH,
                    evidence=(_text("HDR-002", source, f"line {lineno}", raw,
                                    f"max-age={age}"),),
                    references=("RFC 6797",),
                    tags=("http", "headers", "tls"),
                ))
            if "includesubdomains" not in value.lower():
                audit.evaluated("HDR-002")
                audit.add(Finding(
                    check_id="HDR-002",
                    title="HSTS does not cover subdomains",
                    severity=Severity.LOW,
                    assertion=f"{source}:{lineno} omits includeSubDomains.",
                    rationale=(
                        "A subdomain left outside the HSTS policy remains reachable over "
                        "plaintext, and an attacker who can answer for it can set cookies that "
                        "the parent domain will accept."
                    ),
                    remediation="Add `includeSubDomains` once every subdomain serves HTTPS.",
                    reachability=Reachability.REMOTE_UNAUTH,
                    evidence=(_text("HDR-002", source, f"line {lineno}", raw,
                                    "no includeSubDomains"),),
                    tags=("http", "headers", "tls"),
                ))
    else:
        audit.skip("HDR-001", f"{where} does not declare TLS; HSTS is not applicable")

    # HDR-003 / HDR-004 — CSP.
    csp = declared("content-security-policy")
    audit.evaluated("HDR-003")
    if csp is None:
        audit.add(Finding(
            check_id="HDR-003",
            title="Content-Security-Policy is not declared",
            severity=Severity.MEDIUM,
            assertion=f"{where} declares no Content-Security-Policy.",
            rationale=(
                "CSP is the only response header that constrains what a page may load and "
                "execute, so it is the one that limits the damage from an injected script. "
                "Without it, a single injection point is a full compromise."
            ),
            remediation="Declare a CSP, starting in report-only mode if the site is not yet ready to enforce it.",
            reachability=Reachability.REMOTE_UNAUTH,
            evidence=(_text("HDR-003", block.source, f"line {block.lineno}", block.raw,
                            "no CSP declared"),),
            references=("CIS 3.11",),
            tags=("http", "headers"),
        ))
    else:
        value, source, lineno, raw = csp
        weak = [(token, why) for token, why in _CSP_WEAKNESSES
                if re.search(rf"(?<![\w-]){re.escape(token)}", value, re.I)]
        if weak:
            audit.evaluated("HDR-004")
            names = ", ".join(token for token, _ in weak)
            audit.add(Finding(
                check_id="HDR-004",
                title=f"Content-Security-Policy is weakened by {names}",
                severity=Severity.MEDIUM,
                assertion=f"{source}:{lineno} declares a CSP containing {names}.",
                rationale=(
                    "A policy that permits inline script or any origin still permits the "
                    "injection it exists to stop, so it is present without doing the work. "
                    + " ".join(f"`{token}` {why}." for token, why in weak)
                ),
                remediation="Remove the weakening directives and use a nonce or hash for the inline script that genuinely needs it.",
                reachability=Reachability.REMOTE_UNAUTH,
                confidence=Confidence.LIKELY,
                evidence=(_text("HDR-004", source, f"line {lineno}", raw,
                                f"CSP contains {names}"),),
                false_positive_notes="Report-only policies are intentionally permissive while being rolled out.",
                tags=("http", "headers"),
            ))

    # HDR-005 — X-Content-Type-Options.
    xcto = declared("x-content-type-options")
    audit.evaluated("HDR-005")
    if xcto is None or "nosniff" not in xcto[0].lower():
        audit.add(Finding(
            check_id="HDR-005",
            title="X-Content-Type-Options is missing or not `nosniff`",
            severity=Severity.MEDIUM,
            assertion=f"{where} does not declare `X-Content-Type-Options: nosniff`.",
            rationale=(
                "Without `nosniff` a browser may reinterpret an uploaded file as script based "
                "on its content, which turns a file upload into stored cross-site scripting."
            ),
            remediation="Declare `X-Content-Type-Options: nosniff` for all responses.",
            reachability=Reachability.REMOTE_UNAUTH,
            evidence=(_text("HDR-005", block.source, f"line {block.lineno}", block.raw,
                            "no nosniff"),),
            tags=("http", "headers"),
        ))

    # HDR-006 — framing protection, satisfied by either mechanism.
    xfo = declared("x-frame-options")
    csp_frames = csp is not None and "frame-ancestors" in csp[0].lower()
    audit.evaluated("HDR-006")
    if xfo is None and not csp_frames:
        audit.add(Finding(
            check_id="HDR-006",
            title="No clickjacking protection is declared",
            severity=Severity.MEDIUM,
            assertion=f"{where} declares neither X-Frame-Options nor a CSP `frame-ancestors`.",
            rationale=(
                "Without either, the site can be framed by an attacker's page and its controls "
                "used as invisible buttons — a clickjacking attack that the victim cannot see."
            ),
            remediation="Declare `X-Frame-Options: DENY` (or SAMEORIGIN), or set `frame-ancestors` in the CSP.",
            reachability=Reachability.REMOTE_UNAUTH,
            evidence=(_text("HDR-006", block.source, f"line {block.lineno}", block.raw,
                            "no framing protection"),),
            tags=("http", "headers"),
        ))

    # HDR-007 — referrer policy.
    ref = declared("referrer-policy")
    audit.evaluated("HDR-007")
    if ref is None or ref[0].strip().lower() in ("unsafe-url", ""):
        audit.add(Finding(
            check_id="HDR-007",
            title="Referrer-Policy is missing or unsafe",
            severity=Severity.LOW,
            assertion=f"{where} does not declare a safe Referrer-Policy.",
            rationale=(
                "The default policy leaks the full URL of the page — including any token or "
                "identifier in the path or query — to every third party it links out to."
            ),
            remediation="Declare `Referrer-Policy: strict-origin-when-cross-origin` or stricter.",
            reachability=Reachability.REMOTE_UNAUTH,
            evidence=(_text("HDR-007", block.source, f"line {block.lineno}", block.raw,
                            "no safe referrer policy"),),
            tags=("http", "headers"),
        ))

    # HDR-009 — Permissions-Policy, informational only.
    if include_info and "permissions-policy" not in headers:
        audit.evaluated("HDR-009")
        audit.add(Finding(
            check_id="HDR-009",
            title="Permissions-Policy is not declared",
            severity=Severity.INFO,
            assertion=f"{where} declares no Permissions-Policy.",
            rationale=(
                "Optional, but it is the only way to turn off powerful browser features the "
                "site does not use, so a third-party script cannot silently request them."
            ),
            remediation="Declare a Permissions-Policy denying the features the site does not use.",
            reachability=Reachability.REQUIRES_CHAIN,
            tags=("http", "headers"),
        ))


# ── HDR-008: banner version disclosure ───────────────────────────────────────

def check_version_disclosure(audit: Audit) -> None:
    if not audit.blocks:
        audit.skip("HDR-008", "no web server configuration was readable")
        return
    audit.evaluated("HDR-008")
    for source, lineno, raw in audit.tokens_on:
        audit.add(Finding(
            check_id="HDR-008",
            title="Server advertises its version",
            severity=Severity.LOW,
            assertion=f"{source}:{lineno} enables server version disclosure.",
            rationale=(
                "The exact version identifies which published vulnerabilities apply to this "
                "host. It changes nothing about whether the host is exploitable — it only "
                "removes the work an attacker would do to find out."
            ),
            remediation="Suppress the version banner: nginx `server_tokens off`, Apache `ServerTokens Prod`.",
            reachability=Reachability.REMOTE_UNAUTH,
            confidence=Confidence.CONFIRMED,
            evidence=(_text("HDR-008", source, f"line {lineno}", raw, "version banner enabled"),),
            false_positive_notes="Defense in depth only; obscurity is not a control on its own.",
            tags=("http", "headers", "disclosure"),
        ))


# ── HDR-010: nginx add_header inheritance (the footgun) ──────────────────────

def check_nginx_inheritance(audit: Audit) -> None:
    """A location block's own `add_header` discards every inherited header.

    This is the check that makes the plugin worth having. Grepping for a header's
    name finds it in the parent block and reports the site as protected — while the
    route that actually serves user content has silently dropped it.
    """
    servers = [b for b in audit.blocks if b.kind == "server" and b.headers]
    if not servers:
        audit.skip("HDR-010", "no nginx server block declares headers, so inheritance cannot be evaluated")
        return
    audit.evaluated("HDR-010")

    for server in servers:
        children = [b for b in audit.blocks
                    if b.kind == "location" and getattr(b, "parent", None) is server and b.headers]
        if not children:
            continue
        lost_all: list[tuple[Block, list[str]]] = []
        for child in children:
            lost = [name for name in server.headers if name not in child.headers]
            if lost:
                lost_all.append((child, lost))
        if not lost_all:
            continue

        child, lost = lost_all[0]
        pretty = ", ".join(SECURITY_HEADERS.get(n, n) for n in sorted(lost))
        audit.add(Finding(
            check_id="HDR-010",
            title=f"`add_header` in a location block discards {len(lost)} inherited header(s)",
            severity=Severity.HIGH,
            assertion=(
                f"{child.source}:{child.lineno} declares its own `add_header`, which in nginx "
                f"replaces rather than merges — so {pretty} from {server.source}:{server.lineno} "
                f"do not apply to this location. "
                f"{len(lost_all)} of {len(children)} location block(s) are affected."
            ),
            rationale=(
                "nginx's `add_header` does not accumulate across levels: a block that declares "
                "ANY `add_header` of its own inherits NONE from its parents. So adding one "
                "innocuous header inside a location silently removes the security headers the "
                "server block set — and every name-based header scan still finds them in the "
                "parent and reports the site as protected. This is the most common way a site "
                "looks hardened and is not. It can only be found by parsing blocks."
            ),
            remediation=(
                "Re-declare the security headers inside each affected location block, or move "
                "the location's own `add_header` up to the server block so the sets stay equal."
            ),
            reachability=Reachability.REMOTE_UNAUTH,
            confidence=Confidence.CONFIRMED,
            evidence=(
                _text("HDR-010", child.source, f"line {child.lineno}", child.raw,
                      "location block declares its own add_header"),
                _text("HDR-010", server.source, f"line {server.lineno}", server.raw,
                      "server block whose headers are discarded"),
            ),
            references=("nginx: add_header inheritance",),
            tags=("http", "headers", "nginx"),
        ))


def run_all(root: str = "/", include_info: bool = False) -> Audit:
    core()  # bind the contract before any check builds a Finding
    audit = Audit(root)

    files = audit.config_files()
    if not files:
        audit.skip("HDR-001", "no nginx or Apache configuration found under the fixed paths")
        audit.note(
            "No web server configuration was read, so nothing is known about the headers this "
            "host declares. Absence of findings here is not evidence of a hardened site."
        )
    for relative in files:
        lowered = relative.lower()
        if "nginx" in lowered:
            parse_nginx(audit, relative)
        elif "apache" in lowered or "httpd" in lowered:
            parse_apache(audit, relative)

    if files:
        nginx = [b for b in audit.blocks if b.kind in ("server", "location")]
        apache = any("apache" in f.lower() or "httpd" in f.lower() for f in files)
        if not nginx and not apache:
            audit.note(
                "Configuration files were found but no server or VirtualHost block was parsed; "
                "single-line block syntax is not decomposed by this parser."
            )
        for block in server_blocks(audit):
            check_block(audit, block, include_info)
        if not server_blocks(audit):
            audit.skip("HDR-001", "no server block was parsed in any readable configuration")
        check_nginx_inheritance(audit)
        check_version_disclosure(audit)

    audit.settle()
    audit.limitations.append(
        "Only the checks listed in coverage.checks_run were attempted. This audit reads "
        "DECLARED configuration: it does not fetch a page, does not follow an include or a "
        "proxy to another host, does not evaluate a templating layer, and cannot see a header "
        "added by application code rather than by the web server."
    )
    return audit