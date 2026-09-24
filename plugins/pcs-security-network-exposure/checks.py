"""The checks. Read-only, local, evidence-citing.

Everything here reads files. Nothing opens a socket, and no subprocess is run — no
`ss`, no `netstat`, no `lsof`. The kernel's own socket tables are plain text in
`/proc`, which is a better source anyway: it is what those tools read.

Four things are easy to get wrong and are done deliberately:

**The hex in `/proc/net/tcp` is little-endian per 32-bit word.** `0100007F` is
127.0.0.1, not 1.0.0.127. IPv6 is four 32-bit words, each byte-reversed
independently, not one long little-endian value. A decoder that gets this wrong
produces plausible-looking addresses that are simply wrong — which is worse than
failing, because the report reads as authoritative. The harness asserts decoding
against known input for exactly this reason.

**UDP has no LISTEN state.** A bound UDP socket sits in state `07`. Checking for
`0A` on UDP would report every UDP service as absent.

**A wildcard bind is not automatically a finding.** Every SSH daemon on earth
binds every interface, because it is meant to be reachable. The finding is the
*service*: a database or a container socket on every interface is a different
class of problem from a web server in the same position. That distinction is the
entire product — a flat list of listeners is a scanner dump.

**Absent is not safe.** If `/proc` is unavailable and no service configuration is
readable, nothing is known — which is reported as a coverage gap, never as a clean
result.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
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
PROC_TABLES = (
    ("proc/net/tcp", "tcp"),
    ("proc/net/tcp6", "tcp6"),
    ("proc/net/udp", "udp"),
    ("proc/net/udp6", "udp6"),
)

CONFIG_FILES = (
    "etc/mysql/my.cnf",
    "etc/my.cnf",
    "etc/redis/redis.conf",
    "etc/mongod.conf",
    "etc/elasticsearch/elasticsearch.yml",
    "etc/nginx/nginx.conf",
    "etc/apache2/ports.conf",
    "etc/httpd/conf/httpd.conf",
)
CONFIG_GLOBS = (
    "etc/postgresql/*/main/postgresql.conf",
    "etc/nginx/conf.d/*.conf",
    "etc/nginx/sites-enabled/*",
    "etc/apache2/sites-enabled/*.conf",
    "etc/httpd/conf.d/*.conf",
)

#: Services whose exposure beyond loopback is the finding an operator cares about.
#: `severity` is what it is worth when reachable from off-host; the ones marked
#: critical commonly ship with no authentication at all.
_SENSITIVE_PORTS: dict[int, tuple[str, str]] = {
    2375: ("Docker daemon API (unencrypted)", "critical"),
    2376: ("Docker daemon API", "high"),
    2379: ("etcd", "critical"),
    3306: ("MySQL", "high"),
    5432: ("PostgreSQL", "high"),
    5984: ("CouchDB", "critical"),
    6379: ("Redis", "critical"),
    9200: ("Elasticsearch", "critical"),
    9300: ("Elasticsearch transport", "high"),
    11211: ("memcached", "critical"),
    27017: ("MongoDB", "critical"),
}

#: Ports where a wildcard bind is the normal, intended configuration — the
#: service's own protocol definition makes it public. Deliberately narrow: 8080
#: and 8443 are NOT here, because an alternate HTTP port is as often an internal
#: admin surface as a public one, and "worth confirming" is the honest signal.
_EXPECTED_WILDCARD_PORTS = {22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995}

#: (regex, description). Each names a configuration directive that binds a service
#: to every interface. The description is plugin prose; the matched LINE is the
#: evidence.
_WILDCARD_DIRECTIVES = (
    (re.compile(r"^\s*listen_addresses\s*=\s*['\"]?\*", re.I),
     "accepts connections on every interface"),
    (re.compile(r"^\s*bind-address\s*=\s*['\"]?0\.0\.0\.0", re.I),
     "binds every interface"),
    (re.compile(r"^\s*bind\s+0\.0\.0\.0", re.I),
     "binds every interface"),
    (re.compile(r"^\s*bind\s+::\b", re.I),
     "binds every interface"),
    (re.compile(r"^\s*bindIp\s*:.*0\.0\.0\.0", re.I),
     "includes every interface"),
    (re.compile(r"^\s*network\.host\s*:\s*['\"]?0\.0\.0\.0", re.I),
     "binds every interface"),
    (re.compile(r"^\s*listen\s+(?:0\.0\.0\.0:|\[::\]:)?\d+\b[^;]*;", re.I),
     "listens on every interface"),
)


@dataclass
class Listener:
    """One bound socket, decoded from the kernel's own table."""

    proto: str
    address: str
    port: int
    source: str
    locator: str
    raw: str

    @property
    def loopback(self) -> bool:
        try:
            return ipaddress.ip_address(self.address).is_loopback
        except ValueError:
            return False

    @property
    def wildcard(self) -> bool:
        return self.address in ("0.0.0.0", "::")


class Audit:
    """Accumulates findings and — just as importantly — what it could not check."""

    def __init__(self, root: str = "/") -> None:
        self.root = Path(root).resolve()
        self.findings: list = []
        self.checks_run: list[str] = []
        self.checks_skipped: list[tuple[str, str]] = []
        self.inputs_read: list[str] = []
        self.limitations: list[str] = []
        self.listeners: list[Listener] = []
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
        """Promote evaluated checks to 'ran', so 'no findings' means the check executed."""
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
            return None                     # absence recorded by the caller, not here
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

    def glob(self, pattern: str) -> list[str]:
        """Expand a FIXED glob under the root, returning relative paths.

        Uses `root.glob(pattern)` rather than globbing the parent directory: a
        pattern with a `*` in the MIDDLE (`etc/postgresql/*/main/postgresql.conf`)
        has a literal `*` in `Path(pattern).parent`, which is not a directory, so
        parent-relative globbing silently returns nothing. Silent is the problem —
        the check then reports "no configuration found" for a host that has one.
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


def _text(check_id, source, locator, value, note) -> Any:
    """Every value read off disk is UNTRUSTED — see README, 'Why nothing is LOCAL'.

    Annotated `Any`, not `Evidence`: `Evidence` is a module-level name bound by
    `core()` on first use, so it is a value at import time, not a type.
    """
    return Evidence(source=source, locator=locator, note=note,
                    observed=quarantine(value, Provenance.UNTRUSTED))


# ── /proc decoding ───────────────────────────────────────────────────────────

def decode_ipv4(hex_address: str) -> str:
    """`0100007F` -> `127.0.0.1`.

    The kernel writes each 32-bit word in host byte order, so the four octets are
    reversed. Reading the hex left-to-right as a big-endian integer produces
    `1.0.0.127` — a plausible address that is simply wrong.
    """
    packed = bytes.fromhex(hex_address)
    if len(packed) != 4:
        raise ValueError(f"not an IPv4 address: {hex_address!r}")
    return ".".join(str(octet) for octet in reversed(packed))


def decode_ipv6(hex_address: str) -> str:
    """Four 32-bit words, each byte-reversed INDEPENDENTLY.

    Reversing the whole 128-bit value turns `::1` into something that is not `::1`.
    """
    if len(hex_address) != 32:
        raise ValueError(f"not an IPv6 address: {hex_address!r}")
    big_endian = ""
    for i in range(0, 32, 8):
        word = bytes.fromhex(hex_address[i:i + 8])
        big_endian += "".join(f"{octet:02x}" for octet in reversed(word))
    return str(ipaddress.IPv6Address(int(big_endian, 16)))


def _decode_local(proto: str, field: str) -> tuple[str, int]:
    address_hex, _, port_hex = field.partition(":")
    port = int(port_hex, 16)
    address = decode_ipv6(address_hex) if proto.endswith("6") else decode_ipv4(address_hex)
    return address, port


def parse_proc_table(text: str, proto: str, source: str) -> list[Listener]:
    """Parse one /proc/net socket table. Tolerant of short or malformed lines."""
    out: list[Listener] = []
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("sl"):
            continue
        fields = line.split()
        if len(fields) < 4:
            continue
        local, state = fields[1], fields[3].upper()
        # TCP bound sockets are LISTEN (0A). UDP has no LISTEN: a bound UDP socket
        # sits in CLOSE (07), so requiring 0A would report every UDP service absent.
        listening = state == "0A" if "tcp" in proto else state == "07"
        if not listening:
            continue
        try:
            address, port = _decode_local(proto, local)
        except (ValueError, IndexError):
            continue
        out.append(Listener(proto=proto, address=address, port=port,
                            source=source, locator=f"line {lineno}", raw=line))
    return out


# ── NET-001 / NET-002 / NET-004: the listeners themselves ────────────────────

def check_listeners(audit: Audit, include_info: bool) -> None:
    if not audit.listeners:
        return

    seen: set[tuple[str, str, int]] = set()
    for listener in audit.listeners:
        key = (listener.proto, listener.address, listener.port)
        if key in seen:
            continue
        seen.add(key)

        if listener.loopback:
            if include_info:
                audit.evaluated("NET-004")
                audit.add(Finding(
                    check_id="NET-004",
                    title=f"{listener.proto}/{listener.port} is bound to loopback only",
                    severity=Severity.INFO,
                    assertion=f"{listener.address}:{listener.port} ({listener.proto}) accepts loopback connections only.",
                    rationale="A loopback-only listener is not reachable from off-host and is not an exposure.",
                    remediation="No action implied; reported only so the listening set is complete.",
                    reachability=Reachability.LOCAL,
                    evidence=(_text("NET-004", listener.source, listener.locator, listener.raw,
                                    f"{listener.proto}/{listener.port} on {listener.address}"),),
                    tags=("network", "listener"),
                ))
            continue

        sensitive = _SENSITIVE_PORTS.get(listener.port)
        if sensitive is not None:
            service, grade = sensitive
            audit.evaluated("NET-002")
            audit.add(Finding(
                check_id="NET-002",
                title=f"{service} is reachable beyond loopback on port {listener.port}",
                severity=Severity.CRITICAL if grade == "critical" else Severity.HIGH,
                assertion=(
                    f"{listener.proto} {listener.address}:{listener.port} is bound to "
                    f"{'every interface' if listener.wildcard else listener.address}, "
                    f"which is {service}."
                ),
                rationale=(
                    f"{service} is not designed to be exposed to an untrusted network. "
                    "Several of these services ship with authentication disabled by "
                    "default and treat network placement as the only access control, so "
                    "a bind address of every interface is a direct path to the data."
                ),
                remediation=(
                    f"Bind {service} to loopback or a private interface and reach it over "
                    "a tunnel. If it must be reachable, confirm authentication is enabled "
                    "and the port is firewalled to known sources."
                ),
                reachability=Reachability.REMOTE_UNAUTH,
                confidence=Confidence.CONFIRMED,
                evidence=(_text("NET-002", listener.source, listener.locator, listener.raw,
                                f"{listener.proto}/{listener.port} bound to {listener.address}"),),
                references=("CIS 4.1",),
                attacked_via=("T1190",),
                tags=("network", "exposure", "database"),
            ))
            continue

        audit.evaluated("NET-001")
        expected = listener.port in _EXPECTED_WILDCARD_PORTS
        audit.add(Finding(
            check_id="NET-001",
            title=f"{listener.proto}/{listener.port} is reachable beyond loopback",
            severity=Severity.LOW if expected else Severity.MEDIUM,
            assertion=(
                f"{listener.proto} {listener.address}:{listener.port} accepts connections "
                f"from off-host."
            ),
            rationale=(
                "This is a reachability observation, not a verdict: a service that is "
                "meant to be reachable (a web server, a mail server) is not a defect. "
                "It is reported so the complete listening set is visible and the "
                "reachable surface can be reviewed as a whole."
                if expected else
                "The port is not one of the conventionally public services, so this bind "
                "is more likely to be unintended than the web or mail server case. Worth "
                "confirming against what the host is supposed to be running."
            ),
            remediation="Confirm the service is intended to accept off-host connections; if not, bind it to loopback or restrict it with a firewall rule.",
            reachability=Reachability.REMOTE_UNAUTH,
            confidence=Confidence.CONFIRMED,
            evidence=(_text("NET-001", listener.source, listener.locator, listener.raw,
                            f"{listener.proto}/{listener.port} on {listener.address}"),),
            false_positive_notes="A firewall in front of this host may already restrict the port; this audit does not read firewall state.",
            tags=("network", "listener"),
        ))


# ── NET-003: declared wildcard binds in service configuration ───────────────

def check_config(audit: Audit) -> None:
    files = audit.config_files()
    if not files:
        audit.skip("NET-003", "no service configuration found under the fixed paths")
        return

    fired = False
    for rel in files:
        text = audit.read(rel, "NET-003")
        if text is None:
            continue
        for lineno, raw in enumerate(text.splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith("#") or line.startswith(";"):
                continue
            for pattern, description in _WILDCARD_DIRECTIVES:
                if not pattern.search(line):
                    continue
                fired = True
                audit.evaluated("NET-003")
                audit.add(Finding(
                    check_id="NET-003",
                    title=f"{Path(rel).name} {description}",
                    severity=Severity.MEDIUM,
                    assertion=f"{rel}:{lineno} declares that the service {description}.",
                    rationale=(
                        "The configuration is the declared intent, and it is worth reading "
                        "even when no running process was observed: a service that is "
                        "currently stopped will bind the same way when it starts, and this "
                        "is frequently the line that turns a local database into a public "
                        "one."
                    ),
                    remediation="Restrict the directive to loopback or a specific private address if off-host reachability is not required.",
                    reachability=Reachability.REQUIRES_CHAIN,
                    confidence=Confidence.LIKELY,
                    evidence=(_text("NET-003", rel, f"line {lineno}", line, description),),
                    preconditions=("The service must be running for this declaration to take effect.",),
                    tags=("network", "configuration"),
                ))
                break

    if not fired:
        audit.ran("NET-003")


def run_all(root: str = "/", include_info: bool = False) -> Audit:
    core()  # bind the contract before any check builds a Finding
    audit = Audit(root)

    # Tier 1 — the kernel's own socket tables.
    tables_read = 0
    for relative, proto in PROC_TABLES:
        try:
            exists = audit.path(relative).is_file()
        except ValueError:
            continue
        if not exists:
            continue
        text = audit.read(relative, "NET-001")
        if text is None:
            continue
        tables_read += 1
        audit.listeners.extend(parse_proc_table(text, proto, relative))

    if tables_read:
        audit.note(
            "Listener data came from the kernel socket tables under /proc, which is the "
            "same source ss and netstat read. This audit does not run those tools and "
            "does not probe any port."
        )
    else:
        audit.note(
            "The kernel socket tables under /proc were not available, so running "
            "listeners could not be enumerated. What follows reflects DECLARED "
            "configuration only, which may differ from what is actually bound."
        )
        audit.skip("NET-001", "no /proc/net socket table was readable (expected on macOS)")
        audit.skip("NET-002", "running listeners could not be enumerated without /proc/net")

    check_listeners(audit, include_info)
    check_config(audit)
    audit.settle()
    audit.limitations.append(
        "Only the checks listed in coverage.checks_run were attempted. This audit does not "
        "read firewall state, does not inspect container network namespaces other than the "
        "one it runs in, does not resolve service names, and does not probe any port to "
        "confirm reachability."
    )
    return audit