# pcs-security-network-exposure

Read-only audit of local network exposure. One tool: `network_exposure`.

Part of the Pacific Cloud Solutions security suite. **Self-contained**: it bundles the
suite's finding contract and provenance/taint model in `_contract/`, so this one plugin
installs and runs on its own. The shared [`pcs-security-core`](../pcs-security-core)
plugin is used automatically when it is present, and is not required.

**This plugin installs clean.** It names no artifact the install scanner treats as
hostile vocabulary, so it needs no declared-audit-intent signal.

## What it checks

| ID | Check |
|---|---|
| `NET-001` | A service reachable beyond loopback (LOW for conventionally public ports, MEDIUM for the rest) |
| `NET-002` | A **sensitive** service reachable beyond loopback — databases, caches, the container socket (HIGH, CRITICAL where the service commonly ships unauthenticated) |
| `NET-003` | A configuration file **declares** a wildcard bind (`listen_addresses = '*'`, `bind 0.0.0.0`, …) |
| `NET-004` | A loopback-only listener (INFO, only when `include_info` is true) |
| `NET-005` | No listener data available from either tier (coverage gap, not a finding) |

## Install

```bash
hermes plugins install pcs-security-network-exposure
```

That is the whole install. The contract the tool returns findings in travels inside the
plugin, so there is no dependency to install first and nothing to install in order.

If you install [`pcs-security-core`](../pcs-security-core) alongside it — which the
[pack](../../pcs-security-guard.yaml) does — the shared copy is used instead of the
bundled one, so the whole suite shares a single contract instance and one set of
host-level registrations. Either way the report is identical: `scripts/vendor_contract.py`
copies core's modules byte-for-byte into `_contract/`, and `--check` fails the build if
the two ever diverge. Bundled `__init__.py` included, because it carries the
prompt-section text and the redaction patterns — a hand-edit there would change
host-level behaviour without touching core.

## Usage

```
network_exposure                  # audit the running host
network_exposure root=/mnt/suspect # audit a mounted filesystem
network_exposure include_info=true # also list loopback-only listeners
```

## Two design constraints worth stating plainly

**1. It does not touch the network.** No socket is opened, no connection is made,
no subprocess is run — **not `ss`, not `netstat`, not `lsof`, not `nmap`.** It
reads the kernel's own socket tables from `/proc`, which is the same source `ss`
reads, plus the services' own configuration files. A tool that probed a network
would be a scanner, with every legal and operational consequence a scanner
carries, and with a liability profile this plugin deliberately does not have.
"Reachable beyond loopback" here means *bound to an interface other than
loopback* — not *confirmed reachable*, because confirming it would require the
connection this tool refuses to make.

**2. No silent passes.** If `/proc` is unavailable and no configuration is
readable, **nothing is known**, and that is recorded as a coverage gap. No data is
not the same as no exposure.

## Four things that are easy to get wrong

**The hex in `/proc/net/tcp` is little-endian per 32-bit word.** `0100007F` is
127.0.0.1; `0101A8C0` is 192.168.1.1. Reading the hex left-to-right as a
big-endian integer gives `1.0.0.127` and `1.1.168.192` — plausible addresses that
are simply **wrong**. That is worse than failing, because the report reads as
authoritative. IPv6 is four 32-bit words each byte-reversed *independently*, not
one long little-endian value; reversing the whole 128 bits turns `::1` into
something that is not `::1`. The harness pins the decoder against known input
rather than round-tripping it through the same code.

**UDP has no `LISTEN` state.** A bound UDP socket sits in state `07`. Requiring
`0A`, as for TCP, would report every UDP service as absent — silently.

**A wildcard bind is not automatically a finding.** Every SSH daemon on earth
binds every interface, because it is meant to be reachable. The finding is the
*service*: a database or a container socket on every interface is a different
class of problem from a web server in the same position. **That distinction is the
entire product** — a flat list of listeners is a scanner dump, not a triage. So
findings are graded by what the service is, `NET-002` lists commonly-unauthenticated
services (Redis, MongoDB, Elasticsearch, memcached, CouchDB, etcd, the Docker API)
as CRITICAL, and the `rationale` explains why *that* service matters.

**A `*` in the middle of a glob is not the same as a `*` at the end.**
`etc/postgresql/*/main/postgresql.conf` has a literal `*` in its parent path, so
globbing the parent directory silently returns nothing — and the check then
reports "no configuration found" for a host that has one. Fixed patterns are
expanded with `root.glob(pattern)`. *This bug was found by building this plugin and
was present in `pcs-security-tls-posture` too, on its Let's Encrypt pattern; both
are fixed and covered by a test.*

## What this audit genuinely cannot see

Stated on every report in `coverage.limitations`, and worth repeating here:

- it does **not** read firewall state, so a port listed here may already be
  blocked in front of the host;
- it does **not** probe anything, so "reachable" means "bound to a non-loopback
  interface", not "confirmed answering";
- it does **not** see other network namespaces, so container and VM networks other
  than the one it runs in are invisible;
- it does **not** resolve service names or banner-grab.

On **macOS** there is no `/proc`, so tier 1 is unavailable and the report falls
back to declared configuration only — which may differ from what is actually
bound. That limitation is stated in the report rather than hidden.

## Why nothing is `Provenance.LOCAL`

Every value read off disk is quarantined as `UNTRUSTED`, including socket-table
lines and configuration directives. Configuration is operator-authored, which is
why it is tempting to trust — but it is *file content*, and a service that reads
its bind address from an environment variable, an included file, or a generated
ConfigMap is not operator-authored in any meaningful sense at this boundary. The
model is uniform by design.