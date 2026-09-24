# pcs-security-tls-posture

Read-only audit of local TLS posture. One tool: `tls_posture`.

Part of the Pacific Cloud Solutions security suite. Requires
[`pcs-security-core`](../pcs-security-core), which supplies the finding contract and the
provenance/taint model.

**This plugin installs clean.** Unlike [`pcs-security-auth-posture`](../pcs-security-auth-posture),
it names no artifact the install scanner treats as hostile vocabulary, so it needs
no declared-audit-intent signal and no special handling at admission.

## What it checks

| ID | Check |
|---|---|
| `TLS-001` | Certificate has expired |
| `TLS-002` | Certificate expires within 30 days (HIGH at 7 days or fewer) |
| `TLS-003` | Certificate is not yet valid |
| `TLS-004` | RSA/DSA key below 2048 bits, or EC below 224 (CRITICAL below 1024) |
| `TLS-005` | Certificate signed with MD5 or SHA-1 |
| `TLS-006` | Certificate is self-signed |
| `TLS-010` | A deprecated protocol is **enabled** (`SSLv3`, `TLS 1.0`, `TLS 1.1`) |
| `TLS-011` | A weak cipher suite is **offered** (`RC4`, `3DES`, `NULL`, `EXPORT`, …) |
| `TLS-012` | A TLS server config exists with no explicit protocol directive (INFO, opt-in) |

## Install

```bash
hermes plugins install pcs-security-core
hermes plugins install pcs-security-tls-posture
```

If `pcs-security-core` is missing the tool still **registers** — but **refuses to
run**, returning an explicit error instead of a report. No report is ever
produced outside the taint model.

Registration is deliberately tolerant for a specific reason: `hermes plugins
doctor` and `hermes plugins validate` copy a plugin into a temp directory and run
it **in isolation**, with no sibling `pcs-security-core/` on disk. A hard import at
module scope makes both gates fail. The property that matters is "no *report*
without the contract", which the handler enforces — not "the module cannot be
imported".

## Usage

```
tls_posture                          # audit the running host
tls_posture root=/mnt/suspect         # audit a mounted filesystem
tls_posture expiry_days=90            # widen the renewal window
tls_posture include_info=true         # add INFO-severity observations
```

## Three design constraints

**1. Read-only — and specifically, it does not speak TLS.** Nothing is written or
executed, and **no connection is made to anything**. This parses certificate files
and server configuration on disk; it does not perform a handshake. That is a
deliberate scope line: a tool that negotiated TLS with a host would be a network
scanner with an entirely different liability profile, and would inherit every
problem one has.

**2. No target selection.** The tool audits a **fixed list** of relative paths and
globs under the root (`etc/ssl/certs/*.pem`, `etc/pki/tls/certs/*`, the Let's
Encrypt live path, and the nginx/Apache config locations). `Audit.path()` refuses
anything that escapes the root, and the check list is not caller-supplied. This is
the difference between an audit tool and an arbitrary-file-read primitive wearing
an audit tool's schema.

**3. No silent passes.** A certificate that is missing, permission-denied, or
undecodable is recorded in `coverage.checks_skipped` with its reason. **Unreadable
is not the same as valid**, and the report never implies otherwise.
`Report.verdict()` has no code path that returns "secure".

## Three things that are easy to get wrong

**A cipher string is a list of OFFERS and EXCLUSIONS.** `HIGH:!aNULL:!MD5` is a
*hardened* configuration that names MD5 **in order to disable it**. A scanner that
greps the line for `MD5` and files a finding has reported the fix as the bug.
Offered suites are reported; `!` exclusions, `-` removals and `+`/`@` modifiers are
skipped.

**The two servers use opposite polarity for protocols.** nginx writes the versions
it *enables*:

```
ssl_protocols TLSv1.2 TLSv1.3;
```

Apache writes the ones it *removes*:

```
SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
```

A leading `-` means the version is **disabled**. Reading it as enabled reports a
hardened host as broken — the same use-vs-mention trap as the ciphers, in the other
directive. Both cases are covered by the test harness, and the Apache one was a
real bug this harness caught.

**`TLSv1` is a substring of `TLSv1.2`.** Protocol tokens are compared **whole**,
never substring-matched, so a host requiring TLS 1.2 is not reported as permitting
TLS 1.0.

## Two reporting choices worth knowing

**Expiry is graded by how much time is left, not by whether it is a problem.** A
certificate with three days remaining is a scheduled outage an operator can still
prevent; one that expired two years ago belongs to a service nobody is running.
Both are reported — the near-expiry case is graded higher, because it is still
actionable.

**Self-signed is `LOW`, not a failure.** No public client trusts a self-signed
certificate, so it can only be serving internal traffic. That is legitimate in
pinned-client and internal deployments and an unmanaged hand-rolled certificate in
others. The distinction needs a human, which is why it is reported rather than
graded as a defect.

## Why nothing is `Provenance.LOCAL`

Every value read off disk is quarantined as `UNTRUSTED`, including certificate
subject and issuer strings and configuration lines. A certificate's subject field
is attacker-influenced text: anyone who can get a certificate issued can put
arbitrary content in the CN, and it lands in this tool's output. The whole point of
the taint model is that it is marked as data on the way through, and reported —
never promoted into an instruction.

## The crypto backend degrades honestly

Full certificate detail needs an X.509 parser. `cryptography` is used when it is
importable. When it is not, the standard library supplies validity dates and
subject/issuer names but **not** key size or signature algorithm — so `TLS-004`
and `TLS-005` are recorded as **skipped**, with that reason, rather than passed. A
check that could not run is never reported as clean.