# security-auth-posture

Read-only audit of local authentication posture. One tool: `auth_posture`.

Part of the Pacific Cloud Solutions security suite. Requires
[`security-core`](../security-core), which supplies the finding contract and the
provenance/taint model.

## What it checks

| ID | Check |
|---|---|
| `SSH-001` | `PermitRootLogin yes` (escalates to CRITICAL when password auth is also on) |
| `SSH-002` | `PasswordAuthentication yes` |
| `SSH-003` | `PermitEmptyPasswords yes` |
| `SSH-004` | `PermitUserEnvironment yes` |
| `SSH-005` | `X11Forwarding yes` |
| `SSH-006` | Deprecated ciphers / MACs / KEX / host-key algorithms named explicitly |
| `SSH-007` | `MaxAuthTries` raised above the default (INFO, opt-in) |
| `PERM-001` | `sshd_config`, `sudoers`, `/etc/passwd` or an `authorized_keys` writable by group/other |
| `KEY-001` | `authorized_keys` entry that is `ssh-dss`, or RSA below 2048 bits |
| `SUDO-001` | `NOPASSWD` entry (HIGH when it covers `ALL`) |
| `SUDO-002` | Wildcard in a sudoers command path |
| `ACCT-001` | Account other than `root` with UID 0 |
| `ACCT-002` | Account with an empty password field in `/etc/passwd` |

## Install

```bash
hermes plugins install security-core
hermes plugins install security-auth-posture
```

If `security-core` is missing the tool still **registers** — but **refuses to
run**, returning an explicit error instead of a report. No report is ever
produced outside the taint model.

Registration is deliberately tolerant for a specific reason: `hermes plugins
doctor` and `hermes plugins validate` copy a plugin into a temp directory and run
it **in isolation**, with no sibling `security-core/` on disk. A hard import at
module scope makes both gates fail. The property that matters is "no *report*
without the contract", which the handler enforces — not "the module cannot be
imported".

## Usage

```
auth_posture                       # audit the running host
auth_posture root=/mnt/suspect     # audit a mounted filesystem
auth_posture include_info=true     # add INFO-severity observations
```

## Three design constraints

**1. Read-only.** Nothing is written, executed, or connected to. There is no
remediation path — `remediation` strings are advisory text for a human.

**2. No target selection.** The tool audits a **fixed list** of relative paths
under the root. `Audit.path()` refuses anything that escapes the root, and the
check list is not caller-supplied. This is the difference between an audit tool
and an arbitrary-file-read primitive wearing an audit tool's schema: a tool that
accepts a path can be talked into printing `/etc/shadow`, a private key, or a
credential store.

**3. No silent passes.** A file that is missing, permission-denied, or malformed
is recorded in `coverage.checks_skipped` with its reason. **Unreadable is not the
same as safe**, and the report never implies otherwise. `Report.verdict()` has no
code path that returns "secure".

## Two things that are easy to get wrong

**`sshd_config` is first-match-wins.** OpenSSH uses the *first* obtained value for
each keyword, and `Include` is processed in place. A parser that keeps the last
occurrence reports the wrong effective setting — and because most distributions
put `Include /etc/ssh/sshd_config.d/*.conf` at the *top* of the file, it inverts
the answer for drop-in-managed hosts. `effective_sshd()` implements first-wins
with in-place include expansion.

**`without-password` is not `yes`.** It is a legacy alias for
`prohibit-password` (key-only). `SSH-001` fires only on the literal `yes`, so a
correctly hardened host is not reported.

## Why nothing is `Provenance.LOCAL`

Every value read off disk is quarantined as `UNTRUSTED`, including config lines
that look inert. Two reasons: an `authorized_keys` comment and a sudoers comment
are written by whoever added the entry, and on a host that is already compromised
the config files themselves are attacker-controlled. The taint model assumes
nothing about a file's trustworthiness from its path.

## Verify

```bash
hermes plugins doctor   plugins/security-auth-posture
hermes plugins validate plugins/security-auth-posture
```

## Licensing

MIT.