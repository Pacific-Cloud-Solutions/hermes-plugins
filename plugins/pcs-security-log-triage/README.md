# pcs-security-log-triage

Read-only triage of local system logs. One tool: `log_triage`.

Part of the Pacific Cloud Solutions security suite. Requires
[`pcs-security-core`](../pcs-security-core), which supplies the finding contract and the
provenance/taint model.

**This plugin installs clean.** It names no artifact the install scanner treats as
hostile vocabulary, so it needs no declared-audit-intent signal.

## What it checks

| ID | Check |
|---|---|
| `LOG-001` | Repeated authentication failures **correlated by source address** (reported per address; graded by volume) |
| `LOG-002` | A successful authentication **following** a burst of failures from the same address (CRITICAL) |
| `LOG-003` | Service crash, fault or fatal-error lines, grouped by source |
| `LOG-004` | Instruction-like content in log data — **reported as a finding, never obeyed** |
| `LOG-005` | No log was readable at all (coverage gap, not a finding) |
| `LOG-006` | Authentication failures **spread across accounts** — the password spray LOG-001 cannot see (HIGH), or one account attacked from many sources (MEDIUM) |
| `LOG-008` | Account/group state changes and **denied** privilege-escalation attempts |
| `LOG-010` | A log that exists but has stopped receiving entries (INFO — a coverage observation) |

## The spray that per-source correlation cannot see

`LOG-001` groups failures by **source address**. That is the right correlation for a brute
force, and it is structurally blind to the attack that replaced it:

```
Failed password for invalid user admin    from 203.0.113.1    # 1 failure
Failed password for invalid user oracle   from 203.0.113.2    # 1 failure
Failed password for invalid user postgres from 203.0.113.3    # 1 failure
... 7 more accounts, one failure each, from 7 more addresses
```

No address reaches the burst threshold, so `LOG-001` reports nothing — correctly, by its own
rule. `LOG-006` exists because the absence of a burst is not the absence of an attack: this
is a password spray, and it is *shaped* this way specifically to stay under per-source
thresholds. It is graded **HIGH** and reports how many distinct accounts were targeted and
from how many addresses.

The same blind spot runs the other way. One account tried from many addresses, each source
contributing too few attempts to trip anything, is invisible for the identical reason —
`LOG-006` reports that shape at **MEDIUM**.

Both are one instance of a rule the whole suite follows: **correlate on the axis the adversary
is not controlling.** Grouping by source is a choice, and an attacker who knows the choice
simply spreads across the other dimension.

## Install

```bash
hermes plugins install pcs-security-core
hermes plugins install pcs-security-log-triage
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
log_triage                            # triage the running host
log_triage root=/mnt/suspect           # triage a mounted filesystem
log_triage max_lines=50000             # widen the per-file read window
log_triage failure_threshold=3         # tighten the burst threshold
log_triage include_info=true           # add INFO-severity observations
```

## The point of this plugin

Log content is the most hostile input an agent can be handed. A username, an HTTP
User-Agent, a request path, a referrer — all of them land in a log verbatim, and
any of them can contain **text written to read like an instruction to whatever
reads the log.** When that "whatever" is a language model summarising logs, the
log is an injection channel.

This plugin treats every line as **DATA, at the boundary**:

- every value read off disk is quarantined as `UNTRUSTED` before it can reach any
  field;
- `pcs-security-core`'s detector set runs over each line, and a match is **reported
  as a finding** — with the detector name in the evidence, so a human can judge;
- matched text is **never stripped, never sanitised, never executed**, and can
  never be promoted into the trusted prose of a finding (the type system refuses
  it — `Finding.assertion` will not accept a quarantined value);
- the report states explicitly that the content was treated as data and not obeyed.

Removing the text would be the wrong move. The attempt *is* the signal, and
silently stripping it would erase the evidence that something wrote
agent-directed content into a place an agent reads.

## Three design constraints

**1. Read-only.** Nothing is written, executed, or connected to. Logs are parsed
as text.

**2. No target selection.** The tool reads a **fixed list** of relative log paths
under the root. `Audit.path()` refuses anything that escapes the root, and the
list is not caller-supplied. This is the difference between a triage tool and an
arbitrary-file-read primitive wearing a triage tool's schema.

**3. No silent passes.** A log that is missing, unreadable or empty is recorded in
`coverage.checks_skipped` with its reason. **Unreadable is not the same as clean.**
`Report.verdict()` has no code path that returns "secure".

## Four things that are easy to get wrong

**A count is not a finding.** "412 authentication failures" is a number nobody can
act on. The useful part is that 398 came from one address — so events are
**correlated by source address** and the finding names the source. That
correlation, not the count, is the product.

**The ordering is the finding.** Failures alone mean someone is knocking.
Failures **followed by** a success from the same address may mean someone got in —
and that is `LOG-002`, graded CRITICAL. A success that happens *before* the burst
is an ordinary working session; it is explicitly not reported, and the reason is
recorded in the report rather than silently dropped.

**Only authentication logs count as authentication.** A web access log contains the
word "Failed" for entirely unrelated reasons. Counting an HTTP 500 as a failed
login would be a **fabricated finding**, so auth events are only read from
authentication log paths. Addresses appearing in access logs are never reported
as attackers.

**Reading the tail is a deliberate trade with a visible boundary.** Logs are
append-only, so current activity is at the end. A bounded read keeps a 4 GB log
from becoming a 4 GB parse — and when the bound bites, it is recorded as a
coverage limitation. "No findings" from the last 20,000 lines is *not* "no
findings".

## Why nothing is `Provenance.LOCAL`

Every value read off disk is quarantined as `UNTRUSTED` — including apparently
innocuous fields like a hostname or a program name. Those are written by remote
input on any service that logs client-supplied data. The whole point of the taint
model is that it is marked on the way through and reported, never promoted.

## Scope

This triage does not parse binary logs, does not follow rotated or compressed
archives, does not read the systemd journal, and makes no attempt to reconstruct a
complete event timeline. Those gaps are stated in `coverage.limitations` on every
report.