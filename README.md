<p align="center">
  <img src="docs/hero.webp" alt="Hermes Plugins by Pacific Cloud Solutions" width="100%">
</p>

# Hermes Plugins

Installable [Hermes Agent](https://github.com/NousResearch/hermes-agent) plugins, one job each,
pinned to exact commit SHAs so an install is reproducible and reviewable.

## What this is

A small set of security tools that run inside Hermes, on machines you actually own.

They read what's already on the box — your TLS config, your logs, your HTTP headers — and
tell you what's wrong in plain language, with the file and line number so you can go look
for yourself. Pick the ones you want. Nothing here changes your system.

They're built around one idea: a security tool that cries wolf is worse than no security tool
at all. So these are careful about what they claim, and loud about what they didn't check.

## What it does

**Answers, not dashboards.** Every finding says what it is, why it matters *on this machine*,
and what to do about it. No wall of red, no severity soup, no "42 issues found" with nothing
you can act on.

**It tells you what it couldn't check.** This is the part most tools get wrong. An expired
certificate is easy. Knowing that the log you just audited has been silent for three weeks —
so "no findings" really means "no data" — is the useful part. Coverage ships with every
report, and nothing here will ever tell you a system is *secure*. At best it will tell you it
found nothing in the checks it ran, and list the ones it couldn't.

**It reads the config, not just the file.** Certificates get looked at in the context of who
actually serves them, so it can say "the certificate nginx serves on this host expired"
rather than just "this file expired." And it catches a genuinely common mistake: nginx
pointed at `cert.pem` when `fullchain.pem` is sitting right beside it. That one looks like it
works, fails silently for some visitors and not others, and no expiry check on earth will
notice it.

**Safe to run on production.** Read-only and local. No agents, no daemons, no background
service to babysit. The kind of thing you're comfortable running on a Friday afternoon.

**No new console to learn.** You ask Hermes. It's already where you work.

## What it doesn't do

Worth being straight about, because the difference matters:

- **It doesn't scan the network.** It never connects to anything, never performs a TLS
  handshake, never checks a port from the outside. It reads files and tells you what they
  imply. That's a deliberate line — a tool that talks to your servers has a very different
  risk profile from one that reads them.
- **It doesn't fix anything.** You propose, you decide. No auto-remediation, no surprise
  config edits. A security tool that changes your system while you sleep is its own incident
  report.
- **It doesn't read your private keys — and it scrubs secrets it does see.** Certificates and
  configs, yes; private keys, no. And if a credential happens to appear in a log or config it
  reads, it's redacted before it can reach the report.
- **It isn't your EDR, your SIEM, or a vulnerability scanner.** These are posture checks, not
  breach detection. They'll tell you a door is unlocked; they won't tell you someone came
  through it last Tuesday.
- **It doesn't phone home.** No telemetry, no analytics, no update pings. Nothing leaves the
  machine.
- **It won't tell you you're secure.** Nothing should, and this won't pretend to.

## Why that's the point

Most security tooling is built to look thorough. This is built to be *believed*. Every claim
comes with the evidence that produced it, every report names what it didn't look at, and
nothing claims more than it did. When it tells you something, you can go check it yourself in
about ten seconds.

That's the whole product.

## Install

Every plugin here installs straight from this repo. Plugins are **opt-in** in Hermes — a plugin
does nothing until it is enabled.

```bash
# One plugin, pinned to an immutable commit
hermes plugins install Pacific-Cloud-Solutions/hermes-plugins#plugins/<id> --ref <40-char-sha>

# List what's here before installing
hermes plugins browse
```

The whole set is also installable as a **pack** — a single YAML pinning every plugin to a SHA.
If you want the whole toolkit rather than picking through it, this is the one-liner:

```bash
hermes plugins pack show  https://raw.githubusercontent.com/Pacific-Cloud-Solutions/hermes-plugins/main/pcs-security-guard.yaml
hermes plugins pack install https://raw.githubusercontent.com/Pacific-Cloud-Solutions/hermes-plugins/main/pcs-security-guard.yaml
```

Installing a pack is just the individual installs done for you, from one reviewed list. You can
still enable or disable any plugin afterwards.

## Plugins

| Plugin | Does | Category | Catalog |
|---|---|---|---|
| `pcs-security-core` | Shared contract — findings, evidence, coverage, the provenance/taint model, and secret redaction. A foundation plugin: no tools of its own. | tools | — |
| `pcs-security-auth-posture` | Read-only audit of local authentication posture — `sshd_config`, `sudoers`, key files, UID 0 accounts. **Blocked at install pending the declared-audit-intent signal upstream** (see below). | tools | — |
| `pcs-security-tls-posture` | Read-only audit of certificate validity, key strength, and deprecated protocols or weak cipher suites — and of the certificate each server *actually serves*, including the `cert.pem` vs `fullchain.pem` mistake. | tools | — |
| `pcs-security-log-triage` | Read-only triage of local logs — failures correlated by source, password sprays spread across accounts, logins after a burst, account changes, denied privilege attempts, crashes, logs that have gone silent, and instruction-like content in log data. | tools | — |
| `pcs-security-network-exposure` | Read-only audit of which services are reachable beyond loopback, prioritised by what the service is. | tools | — |
| `pcs-security-web-headers` | Read-only audit of declared HTTP security headers — HSTS, CSP, framing and sniffing protection, version disclosure, and nginx `add_header` inheritance. | tools | — |

All six plugins live in this repository; the `pcs-security-guard` pack installs
five. `pcs-security-auth-posture` is held back until the declared-audit-intent
signal lands upstream — **do not publish it before that dependency lands.**

## Layout

```
hermes-plugins/
├── plugins/<id>/          One plugin per directory — plugin.yaml, __init__.py, desc, health
├── catalog/               Submission prose — `## INTRO` / `## DISCLOSURES` the catalog PR is built from
├── scripts/               catalog entry generator, catalog PR helper, hero asset builder
├── docs/                  hero.png (lossless master), hero.webp (README), hero-2x1.webp (catalog card)
├── pcs-security-guard.yaml  Pack pins, one `ref:` per plugin — exact SHAs only
├── AGENTS.md              Repo rules for contributors and agents
└── README.md
```

## Contributing a plugin

Read **[`AGENTS.md`](AGENTS.md)**. It is the single source of truth for the authoring contract, the
two gates (`hermes plugins doctor` / `hermes plugins validate`), the catalog-submission runbook and
the rules that PR is reviewed against.

It lives there on purpose rather than here: this section previously restated the runbook, and the
copy drifted — it documented an invocation that fails, and it omitted the push-first requirement and
all eight review rules. One copy cannot disagree with itself.

## License

MIT © Pacific Cloud Solutions. See `LICENSE`.

This is an independent project. It is not affiliated with, endorsed by, sponsored by, or officially
associated with Nous Research or Hermes Agent. Hermes, Hermes Agent, and Nous Research are names and
marks belonging to their respective owners.
