<p align="center">
  <img src="docs/hero.webp" alt="Hermes Plugins by Pacific Cloud Solutions" width="100%">
</p>

# Hermes Plugins

Installable [Hermes Agent](https://github.com/NousResearch/hermes-agent) plugins, one job each,
pinned to exact commit SHAs so an install is reproducible and reviewable.

## Install

Every plugin here installs straight from this repo. Plugins are **opt-in** in Hermes — a plugin
does nothing until it is enabled.

```bash
# One plugin, pinned to an immutable commit
hermes plugins install Pacific-Cloud-Solutions/hermes-plugins#plugins/<id> --ref <40-char-sha>

# List what's here before installing
hermes plugins browse
```

The whole set is also installable as a **pack** — a single YAML pinning every plugin to a SHA:

```bash
hermes plugins pack show  https://raw.githubusercontent.com/Pacific-Cloud-Solutions/hermes-plugins/main/pcs-security-guard.yaml
hermes plugins pack install https://raw.githubusercontent.com/Pacific-Cloud-Solutions/hermes-plugins/main/pcs-security-guard.yaml
```

## Plugins

| Plugin | Does | Category | Catalog |
|---|---|---|---|
| `pcs-security-core` | Shared contract — findings, evidence, coverage, the provenance/taint model, and secret redaction. A foundation plugin: no tools of its own. | tools | — |
| `pcs-security-auth-posture` | Read-only audit of local authentication posture — `sshd_config`, `sudoers`, key files, UID 0 accounts. **Blocked at install pending the declared-audit-intent signal upstream** (see below). | tools | — |
| `pcs-security-tls-posture` | Read-only audit of certificate validity, key strength, and deprecated protocols or weak cipher suites in server configuration. | tools | — |
| `pcs-security-log-triage` | Read-only triage of local logs — authentication failures correlated by source address, a success following a burst, crashes, and instruction-like content in log data. | tools | — |
| `pcs-security-network-exposure` | Read-only audit of which services are reachable beyond loopback, prioritised by what the service is. | tools | — |
| `pcs-security-web-headers` | Read-only audit of declared HTTP security headers — HSTS, CSP, framing and sniffing protection, version disclosure, and nginx `add_header` inheritance. | tools | — |

All six plugins live in this repository; the `pcs-security-guard` pack installs
five. `pcs-security-auth-posture` is held back until the declared-audit-intent
signal lands upstream — **do not publish it before that dependency lands.**

## Layout

```
hermes-plugins/
├── plugins/<id>/          One plugin per directory — plugin.yaml, __init__.py, desc, health
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
