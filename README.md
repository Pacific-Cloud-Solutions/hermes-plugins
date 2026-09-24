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
hermes plugins pack show  https://raw.githubusercontent.com/Pacific-Cloud-Solutions/hermes-plugins/main/hermes-pack.yaml
hermes plugins pack install https://raw.githubusercontent.com/Pacific-Cloud-Solutions/hermes-plugins/main/hermes-pack.yaml
```

## Plugins

| Plugin | Does | Category | Catalog |
|---|---|---|---|
| `pcs-security-core` | Shared contract — findings, evidence, coverage, the provenance/taint model, and secret redaction. A foundation plugin: no tools of its own. | tools | — |
| `pcs-security-auth-posture` | Read-only audit of local authentication posture — `sshd_config`, `sudoers`, key files, UID 0 accounts. **Blocked at install pending the declared-audit-intent signal upstream** (see below). | tools | — |
| `pcs-security-tls-posture` | Read-only audit of certificate validity, key strength, and deprecated protocols or weak cipher suites in server configuration. | tools | — |
| `pcs-security-log-triage` | Read-only triage of local logs — authentication failures correlated by source address, a success following a burst, crashes, and instruction-like content in log data. | tools | — |
| `pcs-security-network-exposure` | Read-only audit of which services are reachable beyond loopback, prioritised by what the service is. | tools | — |

All five ship in the `pcs-security-guard` pack. The last three install cleanly on a
released Hermes and are the intended first catalog entries; **no plugin has a
catalog entry yet.**

`pcs-security-auth-posture` names the artifacts it audits (`authorized_keys`,
`/etc/passwd`, `NOPASSWD`, `sudoers`), which the install scanner treats as hostile
lexical patterns. It therefore declares read-only audit intent in its manifest, and
**cannot be installed by any route until that signal lands upstream** — the catalog
gate and the install scanner both reject it, and `--force` does not override a
`dangerous` verdict. Do not publish it before the dependency lands.

## Layout

```
hermes-plugins/
├── plugins/<id>/          One plugin per directory — plugin.yaml, __init__.py, desc, health
├── scripts/               catalog entry generator, catalog PR helper, hero asset builder
├── docs/                  hero.png (lossless master), hero.webp (README), hero-2x1.webp (catalog card)
├── hermes-pack.yaml       Pack pins, one `ref:` per plugin — exact SHAs only
├── AGENTS.md              Repo rules for contributors and agents
└── README.md
```

Single edition, no `personal/` + `public/` split. If a plugin ever needs to reach into Hermes app
internals the catalog forbids, it stays in your live install and does not get a catalog entry —
see `AGENTS.md`.

## Contributing a plugin

Read `AGENTS.md` first. The short version:

```bash
hermes plugins doctor "$HERMES_HOME/plugins/<id>"      # runtime contract
hermes plugins validate "$HERMES_HOME/plugins/<id>"    # catalog admission gate (CI)
```

Both must be clean, and the manifest's declared `provides_tools` / `provides_hooks` must match what
`register()` actually registers — undeclared capability creep is treated as a security issue
upstream.

## Getting a plugin into the Hermes catalog

Plugins are **not** merged into the hermes-agent source tree. What lands upstream is a reviewed
`plugin-catalog/<name>.yaml` entry that pins your plugin's commit SHA. This repo carries the whole
workflow:

```bash
python3 scripts/catalog_entry.py --plugin plugins/<id> --sha <40-char-sha> \
    --category tools --maintainer Pacific-Cloud-Solutions \
    --image https://raw.githubusercontent.com/Pacific-Cloud-Solutions/hermes-plugins/<40-char-sha>/docs/hero-2x1.webp \
    > /tmp/<id>.yaml

scripts/open_catalog_pr.sh /tmp/<id>.yaml <name>     # dry run — prints every step
scripts/open_catalog_pr.sh /tmp/<id>.yaml <name> --open-pr   # fork, push, open the PR
```

`--image` must be an https URL on a GitHub host, pinned to the entry's commit — `docs/hero-2x1.webp`
is the 2:1 asset the catalog card expects.

The PR is opened against [`NousResearch/hermes-agent`](https://github.com/NousResearch/hermes-agent)
and needs a human maintainer to merge it. Admission rules (SHA pins, no self-updating code, declared
capabilities matching reality, SDK-only desktop code) are in that repo's `plugin-catalog/README.md`.

## License

MIT © Pacific Cloud Solutions. See `LICENSE`.

This is an independent project. It is not affiliated with, endorsed by, sponsored by, or officially
associated with Nous Research or Hermes Agent. Hermes, Hermes Agent, and Nous Research are names and
marks belonging to their respective owners.