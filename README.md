# Hermes Plugins — Pacific Cloud Solutions

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
| _none yet_ | This repo is the home for plugins we intend to publish. | — | — |

The calculator in `hermes_dev` is a local test fixture and deliberately does not live here.

## Layout

```
hermes-plugins/
├── plugins/<id>/          One plugin per directory — plugin.yaml, __init__.py, desc, health
├── scripts/               catalog_entry.py (generates the upstream catalog entry), PR helper
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
    --category tools --maintainer Pacific-Cloud-Solutions > /tmp/<id>.yaml

scripts/open_catalog_pr.sh /tmp/<id>.yaml <name>     # dry run — prints every step
scripts/open_catalog_pr.sh /tmp/<id>.yaml <name> --open-pr   # fork, push, open the PR
```

The PR is opened against [`NousResearch/hermes-agent`](https://github.com/NousResearch/hermes-agent)
and needs a human maintainer to merge it. Admission rules (SHA pins, no self-updating code, declared
capabilities matching reality, SDK-only desktop code) are in that repo's `plugin-catalog/README.md`.

## License

MIT © Pacific Cloud Solutions. See `LICENSE`.

This is an independent project. It is not affiliated with, endorsed by, sponsored by, or officially
associated with Nous Research or Hermes Agent. Hermes, Hermes Agent, and Nous Research are names and
marks belonging to their respective owners.