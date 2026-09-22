# AGENTS.md — repo rules

Rules for `Pacific-Cloud-Solutions/hermes-plugins`. They apply to human contributors and to any
agent working in this repo.

## What this repo is

Installable Hermes Agent plugins, one job each, pinned to exact commit SHAs. **Single edition** —
`plugins/<id>/` is the plugin, and that is the only copy that ships. No `personal/` + `public/`
split: if a plugin needs to reach into Hermes app internals (prototype patching, `eval`, internal
app stores), it stays in your live install and does not get a catalog entry. Publishing is a
constraint, never a reason to fork a plugin into two trees.

```
plugins/<id>/
├── plugin.yaml         manifest — name, version, description, author, provides_*, requires_env
├── __init__.py         register(ctx) — the whole registration surface
├── schemas.py          tool schemas (what the model sees)
├── tools.py            handlers: (args, **kwargs) -> JSON string, never raise
├── README.md           what it does, how to install, how to configure
└── desktop/plugin.js   only if it ships a Desktop UI surface
```

## Authoring contract

- Handlers are `def handler(args: dict, **kwargs) -> str` and **always return a JSON string** —
  never raise. `**kwargs` is mandatory so additive payload fields cannot break the plugin.
- Declare exactly what `register()` registers, in `provides_tools` / `provides_hooks`.
  Undeclared capability creep is treated as a security issue upstream, and
  `hermes plugins validate` fails on it.
- No self-updating code. A listed plugin must not fetch and replace its own files — the SHA pin
  *is* the trust model; a self-updater moves an installed copy to unreviewed code.
- No telemetry, no analytics, no network calls the plugin does not visibly need.
- Secrets come from the environment via `requires_env` and live in `.env`. Non-secret settings
  belong in `config.yaml` via `ctx.get_config` — never in `.env`.
- Resolve paths from `$HERMES_HOME` / `get_hermes_home()`. Never hardcode `~/.hermes`; a profile
  is home + secret scope + terminal scope.
- Desktop code uses the plugin SDK only: no prototype patching, no `eval`/`new Function`, no
  `import()` outside `@hermes/plugin-sdk` and `react`.

## The gates

Both must be clean before a plugin is pushed:

```bash
hermes plugins doctor   "$HERMES_HOME/plugins/<id>"     # real runtime contracts
hermes plugins validate "$HERMES_HOME/plugins/<id>"     # catalog admission (CI gate)
hermes plugins validate "$HERMES_HOME/plugins/<id>" --json   # machine-readable
```

`validate` runs the capability probe: it imports `register()` in isolation and compares what is
registered against the manifest. That is the check that catches declared-vs-registered drift,
which otherwise fails silently in production.

**Known gap:** the manifest has no field for middleware, so a plugin that registers middleware
cannot declare it and `validate` reports every middleware registration as undeclared. See
"Middleware" below before building one.

## Publishing a plugin to the Hermes catalog

Plugins are **not** merged into hermes-agent. What lands upstream is one reviewed file:
`plugin-catalog/<name>.yaml` pinning this repo's commit SHA. Presence in that directory IS the
install path — `hermes plugins install <name>` clones this repo at the pinned commit.

```bash
# 1. push the plugin here first — the pin must resolve to a pushed commit
git add plugins/<id> && git commit -m "feat(<id>): ..." && git push

# 2. generate the entry from the plugin's own manifest, and prove the loader accepts it
SHA=$(git rev-parse HEAD)
python3 scripts/catalog_entry.py --plugin plugins/<id> --sha "$SHA" \
    --category tools --maintainer Pacific-Cloud-Solutions --verify > /tmp/<id>.yaml

# 3. preview the PR (no network writes), then open it
scripts/open_catalog_pr.sh /tmp/<id>.yaml <id>
scripts/open_catalog_pr.sh /tmp/<id>.yaml <id> --open-pr      # needs sign-off
```

Rules that the PR is reviewed against, from upstream `plugin-catalog/README.md`:

1. Human-merged only — no self-serve registry.
2. **Exact 40-character SHA pins.** Branches, tags, and short SHAs are rejected by the loader.
3. **No self-updating code** in a listed plugin.
4. **SHA bumps are new PRs** whose diff is re-reviewed.
5. Owner-or-major-contributor submissions only; drive-by submissions of third-party repos are
   declined. Ours qualify because we own the plugin repo.
6. Declared capabilities must match reality at the pinned commit.
7. The install scanner runs at admission — `dangerous` fails the entry, `caution` is a warning the
   reviewer reads.
8. Desktop plugins stay inside the plugin SDK.

After a merge, re-pin `hermes-pack.yaml` to the same SHA in this repo, so pack installs and catalog
installs resolve to identical code.

**Never push to `NousResearch/hermes-agent` and never open an upstream PR without explicit
sign-off.** Develop, validate, and stage locally; the `--open-pr` step is a human decision.

## Scripts must run on macOS bash 3.2

Apple ships **GNU bash 3.2.57** as `/bin/bash`, and it mis-parses a heredoc nested inside a
command substitution: a quote character in the body (e.g. an apostrophe in "the plugin
repository's owner") aborts the whole script with `unexpected EOF while looking for matching '`.
Balanced quotes happen to survive, which makes this a silent trap.

- Do not write `VAR=$(cat <<'EOF' … EOF)`. Use `read -r -d '' VAR <<'EOF' || true`, which keeps the
  heredoc outside any command substitution, or redirect the heredoc to a temp file.
- Keep the body a **quoted** heredoc and substitute explicitly (`sed -e "s|__NAME__|$NAME|g"`) —
  markdown backticks in an unquoted body are command substitution.
- Verify every script with `bash -n <script>` before committing, and run it once for real.

## Versioning

`plugin.yaml`'s `version` is the human label; the SHA is the release. Bump the version and the SHA
pin together, in the same commit, so the catalog card's label matches the code it installs.

## Middleware

`provides_middleware` exists in the *catalog entry* schema but not in the plugin manifest
(`_KNOWN_MANIFEST_FIELDS`), so `hermes plugins validate` cannot see it declared and flags any
middleware registration as undeclared — an upstream contract gap, not a plugin bug. Until that is
resolved upstream, pass middleware names to the generator explicitly:

```bash
python3 scripts/catalog_entry.py --plugin plugins/<id> --sha "$SHA" --middleware "llm_call,pre_tool_call" --verify
```

and expect the local `validate` run to warn on the declared-middleware row. Do not paper over it by
dropping the middleware.