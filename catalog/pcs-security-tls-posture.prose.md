# The catalog submission's prose for pcs-security-tls-posture.
#
# `scripts/open_catalog_pr.sh` reads the two sections below and drops them into the PR body
# verbatim. It cannot write them: "what does this do" and "what does it not do" are the
# substance a reviewer judges, and a generator that invents capability claims is worse than
# no generator.
#
# This file used to live beside the entry inside `.catalog-work/hermes-agent/` — the scratch
# clone, which is gitignored and `rm -rf`'d by every `--open-pr` run. So the submitted text
# survived only in the open PR, and the next SHA-bump PR regenerated it as `(missing)`. It
# lives here now, where it is tracked, diffable, and reviewable in this repo.
#
#   ## INTRO        → the PR body's "What does this PR do?" prose, after the entry sentence
#   ## DISCLOSURES  → the bullets under "## Disclosures"
#
# Everything below `## INTRO` is published as written. Keep the two headings exactly as they
# are, and keep no other `## [A-Z]` heading after `## DISCLOSURES` — the reader stops there.

## INTRO

[Pacific-Cloud-Solutions/hermes-plugins](https://github.com/Pacific-Cloud-Solutions/hermes-plugins)
(MIT) audits **local** TLS posture read-only. It parses certificate files and nginx/Apache TLS
directives on disk against a fixed list of well-known paths and returns a structured report in
which every finding cites `file:line` plus the value observed. It declares one tool,
`tls_posture`. It does not connect to anything: no handshake, no socket, no listener
enumeration, no remote target.

The plugin is self-contained. It **bundles** the suite's finding contract in `_contract/` —
byte-identical copies of `pcs-security-core`'s four modules — so `hermes plugins install
pcs-security-tls-posture` installs a tool that runs with no second install. The shared
`pcs-security-core` plugin is used instead when it is present.

## DISCLOSURES

- **Read-only, and it never connects.** No sockets, no TLS handshake, no port or listener
  enumeration, no remote target, no writes, no subprocess. It reads files and reports on them.
  Confirmed by sweeping the tree for network, write and exec calls, not by assertion.
- **Fixed target list — not a general file reader.** It audits a fixed set of relative paths and
  globs under the root (`etc/ssl/certs/*.pem`, the Let's Encrypt live path, the nginx/Apache
  TLS config locations). The check list is not caller-supplied and `Audit.path()` refuses any
  path escaping the root, so an attacker who can name a path cannot turn this into an
  arbitrary-file-read primitive wearing an audit tool's schema.
- **No private key material.** Certificates and configs only. The contract additionally redacts
  private-key, AWS-key, GitHub-token, OpenAI-key, Slack-token and JWT patterns from anything it
  does read, before it can reach a report.
- **Bundled copy of another plugin's code.** `_contract/` contains `pcs-security-core`'s four
  modules copied byte-for-byte, refreshed by a script and guarded by a drift check. This is
  deliberate: a catalog entry installs exactly **one** plugin, so a plugin needing a sibling
  would install onto a host that has none and fail at first use. Nothing is fetched or vendored
  at install time; the copy ships in the pinned tree.
- **Registers host-level pieces only when core is absent.** When `pcs-security-core` is not
  installed, this plugin registers the suite's redaction patterns and a bounded system-prompt
  section (`pcs_security_core.hostile_input`) instructing the agent to treat security-tool
  output as data and never as instruction. That is a prompt-injection guard, not telemetry.
  When core **is** installed, core owns both and this plugin registers neither, so the section
  is registered exactly once.
- **No self-updater and no network.** No `releases/latest`, no `raw.githubusercontent.com`
  fetches, no telemetry, no analytics, no update pings. Updates reach users only as a SHA-bump
  PR plus `hermes plugins update pcs-security-tls-posture`.
- **No Python dependencies**, declared or otherwise — nothing for the dependency policy in
  rule 9 to review.