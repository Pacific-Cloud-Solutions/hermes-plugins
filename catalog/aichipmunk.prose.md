# The catalog submission's prose for aichipmunk.
#
# `scripts/open_catalog_pr.sh` reads `## INTRO` and `## DISCLOSURES` and drops them into the PR
# body verbatim; `scripts/catalog_entry.py` reads `## DESCRIPTION` and uses it as the entry's
# `description:` field, overriding plugin.yaml's one-liner. It cannot write any of them: what
# the plugin does, and what it does not, is the substance a reviewer judges.
#
# `## DESCRIPTION` must come LAST — the disclosures reader stops at the next `## [A-Z]` heading.
#
# This plugin is NOT read-only, which makes this file the important one. It sets a config key,
# restarts a gateway, reads a profile's API key and shells out to `tailscale`. All of that is
# stated below in plain language, before a reviewer has to go looking for it.

## INTRO

[Pacific-Cloud-Solutions/hermes-plugins](https://github.com/Pacific-Cloud-Solutions/hermes-plugins)
(MIT) pairs this machine's Hermes bots with the **AI Chipmunk** mobile app, from inside Hermes
Desktop: pick a bot, get the host the phone can reach, the profile name, and that profile's
`API_SERVER_KEY` as a scannable code. It replaces the terminal-only `hermes bots pair` flow, which
could not ship to customers.

A bot *is* a Hermes profile. The plugin contributes three surfaces and **no tools or hooks**: a
`hermes aichipmunk` CLI command for headless users (`--json` for machine-readable output), a
desktop page with a sidebar row, ⌘K command and status chip, and a dashboard API at
`/api/plugins/aichipmunk/` (`GET /state`, `POST /pair`, `POST /use-tailscale`) that the desktop
page reads. No core files are touched, so an update cannot overwrite it.

## DISCLOSURES

- **It changes one setting and restarts one service.** The desktop page's *Use Tailscale* action
  runs `hermes -p <profile> config set platforms.api_server.host <address>` for the profile that
  owns the API server, then restarts that gateway. It never edits a config file directly, and it
  refuses without an explicit confirmation because the restart drains in-flight runs.
- **It reads a credential, and the pairing code is that credential.** `API_SERVER_KEY` is read
  from the target profile's own secret scope at pairing time, because the API server authenticates
  per profile (`/p/<profile>/`). It is rendered locally as a QR code and never transmitted by the
  plugin. The README states the consequence plainly: while the code is on screen, treat a
  screenshot of it like the key itself.
- **No egress of its own.** The only outbound calls are the ones it visibly needs: the `tailscale`
  CLI (`status`, `serve status`, `serve --bg`) and the `hermes` CLI for the config write and the
  gateway restart. No telemetry, no analytics, no third-party hosts, no update checks.
- **It reads the local Hermes tree**, at a fixed set of locations: profile directories, their
  `config.yaml`, their `.env` secret scope, and the API server's bind. There is no caller-supplied
  path and no arbitrary file reader.
- **The desktop half stays inside the plugin SDK.** `desktop/plugin.js` imports only
  `@hermes/plugin-sdk`, `react` and `react/jsx-runtime` — no prototype patching, no `eval`/`new
  Function`, no dynamic `import()`, no reaching into app internals. `hermes plugins validate`
  confirms this on the desktop-surface check.
- **No self-updater**, and no bundled third-party code. Updates reach users only as a SHA-bump PR
  plus `hermes plugins update aichipmunk`.
- **Tailscale is how the phone reaches these bots.** The API server stays on a loopback bind
  and `tailscale serve` carries that port onto the tailnet, so the phone must be signed in to the
  same tailnet as this machine. There is no second, local-network address: the plugin reports
  what the current setup actually allows rather than implying an address works.
- **It reports rather than guesses.** When the API server's bind and the `tailscale serve` handler
  disagree — which is the state that breaks a phone that used to connect — the page says so
  instead of offering an address that cannot answer. Every address it hands over is one it has
  probed or whose Serve handler it has verified.

## DESCRIPTION

Pairs this machine's Hermes bots with the AI Chipmunk mobile app from inside Hermes Desktop — pick a bot, get the reachable host, profile and API key as a scannable code. Registers a `hermes aichipmunk` CLI command, a desktop page and a dashboard API; no tools or hooks. Disclosure — it adds a `tailscale serve` entry carrying the API server's port onto the tailnet (and only on a machine with no Tailscale CLI does it fall back to setting `platforms.api_server.host` and restarting that gateway), reads `API_SERVER_KEY` from the owning profile's secret scope at pairing time and renders it locally as the pairing code, and shells out to the `tailscale` and `hermes` CLIs; it makes no other network calls and touches no core files. Pairing requires Tailscale on this machine and on the phone.