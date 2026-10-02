# AI Chipmunk — Hermes connector plugin

Connect a Hermes machine's bots to the **AI Chipmunk** mobile app.

A bot *is* a Hermes profile. Pairing hands the app the three things it cannot
discover on its own: the host the phone can actually reach, the profile name
(the API server authenticates per profile, addressed as `/p/<profile>/`), and
that profile's own `API_SERVER_KEY`.

## What this replaces

Pairing used to be terminal-only (`hermes bots pair`), which cannot ship to
customers. This plugin contributes the same capability as a **unified package** —
one folder, two halves:

| Half | File | Role |
|---|---|---|
| Agent | `__init__.py`, `pairing.py` | pairing core; `hermes aichipmunk` for headless use |
| Desktop | `desktop/plugin.js` | renders the code in Hermes Desktop: page, sidebar row, ⌘K command, status chip |
| Backend | `dashboard/plugin_api.py` | the desktop page's data (`/api/plugins/aichipmunk/`) |

No core files are touched, so an update cannot overwrite it. Two things outside it still
have to be right, and the plugin reports on both at pairing time: the api_server bind (the
address the phone must actually reach) and a healthy `tailscale` daemon when you pair over
the tailnet rather than the local network.

## Install

```bash
# Listed in the catalog — install by name.
hermes plugins install aichipmunk

# Not listed yet, or pinning a release: name the subdirectory, because this repo
# holds several plugins. `Pacific-Cloud-Solutions/hermes-plugins#plugins/aichipmunk`
# is the equivalent spelling.
hermes plugins install Pacific-Cloud-Solutions/hermes-plugins/plugins/aichipmunk

hermes plugins enable aichipmunk
```

`--ref <40-character commit sha>` installs exactly one immutable commit: the tag marks a
release, the commit is what actually installs.

Then open **AI Chipmunk** in the desktop app's sidebar (or ⌘K → *Connect AI
Chipmunk*), pick a bot, and scan the code with the phone.

Headless equivalent:

```bash
hermes aichipmunk -p default          # renders a terminal code
hermes aichipmunk -p default --json   # machine-readable (never includes the QR blob)
```

## Security posture

- The key is read from the profile's own secret scope **at pairing time** and is
  never stored, cached, or logged by this plugin.
- Only the last four characters are ever shown (`…4f2a`).
- The desktop page is served over the app's existing authenticated gateway; the
  plugin adds no new network listener.
- The rendered code is a credential while it is on screen. Treat a screenshot of
  it like the key itself.

## Status

Phase 1: local pairing, desktop surface, no terminal.

Phase 2 (not yet built): the cloud rendezvous — outbound-only connector to AI
Chipmunk, Cloud Functions for pairing/policy, and a route ladder (LAN → tunnel →
P2P → relay) so the phone reaches a machine behind any network.