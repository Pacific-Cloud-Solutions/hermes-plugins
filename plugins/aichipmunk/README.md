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

No core files are touched, so an update cannot overwrite it. Two things outside it still have
to be right, and the plugin reports on both at pairing time: the api_server bind, and a healthy
`tailscale` daemon on this machine — the phone reaches these bots over the tailnet, so Tailscale
has to be signed in here and on the phone.

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

## Pairing a machine that isn't this one

The plugin pairs **the machine it runs on**: pairing reads that machine's own profiles, its
`API_SERVER_KEY` and its api_server bind. To pair a phone with a VPS or another host, install the
plugin on *that* host — running it here pairs this machine's bots.

**In the app (easiest):** open the Bots page, choose **Connect to a host**, and enter that host's
dashboard address (e.g. `https://your-vps.example.com`). The app signs in against the host and
reads the live bot roster straight from this plugin's API — nothing has to be typed into the
server's terminal. For that to work the host's dashboard must be published, so on a fresh install
run it once there:

```bash
hermes plugins install Pacific-Cloud-Solutions/hermes-plugins/plugins/aichipmunk --yes-deps
hermes dashboard register      # lets the app reach the host and list its bots
```

**From the terminal (alternative):** the CLI on that host prints the pairing link and a scannable
QR, which is what you need when the dashboard is not published:

```bash
hermes aichipmunk          # pairing link + QR code, in the terminal
hermes aichipmunk --json   # machine-readable (the link is redacted to `link_present`)
```

`--yes-deps` answers the `qrcode` dependency question up front, which is what a non-interactive
install (SSH, CI, a container entrypoint) needs — without it the install can be refused.

Either way the plugin's API (`/api/plugins/aichipmunk/`) is served by that host, and the
`tailscale serve` handler puts the API server on the tailnet.

The **Desktop page is an app-level surface**: Hermes Desktop loads it from
`~/.hermes/desktop-plugins/` on the machine running the app — never from the host the window is
connected to. So installing this plugin on a remote host does not add its page to your local
Desktop app; that host is what the CLI is for. If you do want the page locally, **Capabilities →
Plugins** offers **Install here** for the desktop half.

## Security posture

- The key is read from the profile's own secret scope **at pairing time** and is
  never stored, cached, or logged by this plugin.
- Only the last four characters are ever shown (`…4f2a`).
- The desktop page is served over the app's existing authenticated gateway; the
  plugin opens **no listener of its own**. When you switch a bot to Tailscale it
  does add a persistent `tailscale serve` handler carrying that API server's port
  onto your tailnet — that is a real change to this machine's Tailscale config.
  `tailscale serve status` shows it and `tailscale serve reset` removes it.
- The rendered code is a credential while it is on screen. Treat a screenshot of
  it like the key itself.

## Status

Phase 1: local pairing, desktop surface, no terminal.

Phase 2 (not yet built): the cloud rendezvous — outbound-only connector to AI
Chipmunk, Cloud Functions for pairing/policy, and a route ladder (LAN → tunnel →
P2P → relay) so the phone reaches a machine behind any network.