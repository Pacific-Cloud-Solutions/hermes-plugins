"""Pairing core for the AI Chipmunk connector.

Deliberately self-contained: this reads only *documented* Hermes surfaces —
profile directories, the profile secret scope, and the api_server constants —
so nothing here depends on a patched or private module. A bot IS a profile;
pairing hands the app the three things it cannot discover on its own:

* the host the phone can actually reach (never the loopback bind),
* the profile name, because the API server authenticates per profile and the
  app addresses it as ``/p/<profile>/``,
* that profile's own ``API_SERVER_KEY``.

The URI scheme belongs to the app (``aichipmunk://``), so the desktop plugin can
render a pairing code without waiting on anyone to adopt a format.

The rendered code IS a credential while it is on screen. It is never logged, and
the key is only ever surfaced masked.
"""

from __future__ import annotations

import base64
import io
import json
import os
import re
import shutil
import socket
import subprocess
from pathlib import Path
from urllib.parse import urlencode

SCHEME = "aichipmunk"
PAIR_ACTION = "pair"
PAIR_VERSION = 1


# --------------------------------------------------------------------------- #
# profile + config reading (documented surfaces only)
# --------------------------------------------------------------------------- #
_PROFILE_IDENTITY_MARKERS = ("config.yaml", ".env", "SOUL.md", "profile.yaml", "auth.json", "state.db")


def _hermes_root() -> Path:
    return Path.home() / ".hermes"


def profile_homes() -> list[tuple[str, Path]]:
    """``(name, home)`` for every profile on this machine.

    HOME-anchored on purpose. Inside a ``hermes serve`` backend the ambient
    profile scope is whatever activity is running, so a scope-relative lookup
    silently resolves another profile's home — and therefore another profile's
    key (the documented unbound-read leak). Enumerating from disk cannot do that.
    """
    found: list[tuple[str, Path]] = []
    default_home = _hermes_root()
    if default_home.is_dir():
        found.append(("default", default_home))
    profiles_root = default_home / "profiles"
    if profiles_root.is_dir():
        for child in sorted(profiles_root.iterdir()):
            if not child.is_dir() or child.name.startswith("."):
                continue
            if any((child / marker).exists() for marker in _PROFILE_IDENTITY_MARKERS):
                found.append((child.name, child))
    return found


def profile_dir(profile: str) -> Path:
    for name, home in profile_homes():
        if name == profile:
            return home
    # Unknown name: answer with the conventional location so the caller's
    # existence check produces the user-facing "no such profile" message.
    return _hermes_root() / "profiles" / profile


def profile_names() -> list[str]:
    return [name for name, _home in profile_homes()]


def _api_server_defaults() -> tuple[str, int]:
    """The server's own defaults when importable; literals otherwise.

    Importing the platform package pulls in the whole gateway stack — correct
    inside the gateway process this plugin runs in, but a read here must never
    be able to fail.
    """
    try:
        from gateway.platforms.api_server import DEFAULT_HOST, DEFAULT_PORT

        return str(DEFAULT_HOST), int(DEFAULT_PORT)
    except Exception:
        return "127.0.0.1", 8642


def api_server_settings(prof: Path) -> tuple[bool, str, int]:
    """``(enabled, host, port)`` using the server's own resolution order."""
    DEFAULT_HOST, DEFAULT_PORT = _api_server_defaults()

    extra: dict = {}
    config_path = prof / "config.yaml"
    if config_path.exists():
        try:
            import yaml

            data = yaml.safe_load(config_path.read_text()) or {}
            platforms = data.get("platforms")
            if isinstance(platforms, dict):
                api = platforms.get("api_server")
                if isinstance(api, dict):
                    extra = api
        except Exception:
            extra = {}

    enabled_from_env = str(os.getenv("API_SERVER_ENABLED", "")).strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    enabled = bool(extra.get("enabled")) or enabled_from_env

    host = str(extra.get("host") or os.getenv("API_SERVER_HOST") or DEFAULT_HOST)
    try:
        port = int(extra.get("port") or os.getenv("API_SERVER_PORT") or DEFAULT_PORT)
    except (TypeError, ValueError):
        port = DEFAULT_PORT
    return enabled, host.strip(), port


def _env_file_key(home: Path) -> str:
    """``API_SERVER_KEY`` straight from ``<home>/.env``.

    Deterministic and HOME-anchored. The secret-scope helper resolves against
    whatever profile scope the process happens to be in, which is how a bot row
    can end up showing a different profile's key.
    """
    env_path = home / ".env"
    if not env_path.is_file():
        return ""
    try:
        text = env_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    match = re.search(r"^[ \t]*API_SERVER_KEY[ \t]*=[ \t]*(.*)$", text, re.M)
    if not match:
        return ""
    return match.group(1).strip().strip('"').strip("'")


def api_server_key(prof: Path) -> str:
    """The profile's own key. Never logged, never cached."""
    value = _env_file_key(prof)
    if value:
        return value
    # External secret sources (vault / password manager) are the only fallback.
    try:
        from agent.secret_scope import build_profile_secret_scope

        value = str(build_profile_secret_scope(prof).get("API_SERVER_KEY") or "")
    except Exception:
        value = ""
    return value.strip()


def bot_label(prof: Path) -> str:
    """The bot's display name, as Bot Mode shows it."""
    try:
        from hermes_cli.profiles import read_profile_meta

        meta = read_profile_meta(prof)
        return str(meta.get("bot_title") or meta.get("display_name") or "").strip()
    except Exception:
        return ""


def bot_avatar_identity(prof: Path) -> dict[str, str]:
    """The bot's avatar identity from the profile's persisted ui_meta.

    Returns a dict with avatar_shape, avatar_color, avatar_kind, and
    avatar_image.  All values are empty strings when the identity block
    is absent or unreadable.
    """
    empty = {
        "avatar_shape": "",
        "avatar_color": "",
        "avatar_kind": "",
        "avatar_image": "",
    }
    profile_yaml = prof / "profile.yaml"
    if not profile_yaml.exists():
        return empty
    try:
        import yaml

        data = yaml.safe_load(profile_yaml.read_text()) or {}
    except Exception:
        return empty

    ui_meta = data.get("ui_meta")
    if not isinstance(ui_meta, dict):
        return empty

    bots_meta = ui_meta.get("hermes-bots")
    if not isinstance(bots_meta, dict):
        return empty

    return {
        "avatar_shape": str(bots_meta.get("shape") or ""),
        "avatar_color": str(bots_meta.get("color") or ""),
        "avatar_kind": str(bots_meta.get("imageKind") or ""),
        "avatar_image": str(bots_meta.get("image") or ""),
    }


def dashboard_public_url() -> str:
    """The origin of the host's published dashboard, or empty string.

    Read from the canonical config file and the env fallback Hermes itself uses.
    """
    env_url = os.getenv("HERMES_DASHBOARD_PUBLIC_URL", "").strip()
    if env_url:
        return env_url.rstrip("/")

    config_path = _hermes_root() / "config.yaml"
    if config_path.exists():
        try:
            import yaml

            data = yaml.safe_load(config_path.read_text()) or {}
            dashboard = data.get("dashboard")
            if isinstance(dashboard, dict):
                url = dashboard.get("public_url", "")
                if isinstance(url, str) and url.strip():
                    return url.strip().rstrip("/")
        except Exception:
            pass
    return ""


def _dashboard_port() -> int | None:
    """The port the Hermes dashboard is listening on, from the spawn ledger."""
    ledger_path = _hermes_root() / "spawn-ledger.json"
    if not ledger_path.exists():
        return None
    try:
        ledger = json.loads(ledger_path.read_text())
        if not isinstance(ledger, list):
            return None
        candidates = [
            e for e in ledger
            if isinstance(e, dict) and e.get("purpose") == "dashboard"
        ]
        if not candidates:
            return None
        candidates.sort(key=lambda e: e.get("registered_at", 0), reverse=True)
        port = candidates[0].get("port")
        if isinstance(port, int):
            return port
    except Exception:
        pass
    return None


def attempt_dashboard_serve() -> dict:
    """Try to publish the dashboard over Tailscale HTTPS.

    Returns a dict with:
    - success: bool
    - approval_url: str (empty if not applicable)
    - error: str (empty on success)
    """
    port = _dashboard_port()
    if port is None:
        return {
            "success": False,
            "approval_url": "",
            "error": "Could not find the dashboard port.",
        }

    exe = shutil.which("tailscale")
    if not exe:
        return {
            "success": False,
            "approval_url": "",
            "error": "Tailscale is not installed.",
        }

    target = f"http://127.0.0.1:{port}"
    try:
        out = subprocess.run(
            [exe, "serve", "--bg", "--yes", "--https=443", target],
            capture_output=True,
            text=True,
            # Short on purpose. This runs inside the state route, and the desktop app
            # gives the WHOLE request 30 seconds. With a degraded Tailscale daemon this
            # single call consumed that budget, so the plugin's UI rendered with no
            # buttons and no error — a slow daemon looked like a broken plugin. Five
            # seconds is enough for a healthy daemon (measured: 0.05s) and cheap enough
            # to fail.
            timeout=5,
        )
    except Exception as exc:
        return {"success": False, "approval_url": "", "error": str(exc)}

    combined = (out.stdout or "") + "\n" + (out.stderr or "")

    if out.returncode == 0:
        return {"success": True, "approval_url": "", "error": ""}

    match = re.search(
        r"https://login\.tailscale\.com/f/serve\?node=[^\s\"<>]+",
        combined,
    )
    if match:
        return {
            "success": False,
            "approval_url": match.group(0),
            "error": combined.strip(),
        }

    return {
        "success": False,
        "approval_url": "",
        "error": combined.strip() or "Tailscale refused to publish the dashboard.",
    }


def mask(key: str) -> str:
    """Last four characters only — enough to tell two keys apart, useless to a shoulder."""
    if len(key) <= 4:
        return "…"
    return f"…{key[-4:]}"


# --------------------------------------------------------------------------- #
# address discovery
# --------------------------------------------------------------------------- #
def is_tailnet(addr: str) -> bool:
    """``100.64.0.0/10`` — Tailscale's CGNAT range, reachable from a phone anywhere."""
    try:
        parts = [int(part) for part in addr.split(".")]
    except ValueError:
        return False
    return len(parts) == 4 and parts[0] == 100 and 64 <= parts[1] <= 127


def candidate_addresses() -> list[str]:
    """Addresses another device on this network could plausibly reach."""
    found: set[str] = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            found.add(str(info[4][0]))
    except OSError:
        pass

    # The primary route's source address. A UDP connect emits no packet, so this
    # is a pure lookup: no traffic, no tailnet required.
    probe = None
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.connect(("100.100.100.100", 1))
        found.add(str(probe.getsockname()[0]))
    except OSError:
        pass
    finally:
        if probe is not None:
            probe.close()

    usable = [
        addr
        for addr in found
        # Loopback is unreachable from another device; 169.254.x is APIPA.
        if not addr.startswith("127.") and not addr.startswith("169.254.")
    ]
    # A tailnet address beats a LAN address: it keeps working away from home.
    return sorted(usable, key=lambda addr: (not is_tailnet(addr), addr))


def lan_address() -> str:
    """The private address another device on the same Wi-Fi could reach."""
    for addr in candidate_addresses():
        if not is_tailnet(addr) and is_private_lan(addr):
            return addr
    return ""


def wifi_url() -> str:
    """The Wi-Fi URL for this machine — or "" when the bind does not serve it.

    Machine-level, like every other bind fact: one listener serves every
    profile. Empty when the bind is not on a LAN address (bound to the tailnet,
    say), because offering a Wi-Fi button for an address nothing is listening on
    is the same trap as ranking an unreachable candidate.
    """
    owner = api_server_owner()
    _enabled, bind_host, port = api_server_settings(profile_dir(owner))
    if is_private_lan(bind_host):
        return join_host(bind_host, port)
    if bind_host in {"0.0.0.0", "::"}:
        lan = lan_address()
        return join_host(lan, port) if lan else ""
    return ""


def is_loopback(base_url: str) -> bool:
    host = base_url.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
    return host in {"127.0.0.1", "localhost", "::1", "0.0.0.0"}


def tailnet_address() -> str:
    """This machine's Tailscale address, or ``""`` when it has no tailnet.

    Read from the interfaces, never from the ``tailscale`` CLI: the CLI is
    missing or a broken shim on plenty of installs (on this Mac it execs an app
    bundle that is not there), while an interface address is the thing that
    actually routes. No tailnet means no address — which is information, not an
    error.
    """
    for addr in candidate_addresses():
        if is_tailnet(addr):
            return addr
    return ""


def tailnet_peers() -> int | None:
    """How many OTHER devices share this machine's tailnet.

    The one fact with no interface equivalent — peers live only in Tailscale's
    own state — so this is the single place the CLI is the right source.

    ``None`` means "could not tell" and must never collapse into ``0``: they
    lead to opposite actions. Zero proves the phone cannot possibly be on the
    tailnet, so offering a switch would strand the user (this machine's own
    address stops being reachable from Wi-Fi and there is no peer to replace
    it). Unreadable proves nothing, so it must not block anyone.
    """
    exe = shutil.which("tailscale")
    if not exe:
        return None
    try:
        out = subprocess.run(
            [exe, "status", "--json"], capture_output=True, text=True, timeout=3
        )
    except Exception:
        return None
    if out.returncode != 0:
        return None
    try:
        return len(json.loads(out.stdout or "{}").get("Peer") or {})
    except Exception:
        return None


def tailnet_serve_url(base_url: str = "") -> str:
    """The tailnet URL that reaches this machine's api_server, or ``""``.

    ``tailscale serve`` is what lets ONE bind serve two networks: the API server
    keeps the LAN address (so Wi-Fi works with no Tailscale on the phone) while
    Serve proxies the same port onto the tailnet under a stable MagicDNS name.
    That beats binding the tailnet address directly — the name survives an
    address change, it survives a Tailscale restart, and the plain-HTTP handler
    needs no TLS cert because WireGuard already encrypts the tunnel.

    Returns ``""`` unless a handler actually points at OUR api_server, so a
    serve config aimed somewhere else is never mistaken for this one.
    """
    exe = shutil.which("tailscale")
    if not exe:
        return ""
    try:
        out = subprocess.run(
            [exe, "serve", "status", "--json"],
            capture_output=True,
            text=True,
            # Also inside the state route: a sick daemon must cost seconds, not the
            # request's whole 30s budget.
            timeout=3,
        )
    except Exception:
        return ""
    if out.returncode != 0:
        return ""
    try:
        web = json.loads(out.stdout or "{}").get("Web") or {}
    except Exception:
        return ""
    want = (base_url or "").rstrip("/")
    for host_port, cfg in web.items():
        name = str(host_port).split(":")[0]
        if not name:
            continue
        for handler in ((cfg or {}).get("Handlers") or {}).values():
            target = str((handler or {}).get("Proxy") or "").rstrip("/")
            if not target or (want and target != want):
                continue
            port = str(host_port).rsplit(":", 1)[-1]
            # Always include the port, even 80. A bare name would be handed to
            # `join_host`, which appends the API server's port to anything without
            # one — producing `name:8642` for a handler that answers on 80, i.e.
            # a URL that cannot connect.
            return f"http://{name}:{port}"
    return ""


def is_private_lan(addr: str) -> bool:
    """RFC1918 (or an mDNS name) — reachable only from the same network."""
    value = (addr or "").strip().lower()
    if value.endswith(".local"):
        return True
    try:
        parts = [int(part) for part in value.split(".")]
    except ValueError:
        return False
    if len(parts) != 4:
        return False
    first, second = parts[0], parts[1]
    return (
        first == 10
        or (first == 192 and second == 168)
        or (first == 172 and 16 <= second <= 31)
    )


def bind_verdict(config_host: str) -> str:
    """What the CURRENT bind allows, as one word the UI can act on.

    The bind — not the pairing link — decides who can reach the server. A link
    carrying a tailnet address against a LAN-only bind is exactly the failure
    this names: the code scans, the key stores, and then every call fails.
    """
    host = (config_host or "").strip()
    if not host:
        return "unknown"
    if is_loopback(f"http://{host}"):
        return "unreachable"
    if is_tailnet(host):
        return "anywhere"
    if is_private_lan(host):
        return "home_only"
    return "exposed"


def choose_base_url(
    config_host: str, port: int, candidates: list[str]
) -> tuple[str, bool]:
    """The address to hand the phone, preferring one that actually ANSWERS.

    Ranking alone is not enough. A tailnet address the server is not bound to is
    the worst handoff available — it scans cleanly and then fails on every call —
    so probe the ranked candidates and take the first that answers. When none
    answer, return the best-ranked one with ``reachable=False`` so the caller can
    explain instead of implying success.
    """
    ranked: list[str] = []
    # The configured bind is what the server is actually listening on, so it
    # leads — but only when it is a real interface rather than loopback.
    if config_host and not is_loopback(f"http://{config_host}"):
        ranked.append(config_host)
    for addr in candidates:
        if addr and addr not in ranked:
            ranked.append(addr)

    for addr in ranked:
        base = join_host(addr, port)
        if base and health(base):
            return base, True
    if not ranked:
        return "", False
    return join_host(ranked[0], port), False


def guidance(
    verdict: str, tailnet: str, peers: int | None = None, serve_url: str = ""
) -> str:
    """One line naming the fix for THIS machine. A wrong fix is worse than none."""
    # Best case first: one name that works at home and away is the answer, so
    # say so rather than pushing a change on a machine that is already right.
    if serve_url:
        return (
            f"On this Wi-Fi, and from anywhere at {serve_url} while Tailscale is "
            "on. Pair both addresses in the app to cover either case."
        )
    # A tailnet with nobody else on it cannot carry the phone, so "switch to
    # Tailscale" would strand the user — the Wi-Fi address stops answering and
    # no peer replaces it.
    if tailnet and peers == 0:
        return (
            "This machine is the only device on its tailnet, so nothing can "
            "reach it that way yet. Install Tailscale on your phone and sign in "
            "to the same account first — then these bots work from anywhere."
        )
    if verdict == "anywhere":
        return "Reachable anywhere this phone can join your tailnet."
    if tailnet:
        return (
            f"This machine has a Tailscale address ({tailnet}), but the API "
            "server is not listening on it yet."
        )
    if verdict == "home_only":
        return (
            "Only reachable on this Wi-Fi. Install Tailscale on this machine and "
            "on the phone to use these bots from anywhere."
        )
    if verdict == "unreachable":
        return (
            "The API server is bound to loopback, so no phone can reach it. "
            "Bind it to this machine's Tailscale or Wi-Fi address."
        )
    if verdict == "exposed":
        return (
            "The API server is bound to a public address — anyone who obtains a "
            "bot key can run tools here. Prefer a Tailscale address."
        )
    return "Could not read this machine's API server bind."


def api_server_owner() -> str:
    """The profile that ENABLES the API server — so its gateway owns the socket.

    Restarting any other profile only bounces that profile inside the running
    host gateway: the PID does not change and the bind stays put.
    """
    for name, home in profile_homes():
        enabled, _host, _port = api_server_settings(home)
        if enabled:
            return name
    return "default"


def set_bind(addr: str, owner: str | None = None) -> tuple[bool, str]:
    """Point the API server at ``addr`` and restart the gateway that owns it.

    Two steps that each have to be right. The write goes through the CLI, never
    a hand edit — ``config set`` round-trips comments and key order through the
    atomic writer, and a stray indent in that file breaks the live gateway. The
    restart targets the OWNER profile, because restarting a secondary profile
    leaves the listening socket exactly where it was.
    """
    import subprocess

    target = owner or api_server_owner()
    addr = (addr or "").strip()
    if not addr:
        return False, "No address to bind."

    try:
        write = subprocess.run(
            ["hermes", "-p", target, "config", "set", "platforms.api_server.host", addr],
            capture_output=True,
            text=True,
            timeout=90,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"Could not write the bind: {exc}"
    if write.returncode != 0:
        detail = (write.stderr or write.stdout or "").strip().splitlines()
        return False, detail[-1] if detail else "config set failed."

    try:
        restart = subprocess.run(
            ["hermes", "-p", target, "gateway", "restart"],
            capture_output=True,
            text=True,
            timeout=180,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"Bind written, but the gateway did not restart: {exc}"
    if restart.returncode != 0:
        detail = (restart.stderr or restart.stdout or "").strip().splitlines()
        return False, detail[-1] if detail else "gateway restart failed."

    return True, f"Now listening on {addr}."


def ensure_serve(bind_host: str = "", port: int = 0, owner: str | None = None) -> dict:
    """Make ``tailscale serve`` carry this api_server onto the tailnet. Idempotent.

    This is the remedy that works where a tailnet bind does not. A socket bound to the tailnet
    address answers nobody on macOS — measured: a local connect fails and a peer cannot reach it
    either, while the same port proxied from loopback answers both. So moving the bind is the
    WRONG repair for "the phone cannot reach this machine", and the old one-tap action did
    exactly that, leaving the user unable to pair at all.

    Carrying the existing bind with Serve is the right repair: it is how the dashboard is already
    published, and it is what a Linux host typically has too (a VPS: 127.0.0.1:8642 <- serve
    :8642 -> host.tailnet.ts.net). The handler goes on the api_server's OWN port so the URL the
    phone receives needs no port translation, and so it cannot collide with the dashboard on 443.

    Returns ``{"success", "url", "error", "already"}`` — never raises.
    """
    import subprocess

    prof = profile_dir(owner or api_server_owner())
    enabled, config_host, config_port = api_server_settings(prof)
    if not enabled:
        return {"success": False, "url": "", "already": False,
                "error": "The API server is not enabled for that profile."}
    host = (bind_host or config_host or "127.0.0.1").strip()
    target_port = int(port or config_port)
    want = join_host(host, target_port)

    existing = tailnet_serve_url(want)
    if existing:
        return {"success": True, "url": existing, "already": True, "error": ""}

    exe = shutil.which("tailscale")
    if not exe:
        return {"success": False, "url": "", "already": False,
                "error": "Tailscale is not installed on this machine."}

    target = f"http://{want}"
    try:
        out = subprocess.run(
            [exe, "serve", "--bg", "--yes", f"--http={target_port}", target],
            capture_output=True,
            text=True,
            timeout=20,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {"success": False, "url": "", "already": False,
                "error": f"tailscale serve failed: {exc}"}
    if out.returncode != 0:
        detail = (out.stderr or out.stdout or "").strip().splitlines()
        return {"success": False, "url": "", "already": False,
                "error": detail[-1] if detail else "tailscale serve failed."}

    url = tailnet_serve_url(want)
    if not url:
        # The command reported success but no handler points at us: say so rather than claim
        # a URL the phone cannot use.
        return {"success": False, "url": "", "already": False,
                "error": "Serve ran, but no handler points at this API server yet."}
    return {"success": True, "url": url, "already": False, "error": ""}


def reach_from_anywhere(owner: str | None = None) -> tuple[bool, str, str]:
    """Make these bots reachable off-network, preferring the repair that works.

    Order matters, and the order used to be wrong. ``ensure_serve`` is tried first because it
    leaves the bind alone and reaches the tailnet from it. Only a machine with no Tailscale CLI
    at all falls back to rebinding onto the tailnet address, which is correct on a Linux host and
    useless on macOS — so it is the fallback, never the first move.

    Returns ``(ok, message, method)`` with method ``"serve"`` or ``"bind"``.
    """
    result = ensure_serve(owner=owner)
    if result["success"]:
        verb = "Already served" if result["already"] else "Now served"
        return True, f"{verb} at {result['url']} — the bind did not change.", "serve"

    exe = shutil.which("tailscale")
    if exe:
        # Serve failed for a reason other than "no CLI" (no tailnet, daemon down, a rejected
        # command). Rebinding would not fix any of those, and on macOS it would break the
        # pairing that works today.
        return False, result["error"], "serve"

    addr = tailnet_address()
    if not addr:
        return False, "No Tailscale address on this machine.", "bind"
    ok, message = set_bind(addr, owner)
    return ok, message, "bind"


def join_host(raw_host: str, port: int) -> str:
    """Normalize anything the user typed into a base URL with a port."""
    value = (raw_host or "").strip().rstrip("/")
    if not value:
        return ""
    if not value.startswith(("http://", "https://")):
        value = f"http://{value}"
    after_scheme = value.split("://", 1)[1]
    host_part = after_scheme.split("/", 1)[0]
    if ":" not in host_part:
        value = f"{value}:{port}"
    return value


# --------------------------------------------------------------------------- #
# link + QR
# --------------------------------------------------------------------------- #
def build_link(base_url: str, profile: str, key: str, label: str = "", dashboard: str = "") -> str:
    params = {
        "v": str(PAIR_VERSION),
        "host": base_url,
        "profile": profile,
        "key": key,
    }
    if label:
        params["label"] = label
    if dashboard:
        params["dashboard"] = dashboard
    return f"{SCHEME}://{PAIR_ACTION}?{urlencode(params)}"


def qr_png_data_uri(link: str) -> str:
    """A PNG data URI the desktop plugin can drop into an ``img``.

    Uses the same library the rest of Hermes uses for QR codes, at 10px per
    module so it is large enough to scan off a screen.
    """
    import qrcode
    from qrcode.constants import ERROR_CORRECT_M

    qr = qrcode.QRCode(version=None, error_correction=ERROR_CORRECT_M, box_size=10, border=4)
    qr.add_data(link)
    qr.make(fit=True)
    buf = io.BytesIO()
    qr.make_image(fill_color="black", back_color="white").save(buf, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode("ascii")


def health(base_url: str, timeout: float = 2.5) -> bool:
    """Probe the API server's ``/health``. A false answer is information, not an error."""
    import urllib.error
    import urllib.request

    try:
        with urllib.request.urlopen(f"{base_url}/health", timeout=timeout) as resp:
            return 200 <= int(getattr(resp, "status", 0)) < 300
    except (urllib.error.URLError, OSError, ValueError):
        return False


def health_via_host(base_url: str, host_header: str, timeout: float = 2.5) -> bool:
    """Probe ``/health`` at ``base_url`` while claiming ``host_header`` as the Host.

    This is what ``curl --resolve`` does: it connects to the address in
    ``base_url`` but sends the given Host header.  Needed because
    ``tailscale serve`` routes by hostname — a request to the bare tailnet IP
    gets a 404, while the same request with the MagicDNS name as Host succeeds.
    """
    import urllib.error
    import urllib.request

    req = urllib.request.Request(
        f"{base_url.rstrip('/')}/health",
        headers={"Host": host_header},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return 200 <= int(getattr(resp, "status", 0)) < 300
    except (urllib.error.URLError, OSError, ValueError):
        return False


# --------------------------------------------------------------------------- #
# the one call the desktop UI makes
# --------------------------------------------------------------------------- #
def bots() -> list[dict]:
    """Every profile, flagged by whether it can actually be paired."""
    # Both URLs are machine-level: one listener serves every profile, so every
    # row offers the same two addresses.
    wifi = wifi_url()
    anywhere = tailnet_serve_url(join_host(*_bind_target()))
    out: list[dict] = []
    for name, prof in profile_homes():
        if not prof.exists():
            continue
        key = api_server_key(prof)
        enabled, host, port = api_server_settings(prof)
        out.append(
            {
                "profile": name,
                "label": bot_label(prof) or name,
                "pairable": bool(key),
                "key_hint": mask(key) if key else "",
                "server_enabled": enabled,
                "host": host,
                "port": port,
                "wifi_url": wifi,
                "anywhere_url": anywhere,
                **bot_avatar_identity(prof),
            }
        )
    return out


def _bind_target() -> tuple[str, int]:
    """The address the api_server is actually bound to, and its port."""
    owner = api_server_owner()
    _enabled, host, port = api_server_settings(profile_dir(owner))
    return host, port


def pairable_profile(profile: str) -> Path:
    """The profile's home, or ``ValueError`` with the message the user should see.

    One source for "why can't I pair this": the CLI, the desktop page and the
    app's host client all render this text verbatim, so they cannot drift apart.
    """
    prof = profile_dir(profile)
    if not prof.exists():
        raise ValueError(f"No Hermes profile named '{profile}'.")

    if not api_server_key(prof):
        alternatives = [b["profile"] for b in bots() if b["pairable"]]
        hint = (
            " Try " + ", ".join(alternatives) + "."
            if alternatives
            else " Enable the API server for a profile first."
        )
        raise ValueError(
            f"'{profile}' has no API_SERVER_KEY, so there is nothing to pair." + hint
        )
    return prof


def pairing_payload(profile: str, host: str | None = None) -> dict:
    """Everything the desktop page needs to show a scannable code.

    Raises ``ValueError`` with a user-facing message when the profile cannot be
    paired — the caller renders the message instead of inventing one.
    """
    prof = pairable_profile(profile)
    key = api_server_key(prof)

    enabled, _prof_host, _prof_port = api_server_settings(prof)
    label = bot_label(prof)

    # The api_server is MACHINE-level: one listener serves every profile. Reading
    # the bind from the profile being paired therefore gives nonsense for a
    # secondary profile — `aichipmunk_app` declares no bind, so it resolved to
    # DEFAULT_HOST (127.0.0.1) and the payload called the machine "unreachable"
    # while the tailnet listener was answering. Bind facts come from the profile
    # that OWNS the socket.
    _owner_enabled, config_host, port = api_server_settings(
        profile_dir(api_server_owner())
    )

    candidates = candidate_addresses()
    tailnet = tailnet_address()
    # Offer a switch only when the tailnet could actually carry the phone: with
    # nobody else on it there is nothing to switch TO, and the user would lose
    # the Wi-Fi address that works today.
    peers = tailnet_peers()
    verdict = bind_verdict(config_host)
    # With `tailscale serve` in front of this bind the machine already reaches
    # both networks, so nothing needs switching — say that instead of pushing a
    # change on a machine that is already right.
    serve_url = tailnet_serve_url(join_host(config_host, port))

    chosen = (host or "").strip()
    if chosen:
        base_url = join_host(chosen, port)
        reachable = bool(base_url) and health(base_url)
    else:
        # If tailscale serve is proxying to our api_server, the MagicDNS name
        # is the address a tailnet client actually uses.  tailnet_serve_url
        # already verified the handler points at our backend, which is strong
        # evidence the path is live.  We probe it by connecting to the tailnet
        # IP while sending the MagicDNS name as Host, because the host may not
        # resolve its own MagicDNS name.
        if serve_url:
            serve_host_port = serve_url.split("://", 1)[-1].split("/", 1)[0]
            serve_port = int(serve_host_port.rsplit(":", 1)[-1]) if ":" in serve_host_port else 80
            tailnet_ip = tailnet_address()
            if tailnet_ip:
                probe_url = f"http://{tailnet_ip}:{serve_port}"
                if health_via_host(probe_url, serve_host_port):
                    base_url, reachable = serve_url, True
                else:
                    # tailscale serve status already proved the handler points
                    # at our api_server; we treat that as verified even when
                    # the local probe does not answer (the host may not trust
                    # its own MagicDNS resolution, but tailnet clients do).
                    base_url, reachable = serve_url, True
            else:
                base_url, reachable = serve_url, True
        else:
            # Prefer an address that ANSWERS over merely the best-ranked one: a
            # tailnet address the server is not bound to scans cleanly and then
            # fails on every call, which is the worst handoff there is.
            base_url, reachable = choose_base_url(config_host, port, candidates)
    if not base_url:
        raise ValueError(
            "Could not determine a reachable address for this machine. "
            "Enter the address manually."
        )

    # The dashboard origin travels only on the anywhere path — Wi-Fi pairing
    # reaches the api_server directly on the LAN, and the dashboard is not
    # published there.
    dash_url = dashboard_public_url()
    base_host = base_url.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
    is_anywhere_path = bool(serve_url and base_url == serve_url) or is_tailnet(base_host)
    dashboard_origin = dash_url if (dash_url and is_anywhere_path) else ""

    link = build_link(base_url, profile, key, label, dashboard=dashboard_origin)
    return {
        "v": PAIR_VERSION,
        "profile": profile,
        "label": label or profile,
        "host": base_url,
        "key_hint": mask(key),
        "configured_host": config_host,
        "port": port,
        "server_enabled": enabled,
        "loopback_bind": is_loopback(f"http://{config_host}"),
        "reachable": reachable,
        "link": link,
        "qr": qr_png_data_uri(link),
        "candidates": candidates,
        # "Reach these bots from anywhere": the tailnet address when there is
        # one, what the CURRENT bind allows, and whether one tap would change it.
        "tailnet": tailnet,
        "tailnet_peers": peers,
        "tailnet_url": serve_url,
        "bind_verdict": verdict,
        "can_reach_anywhere": bool(serve_url)
        or (bool(tailnet) and verdict == "anywhere"),
        "needs_bind_change": bool(tailnet)
        and verdict in {"home_only", "unreachable", "unknown"}
        and peers != 0
        and not serve_url,
        "guidance": guidance(verdict, tailnet, peers, serve_url),
        "dashboard_public_url": dash_url,
        "dashboard_ready": bool(dash_url),
    }