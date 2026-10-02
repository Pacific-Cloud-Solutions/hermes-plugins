"""AI Chipmunk connector — pair this machine's Hermes bots with the app.

Two halves, one plugin (the unified-package layout):

* this Python half registers ``hermes aichipmunk`` for headless users and owns
  ``pairing.py``, the module both halves read through;
* ``desktop/plugin.js`` renders the same pairing code inside Hermes Desktop, so
  the terminal is optional rather than required.

Nothing here patches core, and nothing is written to disk: the bot's key is read
from its own profile secret scope when a code is minted, and never stored again.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


def _register_cli(parser) -> None:
    """Add options to the ``hermes aichipmunk`` parser.

    The framework creates the parser for the registered command name and passes
    it in, so this adds arguments — it must not build a subparser of its own.
    """
    parser.set_defaults(func=_aichipmunk_command)
    parser.add_argument(
        "-p",
        "--profile",
        default=None,
        help="Profile (bot) to pair. Defaults to the active profile.",
    )
    parser.add_argument(
        "--host",
        default=None,
        help="Address the phone will use, if it differs from the detected one.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the pairing data as JSON instead of a rendered code.",
    )
    parser.add_argument(
        "--show-link",
        action="store_true",
        help=(
            "Include the pairing link in --json output. The link carries the bot "
            "key, so it is omitted by default: JSON tends to end up in logs and "
            "transcripts."
        ),
    )


def _load_pairing():
    """Load ``pairing.py`` by path — plugin modules are not always a package."""
    import importlib.util
    from pathlib import Path

    path = Path(__file__).resolve().parent / "pairing.py"
    spec = importlib.util.spec_from_file_location("aichipmunk_pairing", path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def _active_profile() -> str:
    """The active profile, without depending on a version-specific helper.

    ``hermes_cli.profiles.current_profile_name`` does NOT exist on every release
    (``ImportError`` on 0.21.4), and a plugin that cannot be imported is worse
    than one that guesses: the command simply does not exist for that user. The
    CLI already tells us in the environment — an active profile makes
    ``$HERMES_HOME`` that profile's own directory.
    """
    import os
    from pathlib import Path

    home = os.environ.get("HERMES_HOME", "").strip()
    if home:
        path = Path(home)
        # ~/.hermes/profiles/<name>  →  <name>;  ~/.hermes  →  default
        if path.parent.name == "profiles":
            return path.name
    return os.environ.get("HERMES_PROFILE", "").strip() or "default"


def _aichipmunk_command(args) -> int:
    import json
    import sys

    pairing = _load_pairing()

    requested = (getattr(args, "profile", None) or "").strip()
    profile = requested or _active_profile()

    try:
        payload = pairing.pairing_payload(profile, getattr(args, "host", None))
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    if getattr(args, "json", False):
        out = {k: v for k, v in payload.items() if k not in {"qr", "link"}}
        out["link_present"] = bool(payload.get("link"))
        if getattr(args, "show_link", False):
            out["link"] = payload["link"]
        print(json.dumps(out, indent=2))
        return 0

    # Terminal users still get a code; the desktop page is the nicer path.
    print()
    print(f"  {payload['label']}  ({payload['profile']})")
    print(f"  host:  {payload['host']}   key: {payload['key_hint']}")
    if not payload["reachable"]:
        print("  note:  this address did not answer /health just now.")
    print()

    link = payload.get("link") or ""

    # The QR is a convenience; the LINK is the contract. A headless host often
    # has no qrcode installed — and letting that failure swallow the whole output
    # path left the user with nothing to pair with, on exactly the machine that
    # has no desktop app to fall back to. So the link prints either way.
    rendered = False
    if link:
        try:
            import qrcode
            from qrcode.constants import ERROR_CORRECT_M

            qr = qrcode.QRCode(
                version=None, error_correction=ERROR_CORRECT_M, box_size=1, border=1
            )
            qr.add_data(link)
            qr.make(fit=True)
            qr.print_ascii(invert=True)
            rendered = True
        except Exception:
            rendered = False

    print()
    if link:
        print("  Pairing link — paste this into AI Chipmunk, or send it to the phone:")
        print()
        print(f"    {link}")
        print()
    if not link:
        print("  No address to pair against was found.")
        print("  Pass the address the phone should use, e.g. --host https://bots.example.com")
        print()
    elif not rendered:
        print("  (No QR renderer installed here — the link above is all you need.)")
        print()
    print("  This link is a credential while it is on screen.")
    return 0


def register(ctx) -> None:
    """Called once by the plugin loader."""
    ctx.register_cli_command(
        name="aichipmunk",
        help="Connect this machine's bots to the AI Chipmunk app",
        setup_fn=_register_cli,
        handler_fn=_aichipmunk_command,
        description=(
            "Pair a Hermes bot (a profile) with the AI Chipmunk mobile app. "
            "Renders the pairing code in Hermes Desktop under AI Chipmunk."
        ),
    )
    logger.debug("aichipmunk plugin registered")