"""AI Chipmunk plugin backend, mounted at ``/api/plugins/aichipmunk/``.

Serves the desktop plugin's page: which bots can be paired, and the pairing code
for the one the user picks. Stateless by design — the code is minted on demand
from the profile's own secret scope, and the plugin never stores a key.

``pairing.py`` is loaded by file path rather than imported as a package, because
plugin backends are loaded as standalone modules (the same way the shipped
plugins' tests load them).
"""

from __future__ import annotations

import importlib.util
import time
from pathlib import Path

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter()

_PAIRING_PATH = Path(__file__).resolve().parents[1] / "pairing.py"
_spec = importlib.util.spec_from_file_location("aichipmunk_pairing", _PAIRING_PATH)
pairing = importlib.util.module_from_spec(_spec)
assert _spec and _spec.loader
_spec.loader.exec_module(pairing)


class PairRequest(BaseModel):
    profile: str
    host: str | None = None


class UseTailscaleRequest(BaseModel):
    # Explicit, because the action restarts the gateway that owns the socket.
    confirm: bool = False


@router.get("/state")
def state() -> dict:
    """Machine addresses, every bot, and whether these bots work off-network.

    The verdict describes the CURRENT bind, which is the thing that decides who
    can reach the server — a pairing link carrying a tailnet address against a
    LAN-only bind is the failure this names.
    """
    tailnet = pairing.tailnet_address()
    peers = pairing.tailnet_peers()
    owner = pairing.api_server_owner()
    _enabled, config_host, port = pairing.api_server_settings(
        pairing.profile_dir(owner)
    )
    verdict = pairing.bind_verdict(config_host)
    # One bind, two networks: Serve carries the same port onto the tailnet under
    # a stable name, so this machine needs no bind change at all.
    serve_url = pairing.tailnet_serve_url(pairing.join_host(config_host, port))
    dash_url = pairing.dashboard_public_url()
    can_anywhere = bool(serve_url) or (bool(tailnet) and verdict == "anywhere")
    serve_attempt: dict = {}
    if not dash_url and can_anywhere:
        serve_attempt = pairing.attempt_dashboard_serve()
        if serve_attempt.get("success"):
            dash_url = pairing.dashboard_public_url()
    return {
        "hosts": pairing.candidate_addresses(),
        "bots": pairing.bots(),
        "tailnet": tailnet,
        "tailnet_peers": peers,
        "tailnet_url": serve_url,
        "bind_verdict": verdict,
        "owner": owner,
        "can_reach_anywhere": can_anywhere,
        # Only when the tailnet could actually carry the phone AND nothing is
        # already carrying it there. With nobody else on the tailnet there is
        # nothing to switch TO and the Wi-Fi address that works today would stop
        # answering.
        "needs_bind_change": bool(tailnet)
        and verdict in {"home_only", "unreachable", "unknown"}
        and peers != 0
        and not serve_url,
        "guidance": pairing.guidance(verdict, tailnet, peers, serve_url),
        "dashboard_public_url": dash_url,
        "dashboard_ready": bool(dash_url),
        "dashboard_approval_url": serve_attempt.get("approval_url", ""),
        "dashboard_serve_error": serve_attempt.get("error", ""),
    }


@router.post("/use-tailscale")
def use_tailscale(req: UseTailscaleRequest) -> dict:
    """Point the API server at this machine's tailnet address. One tap.

    Refuses without an explicit confirm, because it restarts the gateway that
    owns the socket and drains in-flight runs. Refuses when there is no tailnet
    rather than guessing an address: the fix for "no Tailscale" is to install
    it, not to bind somewhere else.

    Refuses, too, when this machine is ALONE on its tailnet. Hiding the button
    is not a guard — the action is one POST away — and the outcome would be the
    worst possible one: the Wi-Fi address stops answering while the tailnet has
    no peer to take over, so the user is locked out of their own bots.
    """
    addr = pairing.tailnet_address()
    if not addr:
        raise HTTPException(
            status_code=409,
            detail=(
                "No Tailscale address on this machine. Install Tailscale and sign "
                "in here and on the phone, then try again."
            ),
        )

    peers = pairing.tailnet_peers()
    if peers == 0:
        raise HTTPException(
            status_code=409,
            detail=(
                "This machine is the only device on its tailnet, so binding it "
                "here would make these bots unreachable from Wi-Fi as well. "
                "Install Tailscale on your phone and sign in to the same account, "
                "then try again."
            ),
        )

    owner = pairing.api_server_owner()
    if not req.confirm:
        return {
            "applied": False,
            "confirm_required": True,
            "address": addr,
            "owner": owner,
            "detail": (
                f"This binds the API server to {addr} and restarts the '{owner}' "
                "gateway that owns it. Runs in progress will be drained."
            ),
        }

    ok, message = pairing.set_bind(addr, owner)
    if not ok:
        raise HTTPException(status_code=500, detail=message)

    _enabled, config_host, port = pairing.api_server_settings(
        pairing.profile_dir(owner)
    )
    base_url = pairing.join_host(addr, port)
    # The listener needs a moment to come back up; reporting the old state here
    # would tell the user their one tap failed when it did not.
    reachable = False
    for _attempt in range(8):
        if pairing.health(base_url):
            reachable = True
            break
        time.sleep(1.5)

    return {
        "applied": True,
        "address": addr,
        "bind_verdict": pairing.bind_verdict(config_host),
        "reachable": reachable,
        "detail": message if reachable else f"{message} Not answering yet.",
    }


@router.post("/pair")
def pair(req: PairRequest) -> dict:
    try:
        return pairing.pairing_payload(req.profile, req.host)
    except ValueError as exc:
        # 400 carries the user-facing message the page renders verbatim.
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/health-check")
def health_check(host: str) -> dict:
    """Re-probe one address, so the page can offer a 'Try again' action."""
    return {"host": host, "reachable": pairing.health(host)}


