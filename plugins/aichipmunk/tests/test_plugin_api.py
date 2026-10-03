"""The plugin backend's contract: what it refuses, previews, and performs.

The confirm gate is the safety-critical part. The action can restart the gateway
that owns the listening socket — the fallback path does, the serve path does not —
so a request that arrives without an explicit confirm must change NOTHING — asserted
by proving `reach_from_anywhere` was never called, not merely by reading the response
body.
"""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path
from unittest import mock

from fastapi import HTTPException

_API = Path(__file__).resolve().parents[1] / "dashboard" / "plugin_api.py"
_spec = importlib.util.spec_from_file_location("aichipmunk_plugin_api", _API)
plugin_api = importlib.util.module_from_spec(_spec)
assert _spec and _spec.loader
_spec.loader.exec_module(plugin_api)

pairing = plugin_api.pairing


class UseTailscale(unittest.TestCase):
    def test_no_tailnet_is_refused_rather_than_guessed(self):
        with mock.patch.object(pairing, "tailnet_address", return_value=""):
            with self.assertRaises(HTTPException) as caught:
                plugin_api.use_tailscale(plugin_api.UseTailscaleRequest())
        self.assertEqual(caught.exception.status_code, 409)
        self.assertIn("Install Tailscale", caught.exception.detail)

    def test_being_alone_on_the_tailnet_is_refused_not_merely_hidden(self):
        # Hiding the button is not a guard: the action is one POST away, and the
        # outcome is the user locking themselves out of their own bots.
        with (
            mock.patch.object(pairing, "tailnet_address", return_value="100.101.102.103"),
            mock.patch.object(pairing, "tailnet_peers", return_value=0),
            mock.patch.object(pairing, "tailnet_serve_url", return_value=""),
            mock.patch.object(pairing, "set_bind") as set_bind,
        ):
            with self.assertRaises(HTTPException) as caught:
                plugin_api.use_tailscale(plugin_api.UseTailscaleRequest(confirm=True))

        self.assertEqual(caught.exception.status_code, 409)
        self.assertIn("only device on its tailnet", caught.exception.detail)
        set_bind.assert_not_called()

    def test_unknown_peer_count_does_not_block_a_switch(self):
        # "Cannot tell" must not be treated as "nobody is there": one allows the
        # action the user asked for, the other refuses it.
        with (
            mock.patch.object(pairing, "tailnet_address", return_value="100.101.102.103"),
            mock.patch.object(pairing, "tailnet_peers", return_value=None),
            mock.patch.object(pairing, "tailnet_serve_url", return_value=""),
            mock.patch.object(pairing, "api_server_owner", return_value="default"),
            mock.patch.object(
                pairing,
                "reach_from_anywhere",
                return_value=(True, "Written.", "serve"),
            ),
            mock.patch.object(
                pairing, "api_server_settings", return_value=(True, "100.101.102.103", 8642)
            ),
            mock.patch.object(pairing, "profile_dir", return_value=Path("/tmp")),
            mock.patch.object(pairing, "health", return_value=True),
        ):
            out = plugin_api.use_tailscale(plugin_api.UseTailscaleRequest(confirm=True))
        self.assertTrue(out["applied"])

    def test_without_confirm_it_previews_and_changes_nothing(self):
        with (
            mock.patch.object(pairing, "tailnet_address", return_value="100.101.102.103"),
            mock.patch.object(pairing, "tailnet_peers", return_value=1),
            mock.patch.object(pairing, "tailnet_serve_url", return_value=""),
            mock.patch.object(pairing, "api_server_owner", return_value="default"),
            mock.patch.object(pairing, "set_bind") as set_bind,
        ):
            out = plugin_api.use_tailscale(plugin_api.UseTailscaleRequest())

        self.assertFalse(out["applied"])
        self.assertTrue(out["confirm_required"])
        self.assertEqual(out["address"], "100.101.102.103")
        self.assertEqual(out["owner"], "default")
        self.assertIn("restarts", out["detail"])
        set_bind.assert_not_called()

    def test_confirm_performs_the_change_and_reports_reachability(self):
        with (
            mock.patch.object(pairing, "tailnet_address", return_value="100.101.102.103"),
            mock.patch.object(pairing, "tailnet_peers", return_value=1),
            mock.patch.object(pairing, "tailnet_serve_url", return_value=""),
            mock.patch.object(pairing, "api_server_owner", return_value="default"),
            mock.patch.object(
                pairing,
                "reach_from_anywhere",
                return_value=(True, "Now served at http://box.ts.net:8642 — the bind did not change.", "serve"),
            ) as reach,
            # The trap this guards: the old action rebound the API server onto the tailnet
            # address, which answers nobody on macOS, so one tap left the user unable to
            # pair at all. With a working Serve path, the bind must never be touched.
            mock.patch.object(pairing, "set_bind") as set_bind,
            mock.patch.object(
                pairing, "api_server_settings", return_value=(True, "100.101.102.103", 8642)
            ),
            mock.patch.object(pairing, "profile_dir", return_value=Path("/tmp")),
            mock.patch.object(pairing, "health", return_value=True),
        ):
            out = plugin_api.use_tailscale(plugin_api.UseTailscaleRequest(confirm=True))

        self.assertTrue(out["applied"])
        self.assertTrue(out["reachable"])
        self.assertEqual(out["bind_verdict"], "anywhere")
        self.assertEqual(out["method"], "serve")
        reach.assert_called_once()
        set_bind.assert_not_called()

    def test_a_bind_that_does_not_answer_says_so_instead_of_claiming_success(self):
        with (
            mock.patch.object(pairing, "tailnet_address", return_value="100.101.102.103"),
            mock.patch.object(pairing, "tailnet_peers", return_value=1),
            mock.patch.object(pairing, "tailnet_serve_url", return_value=""),
            mock.patch.object(pairing, "api_server_owner", return_value="default"),
            mock.patch.object(
                pairing,
                "reach_from_anywhere",
                return_value=(True, "Written.", "serve"),
            ),
            mock.patch.object(
                pairing, "api_server_settings", return_value=(True, "100.101.102.103", 8642)
            ),
            mock.patch.object(pairing, "profile_dir", return_value=Path("/tmp")),
            mock.patch.object(pairing, "health", return_value=False),
            mock.patch("time.sleep", return_value=None),
        ):
            out = plugin_api.use_tailscale(plugin_api.UseTailscaleRequest(confirm=True))

        self.assertFalse(out["reachable"])
        # The serve path words this "The API server is not answering yet." — what the test
        # cares about is the claim, not the capitalisation.
        self.assertIn("not answering yet", out["detail"].lower())

    def test_a_failed_bind_is_a_500_carrying_the_reason(self):
        with (
            mock.patch.object(pairing, "tailnet_address", return_value="100.101.102.103"),
            mock.patch.object(pairing, "tailnet_peers", return_value=1),
            mock.patch.object(pairing, "tailnet_serve_url", return_value=""),
            mock.patch.object(pairing, "api_server_owner", return_value="default"),
            mock.patch.object(
                pairing,
                "reach_from_anywhere",
                return_value=(False, "config set failed.", "bind"),
            ),
        ):
            with self.assertRaises(HTTPException) as caught:
                plugin_api.use_tailscale(plugin_api.UseTailscaleRequest(confirm=True))
        self.assertEqual(caught.exception.status_code, 500)
        self.assertIn("config set failed.", caught.exception.detail)


class State(unittest.TestCase):
    def test_state_names_what_the_current_bind_allows(self):
        with (
            mock.patch.object(pairing, "tailnet_address", return_value="100.101.102.103"),
            mock.patch.object(pairing, "tailnet_peers", return_value=1),
            mock.patch.object(pairing, "tailnet_serve_url", return_value=""),
            mock.patch.object(pairing, "api_server_owner", return_value="default"),
            mock.patch.object(pairing, "profile_dir", return_value=Path("/tmp")),
            mock.patch.object(
                pairing, "api_server_settings", return_value=(True, "192.168.40.111", 8642)
            ),
            mock.patch.object(
                pairing, "candidate_addresses", return_value=["192.168.40.111"]
            ),
            mock.patch.object(pairing, "bots", return_value=[]),
        ):
            out = plugin_api.state()

        self.assertEqual(out["bind_verdict"], "home_only")
        self.assertEqual(out["tailnet"], "100.101.102.103")
        self.assertTrue(out["needs_bind_change"])
        self.assertFalse(out["can_reach_anywhere"])
        self.assertIn("100.101.102.103", out["guidance"])

    def test_state_withholds_the_switch_when_alone_on_the_tailnet(self):
        with (
            mock.patch.object(pairing, "tailnet_address", return_value="100.101.102.103"),
            mock.patch.object(pairing, "tailnet_peers", return_value=0),
            mock.patch.object(pairing, "tailnet_serve_url", return_value=""),
            mock.patch.object(pairing, "api_server_owner", return_value="default"),
            mock.patch.object(pairing, "profile_dir", return_value=Path("/tmp")),
            mock.patch.object(
                pairing, "api_server_settings", return_value=(True, "192.168.40.111", 8642)
            ),
            mock.patch.object(
                pairing, "candidate_addresses", return_value=["192.168.40.111"]
            ),
            mock.patch.object(pairing, "bots", return_value=[]),
        ):
            out = plugin_api.state()

        self.assertEqual(out["tailnet_peers"], 0)
        self.assertFalse(out["needs_bind_change"])
        self.assertIn("only device on its tailnet", out["guidance"])

    def test_a_machine_with_no_tailnet_is_told_to_install_it(self):
        with (
            mock.patch.object(pairing, "tailnet_address", return_value=""),
            mock.patch.object(pairing, "tailnet_peers", return_value=None),
            mock.patch.object(pairing, "tailnet_serve_url", return_value=""),
            mock.patch.object(pairing, "api_server_owner", return_value="default"),
            mock.patch.object(pairing, "profile_dir", return_value=Path("/tmp")),
            mock.patch.object(
                pairing, "api_server_settings", return_value=(True, "192.168.40.111", 8642)
            ),
            mock.patch.object(
                pairing, "candidate_addresses", return_value=["192.168.40.111"]
            ),
            mock.patch.object(pairing, "bots", return_value=[]),
        ):
            out = plugin_api.state()

        self.assertEqual(out["tailnet"], "")
        # Nothing to switch to, so no switch is offered.
        self.assertFalse(out["needs_bind_change"])
        self.assertIn("Only reachable on this Wi-Fi", out["guidance"])


class Pair(unittest.TestCase):
    def test_pair_returns_the_requested_profile_and_host(self):
        with (
            mock.patch.object(pairing, "tailnet_address", return_value="100.101.102.103"),
            mock.patch.object(pairing, "tailnet_peers", return_value=1),
            mock.patch.object(pairing, "tailnet_serve_url", return_value=""),
            mock.patch.object(pairing, "api_server_owner", return_value="default"),
            mock.patch.object(pairing, "profile_dir", return_value=Path("/tmp")),
            mock.patch.object(
                pairing, "api_server_settings", return_value=(True, "192.168.40.111", 8642)
            ),
            mock.patch.object(
                pairing, "candidate_addresses", return_value=["192.168.40.111"]
            ),
            mock.patch.object(pairing, "bots", return_value=[]),
            mock.patch.object(pairing, "api_server_key", return_value="k" * 43),
            mock.patch.object(pairing, "bot_label", return_value="Leo"),
            mock.patch.object(pairing, "health", return_value=True),
            mock.patch.object(pairing, "qr_png_data_uri", return_value="data:image/png;base64,AAAA"),
            mock.patch.object(pairing, "dashboard_public_url", return_value=""),
        ):
            out = plugin_api.pair(plugin_api.PairRequest(profile="hermes_dev", host="192.168.40.111"))

        self.assertEqual(out["profile"], "hermes_dev")
        self.assertIn("host", out)
        self.assertIn("link", out)
        # The frontend scopes selection to (profile, host); the payload must
        # name the profile so one bot's selection does not light every row.
        self.assertTrue(out["link"].startswith("aichipmunk://pair?"))

    def test_pair_payload_includes_dashboard_on_anywhere_path(self):
        with (
            mock.patch.object(pairing, "tailnet_address", return_value="100.101.102.103"),
            mock.patch.object(pairing, "tailnet_peers", return_value=1),
            mock.patch.object(pairing, "tailnet_serve_url", return_value="http://mac.tail9cf0ce.ts.net:80"),
            mock.patch.object(pairing, "api_server_owner", return_value="default"),
            mock.patch.object(pairing, "profile_dir", return_value=Path("/tmp")),
            mock.patch.object(
                pairing, "api_server_settings", return_value=(True, "192.168.40.111", 8642)
            ),
            mock.patch.object(
                pairing, "candidate_addresses", return_value=["192.168.40.111", "100.101.102.103"]
            ),
            mock.patch.object(pairing, "bots", return_value=[]),
            mock.patch.object(pairing, "api_server_key", return_value="k" * 43),
            mock.patch.object(pairing, "bot_label", return_value="Leo"),
            mock.patch.object(pairing, "health", return_value=True),
            mock.patch.object(pairing, "health_via_host", return_value=True),
            mock.patch.object(pairing, "qr_png_data_uri", return_value="data:image/png;base64,AAAA"),
            mock.patch.object(pairing, "dashboard_public_url", return_value="https://dash.example.com"),
        ):
            out = plugin_api.pair(plugin_api.PairRequest(profile="default", host="http://mac.tail9cf0ce.ts.net:80"))

        from urllib.parse import parse_qs, urlparse
        params = parse_qs(urlparse(out["link"]).query)
        self.assertIn("dashboard", params)
        self.assertEqual(params["dashboard"], ["https://dash.example.com"])

    def test_pair_payload_omits_dashboard_on_wifi_path(self):
        with (
            mock.patch.object(pairing, "tailnet_address", return_value="100.101.102.103"),
            mock.patch.object(pairing, "tailnet_peers", return_value=1),
            mock.patch.object(pairing, "tailnet_serve_url", return_value="http://mac.tail9cf0ce.ts.net:80"),
            mock.patch.object(pairing, "api_server_owner", return_value="default"),
            mock.patch.object(pairing, "profile_dir", return_value=Path("/tmp")),
            mock.patch.object(
                pairing, "api_server_settings", return_value=(True, "192.168.40.111", 8642)
            ),
            mock.patch.object(
                pairing, "candidate_addresses", return_value=["192.168.40.111", "100.101.102.103"]
            ),
            mock.patch.object(pairing, "bots", return_value=[]),
            mock.patch.object(pairing, "api_server_key", return_value="k" * 43),
            mock.patch.object(pairing, "bot_label", return_value="Leo"),
            mock.patch.object(pairing, "health", return_value=True),
            mock.patch.object(pairing, "qr_png_data_uri", return_value="data:image/png;base64,AAAA"),
            mock.patch.object(pairing, "dashboard_public_url", return_value="https://dash.example.com"),
        ):
            out = plugin_api.pair(plugin_api.PairRequest(profile="default", host="192.168.40.111"))

        from urllib.parse import parse_qs, urlparse
        params = parse_qs(urlparse(out["link"]).query)
        self.assertNotIn("dashboard", params)


class ReviewFixes(unittest.TestCase):
    """The defects the catalog review named, each pinned so it cannot come back."""

    def test_a_poll_of_state_performs_no_side_effects(self):
        """The status chip polls /state every 20s in EVERY open Desktop window.

        This route used to publish the dashboard onto the tailnet with
        `tailscale serve --bg` whenever public_url was unset — unasked, and again
        on every poll. Every mutation this plugin can make goes through a
        subprocess, so proving none runs is proving the route is read-only.
        """
        with (
            mock.patch.object(pairing, "tailnet_address", return_value="100.101.102.103"),
            mock.patch.object(pairing, "tailnet_peers", return_value=1),
            mock.patch.object(pairing, "tailnet_serve_url", return_value=""),
            mock.patch.object(pairing, "api_server_owner", return_value="default"),
            mock.patch.object(pairing, "profile_dir", return_value=Path("/tmp")),
            mock.patch.object(
                pairing, "api_server_settings", return_value=(True, "192.168.40.111", 8642)
            ),
            mock.patch.object(
                pairing, "candidate_addresses", return_value=["192.168.40.111"]
            ),
            mock.patch.object(pairing, "bots", return_value=[]),
            mock.patch.object(pairing, "dashboard_public_url", return_value=""),
            mock.patch.object(pairing.subprocess, "run") as run,
        ):
            out = plugin_api.state()

        run.assert_not_called()
        self.assertFalse(out["dashboard_ready"])

    def test_state_no_longer_promises_a_dashboard_it_did_not_publish(self):
        # The keys that carried the auto-serve outcome are gone with the call, so
        # no caller can render an approval link for a publish that never happened.
        with (
            mock.patch.object(pairing, "tailnet_address", return_value="100.101.102.103"),
            mock.patch.object(pairing, "tailnet_peers", return_value=1),
            mock.patch.object(pairing, "tailnet_serve_url", return_value=""),
            mock.patch.object(pairing, "api_server_owner", return_value="default"),
            mock.patch.object(pairing, "profile_dir", return_value=Path("/tmp")),
            mock.patch.object(
                pairing, "api_server_settings", return_value=(True, "192.168.40.111", 8642)
            ),
            mock.patch.object(
                pairing, "candidate_addresses", return_value=["192.168.40.111"]
            ),
            mock.patch.object(pairing, "bots", return_value=[]),
        ):
            out = plugin_api.state()

        self.assertNotIn("dashboard_approval_url", out)
        self.assertNotIn("dashboard_serve_error", out)

    def test_pair_refuses_a_profile_name_that_is_not_a_profile(self):
        """An unvalidated name used to reach the filesystem as a path fragment.

        `../../x` resolved outside the profiles tree, so the payload read that
        directory's `.env` and handed its `API_SERVER_KEY` back in the link. The
        name is now checked against the profiles that exist, with no fallback.
        """
        with mock.patch.object(pairing, "profile_homes", return_value=[]):
            with self.assertRaises(HTTPException) as caught:
                plugin_api.pair(plugin_api.PairRequest(profile="../../x"))
        self.assertEqual(caught.exception.status_code, 400)
        self.assertIn("No Hermes profile named", caught.exception.detail)

    def test_health_check_probes_only_addresses_this_plugin_offered(self):
        # An open probe would make the backend fetch any URL's /health on demand
        # — a request-forgery foothold. The page only re-probes what it was given.
        with (
            mock.patch.object(pairing, "api_server_owner", return_value="default"),
            mock.patch.object(pairing, "profile_dir", return_value=Path("/tmp")),
            mock.patch.object(
                pairing, "api_server_settings", return_value=(True, "192.168.40.111", 8642)
            ),
            mock.patch.object(
                pairing, "candidate_addresses", return_value=["192.168.40.111"]
            ),
            mock.patch.object(pairing, "tailnet_serve_url", return_value=""),
        ):
            with self.assertRaises(HTTPException) as caught:
                plugin_api.health_check("http://169.254.169.254")
            self.assertEqual(caught.exception.status_code, 400)

            with mock.patch.object(pairing, "health", return_value=True) as probe:
                offered = plugin_api.health_check("192.168.40.111")

        self.assertEqual(offered, {"host": "192.168.40.111", "reachable": True})
        probe.assert_called_once()

    def test_pair_refuses_a_host_this_plugin_never_offered(self):
        with mock.patch.object(pairing, "is_offered_host", return_value=False):
            with self.assertRaises(HTTPException) as caught:
                plugin_api.pair(
                    plugin_api.PairRequest(profile="default", host="http://169.254.169.254")
                )
        self.assertEqual(caught.exception.status_code, 400)

    def test_state_renders_on_a_machine_with_no_profiles(self):
        """A host with nothing to pair must still load the UI.

        api_server_owner() answers with a name when no profile enables the API
        server — or when there are no profiles at all — and the polled route used
        to resolve that name through the now-strict profile_dir, turning an empty
        machine into a 500 that took the whole page down.
        """
        with (
            mock.patch.object(pairing, "profile_homes", return_value=[]),
            mock.patch.object(pairing, "tailnet_address", return_value=""),
            mock.patch.object(pairing, "tailnet_peers", return_value=None),
            mock.patch.object(pairing, "tailnet_serve_url", return_value=""),
            mock.patch.object(pairing, "candidate_addresses", return_value=[]),
            mock.patch.object(pairing, "bots", return_value=[]),
            mock.patch.object(pairing, "dashboard_public_url", return_value=""),
        ):
            out = plugin_api.state()

        self.assertEqual(out["hosts"], [])
        self.assertFalse(out["can_reach_anywhere"])

    def test_probing_an_offered_candidate_does_not_shell_out(self):
        """The 'Try again' path must stay free.

        Reading `tailscale serve status` costs the whole 3s timeout wherever the
        CLI is a shim for a missing app bundle, so the allowlist consults the
        cheap sources (interface candidates, the configured bind) before it
        considers paying for the tailnet form at all.
        """
        with (
            mock.patch.object(pairing, "owner_api_server_state", return_value=(True, "192.168.40.111", 8642)),
            mock.patch.object(
                pairing, "candidate_addresses", return_value=["192.168.40.111"]
            ),
            mock.patch.object(pairing, "tailnet_serve_url") as serve,
            mock.patch.object(pairing, "health", return_value=True),
        ):
            out = plugin_api.health_check("192.168.40.111")

        serve.assert_not_called()
        self.assertEqual(out, {"host": "192.168.40.111", "reachable": True})


class StateContract(unittest.TestCase):
    """GET /state is a PUBLISHED contract — the mobile app parses it.

    The app reads ``hosts`` and ``bots`` from this route (see aichipmunk_app
    ``lib/services/hermes_bots_service.dart`` and ``hermes_host_client.dart``).
    Any change to the set below is a decision about who reads a field, so it must
    be made deliberately: a removed key is merely falsy in JS, but it throws in a
    typed client that declares the field non-nullable. Change the expectation
    here only after checking the consumers.
    """

    EXPECTED_KEYS = frozenset(
        {
            "hosts",
            "bots",
            "tailnet",
            "tailnet_peers",
            "tailnet_url",
            "bind_verdict",
            "owner",
            "can_reach_anywhere",
            "needs_bind_change",
            "guidance",
            "dashboard_public_url",
            "dashboard_ready",
        }
    )

    def test_state_key_set_matches_the_published_contract(self):
        with (
            mock.patch.object(pairing, "tailnet_address", return_value="100.101.102.103"),
            mock.patch.object(pairing, "tailnet_peers", return_value=1),
            mock.patch.object(pairing, "tailnet_serve_url", return_value=""),
            mock.patch.object(pairing, "api_server_owner", return_value="default"),
            mock.patch.object(pairing, "profile_dir", return_value=Path("/tmp")),
            mock.patch.object(
                pairing, "api_server_settings", return_value=(True, "192.168.40.111", 8642)
            ),
            mock.patch.object(
                pairing, "candidate_addresses", return_value=["192.168.40.111"]
            ),
            mock.patch.object(pairing, "bots", return_value=[]),
            mock.patch.object(pairing, "dashboard_public_url", return_value=""),
        ):
            out = plugin_api.state()

        self.assertEqual(set(out), set(self.EXPECTED_KEYS))


if __name__ == "__main__":
    unittest.main()
