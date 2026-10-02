"""The plugin backend's contract: what it refuses, previews, and performs.

The confirm gate is the safety-critical part. The action restarts the gateway
that owns the listening socket, so a request that arrives without an explicit
confirm must change NOTHING — asserted by proving `set_bind` was never called,
not merely by reading the response body.
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
            mock.patch.object(pairing, "set_bind", return_value=(True, "Written.")),
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
                "set_bind",
                return_value=(True, "Now listening on 100.101.102.103."),
            ) as set_bind,
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
        set_bind.assert_called_once()

    def test_a_bind_that_does_not_answer_says_so_instead_of_claiming_success(self):
        with (
            mock.patch.object(pairing, "tailnet_address", return_value="100.101.102.103"),
            mock.patch.object(pairing, "tailnet_peers", return_value=1),
            mock.patch.object(pairing, "tailnet_serve_url", return_value=""),
            mock.patch.object(pairing, "api_server_owner", return_value="default"),
            mock.patch.object(pairing, "set_bind", return_value=(True, "Written.")),
            mock.patch.object(
                pairing, "api_server_settings", return_value=(True, "100.101.102.103", 8642)
            ),
            mock.patch.object(pairing, "profile_dir", return_value=Path("/tmp")),
            mock.patch.object(pairing, "health", return_value=False),
            mock.patch("time.sleep", return_value=None),
        ):
            out = plugin_api.use_tailscale(plugin_api.UseTailscaleRequest(confirm=True))

        self.assertFalse(out["reachable"])
        self.assertIn("Not answering yet", out["detail"])

    def test_a_failed_bind_is_a_500_carrying_the_reason(self):
        with (
            mock.patch.object(pairing, "tailnet_address", return_value="100.101.102.103"),
            mock.patch.object(pairing, "tailnet_peers", return_value=1),
            mock.patch.object(pairing, "tailnet_serve_url", return_value=""),
            mock.patch.object(pairing, "api_server_owner", return_value="default"),
            mock.patch.object(pairing, "set_bind", return_value=(False, "config set failed.")),
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


if __name__ == "__main__":
    unittest.main()
