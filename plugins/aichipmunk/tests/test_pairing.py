"""Pairing-core contract tests.

These assert the *relationship* between the pieces (a link round-trips into the
same params; the mask never reveals the key), never a frozen snapshot of today's
addresses or QR bytes.
"""

from __future__ import annotations

import contextlib
import importlib.util
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from urllib.parse import parse_qs, urlparse

_PAIRING = Path(__file__).resolve().parents[1] / "pairing.py"
_spec = importlib.util.spec_from_file_location("aichipmunk_pairing", _PAIRING)
pairing = importlib.util.module_from_spec(_spec)
assert _spec and _spec.loader
_spec.loader.exec_module(pairing)


class BuildLink(unittest.TestCase):
    def test_link_round_trips_its_params(self):
        link = pairing.build_link(
            "http://192.168.1.5:8642", "default", "secret-key-value", "Leo"
        )
        parsed = urlparse(link)
        params = parse_qs(parsed.query)

        self.assertEqual(parsed.scheme, pairing.SCHEME)
        self.assertEqual(parsed.netloc, pairing.PAIR_ACTION)
        self.assertEqual(params["host"], ["http://192.168.1.5:8642"])
        self.assertEqual(params["profile"], ["default"])
        self.assertEqual(params["key"], ["secret-key-value"])
        self.assertEqual(params["label"], ["Leo"])
        self.assertEqual(params["v"], [str(pairing.PAIR_VERSION)])

    def test_label_is_optional(self):
        link = pairing.build_link("http://10.0.0.2:8642", "hermes_dev", "k")
        self.assertNotIn("label", parse_qs(urlparse(link).query))


class Mask(unittest.TestCase):
    def test_mask_never_reveals_the_key(self):
        key = "sk-live-abcdef1234567890"
        masked = pairing.mask(key)
        self.assertTrue(masked.endswith(key[-4:]))
        self.assertNotIn(key[:-4], masked)

    def test_short_key_reveals_nothing(self):
        self.assertEqual(pairing.mask("abc"), "…")
        self.assertEqual(pairing.mask(""), "…")


class JoinHost(unittest.TestCase):
    def test_bare_host_gets_scheme_and_port(self):
        self.assertEqual(pairing.join_host("192.168.1.5", 8642), "http://192.168.1.5:8642")

    def test_explicit_port_is_left_alone(self):
        self.assertEqual(
            pairing.join_host("http://host.local:9000", 8642), "http://host.local:9000"
        )

    def test_explicit_scheme_wins(self):
        self.assertEqual(pairing.join_host("https://bots.example.com", 443), "https://bots.example.com:443")

    def test_empty_host_stays_empty(self):
        self.assertEqual(pairing.join_host("  ", 8642), "")


class AddressClass(unittest.TestCase):
    def test_loopback_is_recognized(self):
        for host in ("http://127.0.0.1:8642", "http://localhost:8642", "http://0.0.0.0:8642"):
            self.assertTrue(pairing.is_loopback(host), host)

    def test_lan_and_tailnet_are_not_loopback(self):
        self.assertFalse(pairing.is_loopback("http://192.168.40.111:8642"))
        self.assertFalse(pairing.is_loopback("http://100.101.102.103:8642"))

    def test_tailnet_range(self):
        self.assertTrue(pairing.is_tailnet("100.64.0.1"))
        self.assertTrue(pairing.is_tailnet("100.127.255.255"))
        self.assertFalse(pairing.is_tailnet("100.128.0.1"))
        self.assertFalse(pairing.is_tailnet("192.168.1.1"))
        self.assertFalse(pairing.is_tailnet("not-an-ip"))


class Qr(unittest.TestCase):
    def test_qr_is_a_png_data_uri(self):
        uri = pairing.qr_png_data_uri(
            pairing.build_link("http://192.168.1.5:8642", "default", "k")
        )
        self.assertTrue(uri.startswith("data:image/png;base64,"))
        self.assertGreater(len(uri), 500)


class Candidates(unittest.TestCase):
    def test_no_loopback_or_apipa_is_offered(self):
        for addr in pairing.candidate_addresses():
            self.assertFalse(addr.startswith("127."), addr)
            self.assertFalse(addr.startswith("169.254."), addr)


class BindVerdict(unittest.TestCase):
    """What the CURRENT bind allows — the thing that decides who can reach it."""

    def test_a_tailnet_bind_works_anywhere(self):
        self.assertEqual(pairing.bind_verdict("100.101.102.103"), "anywhere")

    def test_a_lan_bind_is_home_only(self):
        for host in ("192.168.40.111", "10.0.0.5", "172.16.4.4", "mac-studio.local"):
            self.assertEqual(pairing.bind_verdict(host), "home_only", host)

    def test_loopback_can_never_be_reached_by_a_phone(self):
        for host in ("127.0.0.1", "localhost", "0.0.0.0"):
            self.assertEqual(pairing.bind_verdict(host), "unreachable", host)

    def test_a_public_bind_is_flagged_exposed_not_merely_public(self):
        # The point is not that it is routable, it is that anyone holding a key
        # can run tools on this machine.
        self.assertEqual(pairing.bind_verdict("203.0.113.9"), "exposed")

    def test_an_unreadable_bind_is_unknown_rather_than_a_guess(self):
        self.assertEqual(pairing.bind_verdict(""), "unknown")
        self.assertEqual(pairing.bind_verdict("   "), "unknown")


class PrivateLan(unittest.TestCase):
    def test_rfc1918_and_mdns_are_local(self):
        for host in ("10.0.0.1", "192.168.1.1", "172.16.0.1", "172.31.255.255", "box.local"):
            self.assertTrue(pairing.is_private_lan(host), host)

    def test_tailnet_and_public_are_not_local(self):
        for host in ("100.101.102.103", "8.8.8.8", "172.32.0.1", ""):
            self.assertFalse(pairing.is_private_lan(host), host)


class TailnetAddress(unittest.TestCase):
    def setUp(self):
        self._candidates = pairing.candidate_addresses

    def tearDown(self):
        pairing.candidate_addresses = self._candidates

    def test_finds_the_tailnet_address(self):
        pairing.candidate_addresses = lambda: ["192.168.40.111", "100.101.102.103"]
        self.assertEqual(pairing.tailnet_address(), "100.101.102.103")

    def test_no_tailnet_is_empty_not_an_error(self):
        pairing.candidate_addresses = lambda: ["192.168.40.111"]
        self.assertEqual(pairing.tailnet_address(), "")


class ChooseBaseUrl(unittest.TestCase):
    """The handoff must be an address that ANSWERS, not the best-ranked one."""

    def setUp(self):
        self._health = pairing.health
        self.answers: set[str] = set()
        pairing.health = lambda base_url, timeout=2.5: base_url in self.answers

    def tearDown(self):
        pairing.health = self._health

    def test_a_tailnet_address_the_server_is_not_bound_to_is_never_handed_over(self):
        # The worst handoff there is: it scans cleanly, stores a key, and then
        # every call fails. Ranking alone would choose it.
        self.answers.add("http://192.168.40.111:8642")
        base, reachable = pairing.choose_base_url(
            "192.168.40.111", 8642, ["100.101.102.103", "192.168.40.111"]
        )
        self.assertEqual(base, "http://192.168.40.111:8642")
        self.assertTrue(reachable)

    def test_the_bound_address_is_preferred_once_it_answers(self):
        self.answers.add("http://100.101.102.103:8642")
        base, reachable = pairing.choose_base_url(
            "100.101.102.103", 8642, ["192.168.40.111"]
        )
        self.assertEqual(base, "http://100.101.102.103:8642")
        self.assertTrue(reachable)

    def test_a_loopback_bind_never_leads(self):
        # 127.0.0.1 answers from the host and is still useless to a phone.
        self.answers.update({"http://127.0.0.1:8642", "http://192.168.40.111:8642"})
        base, reachable = pairing.choose_base_url(
            "127.0.0.1", 8642, ["192.168.40.111"]
        )
        self.assertEqual(base, "http://192.168.40.111:8642")
        self.assertTrue(reachable)

    def test_nothing_answering_still_returns_a_candidate_and_says_so(self):
        base, reachable = pairing.choose_base_url(
            "192.168.40.111", 8642, ["100.101.102.103"]
        )
        self.assertEqual(base, "http://192.168.40.111:8642")
        self.assertFalse(reachable, "the caller must be able to explain, not imply success")

    def test_no_candidates_is_empty_rather_than_a_fabricated_url(self):
        self.assertEqual(pairing.choose_base_url("", 8642, []), ("", False))


class NetworkButtons(unittest.TestCase):
    """Each bot row offers exactly the addresses that actually answer.

    Two separate buttons in the desktop plugin, and they are two separate
    gateways in the app: Wi-Fi needs no Tailscale at home, the tailnet name
    works anywhere. So the payload must carry BOTH, and a button must never be
    offered for an address nothing is listening on.
    """

    def _patch_bind(self, host, port=8642, candidates=("100.79.181.20", "192.168.40.111")):
        stack = contextlib.ExitStack()
        stack.enter_context(mock.patch.object(pairing, "api_server_owner", return_value="default"))
        stack.enter_context(mock.patch.object(pairing, "profile_dir", return_value=Path("/tmp/p")))
        stack.enter_context(
            mock.patch.object(pairing, "api_server_settings", return_value=(True, host, port))
        )
        stack.enter_context(
            mock.patch.object(pairing, "candidate_addresses", return_value=list(candidates))
        )
        return stack

    def test_a_lan_bind_offers_the_wifi_address(self):
        with self._patch_bind("192.168.40.111"):
            self.assertEqual(pairing.wifi_url(), "http://192.168.40.111:8642")

    def test_a_tailnet_bind_offers_no_wifi_button(self):
        # Bound to the tailnet, the LAN address answers nothing. Offering it is
        # the same trap as ranking an unreachable candidate.
        with self._patch_bind("100.79.181.20"):
            self.assertEqual(pairing.wifi_url(), "")

    def test_a_loopback_bind_offers_no_wifi_button(self):
        with self._patch_bind("127.0.0.1"):
            self.assertEqual(pairing.wifi_url(), "")

    def test_a_wildcard_bind_resolves_to_the_lan_address(self):
        with self._patch_bind("0.0.0.0"):
            self.assertEqual(pairing.wifi_url(), "http://192.168.40.111:8642")

    def test_a_wildcard_bind_with_no_lan_offers_nothing(self):
        with self._patch_bind("0.0.0.0", candidates=("100.79.181.20",)):
            self.assertEqual(pairing.wifi_url(), "")

    def test_every_bot_row_carries_both_buttons(self):
        with tempfile.TemporaryDirectory() as d:
            with self._patch_bind("192.168.40.111"), contextlib.ExitStack() as stack:
                stack.enter_context(
                    mock.patch.object(
                        pairing, "profile_homes", return_value=[("default", Path(d))]
                    )
                )
                stack.enter_context(mock.patch.object(pairing, "api_server_key", return_value="k"))
                stack.enter_context(mock.patch.object(pairing, "bot_label", return_value="Leo"))
                stack.enter_context(
                    mock.patch.object(
                        pairing, "tailnet_serve_url", return_value="http://mac.tail9cf0ce.ts.net:80"
                    )
                )
                rows = pairing.bots()

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["wifi_url"], "http://192.168.40.111:8642")
        self.assertEqual(rows[0]["anywhere_url"], "http://mac.tail9cf0ce.ts.net:80")
        # Selection is per address, so the two buttons MUST differ — equal URLs
        # would make one button's "Selected" state lock the other.
        self.assertNotEqual(rows[0]["wifi_url"], rows[0]["anywhere_url"])


class BotAvatarIdentity(unittest.TestCase):
    """The /state roster carries each bot's avatar identity from profile.yaml."""

    def _write_profile_yaml(self, directory: Path, ui_meta: dict | None) -> Path:
        profile_yaml = directory / "profile.yaml"
        data: dict = {}
        if ui_meta is not None:
            data["ui_meta"] = ui_meta
        import yaml
        profile_yaml.write_text(yaml.safe_dump(data))
        return directory

    def test_profile_with_identity_block_yields_all_four_keys(self):
        with tempfile.TemporaryDirectory() as d:
            prof = self._write_profile_yaml(
                Path(d),
                {
                    "hermes-bots": {
                        "shape": "hexagon",
                        "color": "hsl(164 68% 58%)",
                        "imageKind": "shape",
                        "image": "",
                    }
                },
            )
            identity = pairing.bot_avatar_identity(prof)
        self.assertEqual(identity["avatar_shape"], "hexagon")
        self.assertEqual(identity["avatar_color"], "hsl(164 68% 58%)")
        self.assertEqual(identity["avatar_kind"], "shape")
        self.assertEqual(identity["avatar_image"], "")

    def test_profile_without_identity_block_yields_empty_strings(self):
        with tempfile.TemporaryDirectory() as d:
            prof = self._write_profile_yaml(Path(d), None)
            identity = pairing.bot_avatar_identity(prof)
        self.assertEqual(identity["avatar_shape"], "")
        self.assertEqual(identity["avatar_color"], "")
        self.assertEqual(identity["avatar_kind"], "")
        self.assertEqual(identity["avatar_image"], "")

    def test_profile_with_photo_image_passes_through(self):
        with tempfile.TemporaryDirectory() as d:
            prof = self._write_profile_yaml(
                Path(d),
                {
                    "hermes-bots": {
                        "shape": "circle",
                        "color": "#ffcc00",
                        "imageKind": "photo",
                        "image": "data:image/png;base64,AAAA",
                    }
                },
            )
            identity = pairing.bot_avatar_identity(prof)
        self.assertEqual(identity["avatar_shape"], "circle")
        self.assertEqual(identity["avatar_color"], "#ffcc00")
        self.assertEqual(identity["avatar_kind"], "photo")
        self.assertEqual(identity["avatar_image"], "data:image/png;base64,AAAA")

    def test_bots_payload_includes_avatar_keys(self):
        with tempfile.TemporaryDirectory() as d:
            prof = self._write_profile_yaml(
                Path(d),
                {
                    "hermes-bots": {
                        "shape": "cloud",
                        "color": "hsl(200 80% 50%)",
                        "imageKind": "shape",
                    }
                },
            )
            with contextlib.ExitStack() as stack:
                stack.enter_context(
                    mock.patch.object(
                        pairing, "profile_homes", return_value=[("default", prof)]
                    )
                )
                stack.enter_context(mock.patch.object(pairing, "api_server_key", return_value="k"))
                stack.enter_context(mock.patch.object(pairing, "bot_label", return_value="Leo"))
                stack.enter_context(
                    mock.patch.object(
                        pairing, "tailnet_serve_url", return_value="http://mac.tail9cf0ce.ts.net:80"
                    )
                )
                stack.enter_context(
                    mock.patch.object(pairing, "api_server_settings", return_value=(True, "127.0.0.1", 8642))
                )
                rows = pairing.bots()

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["avatar_shape"], "cloud")
        self.assertEqual(rows[0]["avatar_color"], "hsl(200 80% 50%)")
        self.assertEqual(rows[0]["avatar_kind"], "shape")
        self.assertEqual(rows[0]["avatar_image"], "")
        # Existing keys must still be present.
        self.assertEqual(rows[0]["profile"], "default")
        self.assertEqual(rows[0]["label"], "Leo")


class TailnetPeers(unittest.TestCase):
    """``None`` (cannot tell) and ``0`` (provably alone) lead to OPPOSITE actions."""

    @staticmethod
    def _status(stdout, returncode=0):
        return mock.Mock(returncode=returncode, stdout=stdout, stderr="")

    def test_counts_the_other_devices(self):
        payload = json.dumps({"Peer": {"a": {}, "b": {}}})
        with (
            mock.patch("shutil.which", return_value="/usr/local/bin/tailscale"),
            mock.patch("subprocess.run", return_value=self._status(payload)),
        ):
            self.assertEqual(pairing.tailnet_peers(), 2)

    def test_an_empty_tailnet_is_zero_and_that_is_a_real_answer(self):
        with (
            mock.patch("shutil.which", return_value="/usr/local/bin/tailscale"),
            mock.patch("subprocess.run", return_value=self._status('{"Peer": null}')),
        ):
            self.assertEqual(pairing.tailnet_peers(), 0)

    def test_no_cli_is_unknown_not_zero(self):
        with mock.patch("shutil.which", return_value=None):
            self.assertIsNone(pairing.tailnet_peers())

    def test_unparseable_output_is_unknown_not_zero(self):
        with (
            mock.patch("shutil.which", return_value="/usr/local/bin/tailscale"),
            mock.patch("subprocess.run", return_value=self._status("not json")),
        ):
            self.assertIsNone(pairing.tailnet_peers())

    def test_a_stopped_cli_is_unknown_not_zero(self):
        # "Tailscale is stopped" proves nothing about the tailnet's membership.
        with (
            mock.patch("shutil.which", return_value="/usr/local/bin/tailscale"),
            mock.patch("subprocess.run", return_value=self._status("", returncode=1)),
        ):
            self.assertIsNone(pairing.tailnet_peers())

    def test_a_cli_that_hangs_is_unknown_not_a_hang(self):
        with (
            mock.patch("shutil.which", return_value="/usr/local/bin/tailscale"),
            mock.patch("subprocess.run", side_effect=TimeoutError),
        ):
            self.assertIsNone(pairing.tailnet_peers())


class TailnetServeUrl(unittest.TestCase):
    """Serve is what lets ONE bind serve two networks — and only OUR backend counts."""

    @staticmethod
    def _status(payload):
        return mock.Mock(returncode=0, stdout=json.dumps(payload), stderr="")

    def _with(self, payload, base_url="http://192.168.40.111:8642"):
        with (
            mock.patch("shutil.which", return_value="/usr/local/bin/tailscale"),
            mock.patch("subprocess.run", return_value=self._status(payload)),
        ):
            return pairing.tailnet_serve_url(base_url)

    def test_finds_the_name_serving_our_backend(self):
        url = self._with(
            {
                "Web": {
                    "macbook-pro.tail9cf0ce.ts.net:80": {
                        "Handlers": {"/": {"Proxy": "http://192.168.40.111:8642"}}
                    }
                }
            }
        )
        self.assertEqual(url, "http://macbook-pro.tail9cf0ce.ts.net:80")

    def test_a_non_80_port_is_carried_through(self):
        url = self._with(
            {
                "Web": {
                    "box.tail9cf0ce.ts.net:8443": {
                        "Handlers": {"/": {"Proxy": "http://192.168.40.111:8642"}}
                    }
                }
            }
        )
        self.assertEqual(url, "http://box.tail9cf0ce.ts.net:8443")

    def test_the_port_is_always_explicit_so_join_host_leaves_it_alone(self):
        # A bare name would collect the API server's port and describe a handler
        # that is not there.
        url = self._with(
            {
                "Web": {
                    "box.tail9cf0ce.ts.net:80": {
                        "Handlers": {"/": {"Proxy": "http://192.168.40.111:8642"}}
                    }
                }
            }
        )
        self.assertEqual(pairing.join_host(url, 8642), url)

    def test_a_handler_pointing_somewhere_else_is_not_this_machine(self):
        # Handing over a name that proxies to a different service would be worse
        # than handing over nothing.
        url = self._with(
            {"Web": {"box.ts.net:80": {"Handlers": {"/": {"Proxy": "http://127.0.0.1:9999"}}}}}
        )
        self.assertEqual(url, "")

    def test_no_serve_config_is_empty(self):
        self.assertEqual(self._with({}), "")
        self.assertEqual(self._with({"Web": {}}), "")

    def test_no_cli_is_empty_rather_than_a_guess(self):
        with mock.patch("shutil.which", return_value=None):
            self.assertEqual(pairing.tailnet_serve_url("http://192.168.40.111:8642"), "")

    def test_a_cli_that_fails_is_empty(self):
        with (
            mock.patch("shutil.which", return_value="/usr/local/bin/tailscale"),
            mock.patch("subprocess.run", return_value=mock.Mock(returncode=1, stdout="")),
        ):
            self.assertEqual(pairing.tailnet_serve_url("http://192.168.40.111:8642"), "")


class Guidance(unittest.TestCase):
    def test_being_alone_on_the_tailnet_outranks_the_verdict(self):
        # The switch would strand the user, so it must not be recommended even
        # though the current bind is the one that only works at home.
        text = pairing.guidance("home_only", "100.101.102.103", 0)
        self.assertIn("only device on its tailnet", text)
        self.assertNotIn("not listening on it yet", text)

    def test_a_populated_tailnet_recommends_the_switch(self):
        text = pairing.guidance("home_only", "100.101.102.103", 2)
        self.assertIn("not listening on it yet", text)

    def test_unknown_peers_do_not_block_the_advice(self):
        text = pairing.guidance("home_only", "100.101.102.103", None)
        self.assertIn("not listening on it yet", text)

    def test_no_tailnet_teaches_the_install(self):
        self.assertIn("Only reachable on this Wi-Fi", pairing.guidance("home_only", "", None))

    def test_an_exposed_bind_is_called_out(self):
        self.assertIn("public address", pairing.guidance("exposed", "", None))

    def test_a_serve_url_is_reported_as_the_answer_not_a_problem(self):
        # One name that works at home and away is the goal state; pushing a bind
        # change on an already-correct machine is its own kind of wrong.
        text = pairing.guidance("home_only", "100.101.102.103", 1, "http://box.ts.net")
        self.assertIn("http://box.ts.net", text)
        self.assertNotIn("not listening on it yet", text)


class ApiServerOwner(unittest.TestCase):
    def setUp(self):
        self._homes = pairing.profile_homes
        self._settings = pairing.api_server_settings

    def tearDown(self):
        pairing.profile_homes = self._homes
        pairing.api_server_settings = self._settings

    def test_the_profile_that_enables_the_server_owns_the_socket(self):
        pairing.profile_homes = lambda: [("default", Path("/d")), ("other", Path("/o"))]
        pairing.api_server_settings = lambda home: (str(home) == "/o", "192.168.1.1", 8642)
        self.assertEqual(pairing.api_server_owner(), "other")

    def test_falls_back_to_default_when_nothing_declares_it(self):
        pairing.profile_homes = lambda: [("default", Path("/d"))]
        pairing.api_server_settings = lambda home: (False, "127.0.0.1", 8642)
        self.assertEqual(pairing.api_server_owner(), "default")


class SetBind(unittest.TestCase):
    """The write goes through the CLI, and the restart targets the OWNER."""

    @staticmethod
    def _result(returncode=0, stdout="", stderr=""):
        return mock.Mock(returncode=returncode, stdout=stdout, stderr=stderr)

    def test_writes_the_bind_through_the_cli_then_restarts_the_owner(self):
        calls: list[list[str]] = []

        def fake_run(argv, **kwargs):
            calls.append(list(argv))
            return self._result()

        with mock.patch("subprocess.run", side_effect=fake_run):
            ok, message = pairing.set_bind("100.101.102.103", "default")

        self.assertTrue(ok, message)
        # argv[0] is the CLI belonging to THIS interpreter (an absolute path), not
        # a bare name off PATH — see _hermes_cli(). The contract under test is the
        # arguments, so assert those and only sanity-check the binary.
        self.assertTrue(calls[0][0].endswith("hermes"), calls[0])
        self.assertEqual(calls[0][1:4], ["-p", "default", "config"])
        self.assertIn("platforms.api_server.host", calls[0])
        self.assertIn("100.101.102.103", calls[0])
        # A secondary profile only bounces ITSELF inside the running host
        # gateway: same PID, bind unchanged. Name the owner.
        self.assertTrue(calls[1][0].endswith("hermes"), calls[1])
        self.assertEqual(calls[1][1:3], ["-p", "default"])
        self.assertIn("restart", calls[1])

    def test_a_failed_write_stops_before_restarting(self):
        with mock.patch(
            "subprocess.run", return_value=self._result(returncode=1, stderr="bad path")
        ):
            ok, message = pairing.set_bind("100.101.102.103", "default")
        self.assertFalse(ok)
        self.assertIn("bad path", message)

    def test_a_failed_restart_is_reported_not_hidden(self):
        with mock.patch(
            "subprocess.run",
            side_effect=[self._result(), self._result(returncode=1, stderr="no gateway")],
        ):
            ok, message = pairing.set_bind("100.101.102.103", "default")
        self.assertFalse(ok)
        self.assertIn("no gateway", message)

    def test_no_address_is_refused(self):
        ok, message = pairing.set_bind("", "default")
        self.assertFalse(ok)
        self.assertIn("No address", message)


class PairingPayloadVerdict(unittest.TestCase):
    """The payload must tell the truth about whether these bots work off-network."""

    def setUp(self):
        self._saved = {
            name: getattr(pairing, name)
            for name in (
                "profile_dir",
                "api_server_key",
                "bot_label",
                "api_server_settings",
                "candidate_addresses",
                "health",
                "qr_png_data_uri",
                "tailnet_peers",
                "api_server_owner",
                "tailnet_serve_url",
                "tailnet_address",
                "health_via_host",
            )
        }
        self.tmp = tempfile.mkdtemp()
        pairing.profile_dir = lambda profile: Path(self.tmp)
        pairing.api_server_key = lambda prof: "k" * 43
        pairing.bot_label = lambda prof: "Chipmunk"
        pairing.qr_png_data_uri = lambda link: "data:image/png;base64,AAAA"

    def tearDown(self):
        for name, value in self._saved.items():
            setattr(pairing, name, value)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _payload(self, config_host, candidates, answers, peers=1, serve_url="", tailnet_ip=None, serve_reachable=True):
        pairing.api_server_settings = lambda prof: (True, config_host, 8642)
        pairing.api_server_owner = lambda: "default"
        pairing.candidate_addresses = lambda: list(candidates)
        pairing.health = lambda base_url, timeout=2.5: base_url in answers
        pairing.tailnet_peers = lambda: peers
        pairing.tailnet_serve_url = lambda base_url="": serve_url
        if tailnet_ip is None:
            tailnet_ip = next((a for a in candidates if pairing.is_tailnet(a)), "")
        pairing.tailnet_address = lambda: tailnet_ip
        pairing.health_via_host = lambda *a, **k: serve_reachable
        return pairing.pairing_payload("default")

    def test_a_serve_url_needs_no_bind_change_at_all(self):
        # Already reachable both ways: offering a switch here would be pushing a
        # change on a machine that is already right.
        payload = self._payload(
            "192.168.40.111",
            ["192.168.40.111"],
            {"http://192.168.40.111:8642"},
            serve_url="http://box.tail9cf0ce.ts.net:80",
            tailnet_ip="100.81.171.122",
        )
        self.assertEqual(payload["tailnet_url"], "http://box.tail9cf0ce.ts.net:80")
        self.assertTrue(payload["can_reach_anywhere"])
        self.assertFalse(payload["needs_bind_change"])
        self.assertIn("http://box.tail9cf0ce.ts.net:80", payload["guidance"])
        # With an active serve handler the MagicDNS name is preferred.
        self.assertEqual(payload["host"], "http://box.tail9cf0ce.ts.net:80")
        self.assertTrue(payload["reachable"])

    def test_the_bind_is_read_from_the_owner_not_the_profile_being_paired(self):
        """A secondary profile declares no bind; read there it fell through to
        DEFAULT_HOST (127.0.0.1) and the payload called the machine unreachable
        while the tailnet listener was answering."""
        owner_dir = Path(self.tmp) / "owner"
        secondary_dir = Path(self.tmp) / "secondary"
        owner_dir.mkdir()
        secondary_dir.mkdir()
        pairing.profile_dir = (
            lambda profile: secondary_dir if profile == "secondary" else owner_dir
        )
        pairing.api_server_owner = lambda: "owner"
        pairing.api_server_settings = lambda prof: (
            (True, "100.101.102.103", 8642)
            if Path(prof) == owner_dir
            else (False, "127.0.0.1", 8642)
        )
        pairing.candidate_addresses = lambda: ["100.101.102.103", "192.168.40.111"]
        pairing.health = lambda base_url, timeout=2.5: (
            base_url == "http://100.101.102.103:8642"
        )
        pairing.tailnet_peers = lambda: 1
        pairing.tailnet_serve_url = lambda base_url="": ""

        payload = pairing.pairing_payload("secondary")

        self.assertEqual(payload["configured_host"], "100.101.102.103")
        self.assertEqual(payload["bind_verdict"], "anywhere")
        self.assertFalse(payload["needs_bind_change"])
        self.assertTrue(payload["can_reach_anywhere"])
        self.assertIn("Reachable anywhere", payload["guidance"])
        # And the code handed over is the one that answers.
        self.assertEqual(payload["host"], "http://100.101.102.103:8642")

    def test_a_lan_only_machine_with_no_tailnet_teaches_the_upgrade(self):
        payload = self._payload(
            "192.168.40.111", ["192.168.40.111"], {"http://192.168.40.111:8642"}
        )
        self.assertEqual(payload["bind_verdict"], "home_only")
        self.assertEqual(payload["tailnet"], "")
        self.assertFalse(payload["can_reach_anywhere"])
        # Nothing to switch to, so do not offer a switch.
        self.assertFalse(payload["needs_bind_change"])
        self.assertIn("Only reachable on this Wi-Fi", payload["guidance"])

    def test_a_tailnet_that_exists_but_is_unbound_offers_the_one_tap(self):
        payload = self._payload(
            "192.168.40.111",
            ["192.168.40.111", "100.101.102.103"],
            {"http://192.168.40.111:8642"},
        )
        self.assertEqual(payload["tailnet"], "100.101.102.103")
        self.assertTrue(payload["needs_bind_change"])
        self.assertFalse(payload["can_reach_anywhere"])
        self.assertIn("100.101.102.103", payload["guidance"])
        # And the code it hands over still WORKS — the bound address, not the
        # tailnet one it cannot yet use.
        self.assertEqual(payload["host"], "http://192.168.40.111:8642")
        self.assertTrue(payload["reachable"])

    def test_a_tailnet_bind_reaches_anywhere_and_offers_nothing(self):
        payload = self._payload(
            "100.101.102.103",
            ["100.101.102.103", "192.168.40.111"],
            {"http://100.101.102.103:8642"},
        )
        self.assertTrue(payload["can_reach_anywhere"])
        self.assertFalse(payload["needs_bind_change"])
        self.assertEqual(payload["host"], "http://100.101.102.103:8642")

    def test_the_link_carries_the_address_that_answers(self):
        payload = self._payload(
            "192.168.40.111",
            ["100.101.102.103", "192.168.40.111"],
            {"http://192.168.40.111:8642"},
        )
        params = parse_qs(urlparse(payload["link"]).query)
        self.assertEqual(params["host"], ["http://192.168.40.111:8642"])

    def test_being_alone_on_the_tailnet_withholds_the_switch(self):
        # The whole point: tapping here would make the bots unreachable from
        # Wi-Fi while the tailnet has nobody to hand them to.
        payload = self._payload(
            "192.168.40.111",
            ["100.101.102.103", "192.168.40.111"],
            {"http://192.168.40.111:8642"},
            peers=0,
        )
        self.assertTrue(payload["tailnet"])
        self.assertFalse(payload["needs_bind_change"])
        self.assertIn("only device on its tailnet", payload["guidance"])
        # And the working Wi-Fi link is still handed over.
        self.assertEqual(payload["host"], "http://192.168.40.111:8642")
        self.assertTrue(payload["reachable"])

    def test_a_populated_tailnet_offers_the_switch(self):
        payload = self._payload(
            "192.168.40.111",
            ["100.101.102.103", "192.168.40.111"],
            {"http://192.168.40.111:8642"},
            peers=1,
        )
        self.assertTrue(payload["needs_bind_change"])
        self.assertIn("not listening on it yet", payload["guidance"])

    def test_active_serve_handler_prefers_magicdns_name(self):
        payload = self._payload(
            "127.0.0.1",
            ["100.81.171.122"],
            set(),
            serve_url="http://atlas.tail9cf0ce.ts.net:8642",
            tailnet_ip="100.81.171.122",
        )
        self.assertEqual(payload["host"], "http://atlas.tail9cf0ce.ts.net:8642")
        self.assertTrue(payload["reachable"])

    def test_serve_status_verified_even_when_local_probe_fails(self):
        # tailscale serve status already proved the handler points at our
        # api_server; we treat that as verified even when the local probe
        # does not answer (the host may not resolve its own MagicDNS name).
        payload = self._payload(
            "127.0.0.1",
            ["100.81.171.122"],
            set(),
            serve_url="http://atlas.tail9cf0ce.ts.net:8642",
            tailnet_ip="100.81.171.122",
            serve_reachable=False,
        )
        self.assertEqual(payload["host"], "http://atlas.tail9cf0ce.ts.net:8642")
        self.assertTrue(payload["reachable"])

    def test_no_serve_handler_falls_back_to_candidates(self):
        payload = self._payload(
            "192.168.40.111",
            ["192.168.40.111"],
            {"http://192.168.40.111:8642"},
        )
        self.assertEqual(payload["host"], "http://192.168.40.111:8642")
        self.assertTrue(payload["reachable"])

    def test_serve_handler_pointing_elsewhere_is_not_preferred(self):
        # tailnet_serve_url returns "" when the handler does not point at our
        # api_server, so the payload must fall back to normal candidate selection.
        payload = self._payload(
            "192.168.40.111",
            ["192.168.40.111"],
            {"http://192.168.40.111:8642"},
            serve_url="",
        )
        self.assertEqual(payload["host"], "http://192.168.40.111:8642")


class HealthViaHost(unittest.TestCase):
    def test_sends_the_given_host_header(self):
        captured = {}

        def fake_urlopen(req, timeout=None):
            captured["host"] = req.get_header("Host")
            resp = mock.Mock()
            resp.status = 200
            resp.__enter__ = mock.Mock(return_value=resp)
            resp.__exit__ = mock.Mock(return_value=False)
            return resp

        with mock.patch("urllib.request.urlopen", fake_urlopen):
            result = pairing.health_via_host("http://100.81.171.122:8642", "atlas.tail9cf0ce.ts.net:8642")
        self.assertTrue(result)
        self.assertEqual(captured.get("host"), "atlas.tail9cf0ce.ts.net:8642")

    def test_returns_false_when_server_errors(self):
        resp = mock.Mock()
        resp.status = 500
        resp.__enter__ = mock.Mock(return_value=resp)
        resp.__exit__ = mock.Mock(return_value=False)

        with mock.patch("urllib.request.urlopen", return_value=resp):
            self.assertFalse(pairing.health_via_host("http://100.81.171.122:8642", "atlas.tail9cf0ce.ts.net:8642"))

    def test_returns_false_on_network_failure(self):
        with mock.patch("urllib.request.urlopen", side_effect=OSError("boom")):
            self.assertFalse(pairing.health_via_host("http://100.81.171.122:8642", "atlas.tail9cf0ce.ts.net:8642"))


class ReviewFixes(unittest.TestCase):
    """Behaviour the catalog review required, pinned at the pairing layer."""

    def test_profile_dir_refuses_a_name_that_is_not_a_profile(self):
        # The name comes off the wire. It must never be joined onto a path —
        # these are the shapes that used to reach another directory's .env and
        # return its API_SERVER_KEY in the pairing link.
        for bad in ("../../x", "/etc", "..", "a/b", "profiles/../.."):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError) as caught:
                    pairing.profile_dir(bad)
                self.assertIn("No Hermes profile named", str(caught.exception))

    def test_every_real_profile_still_resolves_to_its_own_home(self):
        # The guard must not cost the feature: profiles that DO exist still
        # resolve, so the refusal above is a filter and not a wall.
        names = pairing.profile_names()
        if not names:
            self.skipTest("no Hermes profiles on this machine to check")
        for name in names:
            with self.subTest(profile=name):
                self.assertTrue(pairing.profile_dir(name).is_dir())

    def test_qr_renders_when_the_optional_extra_is_present(self):
        uri = pairing.qr_png_data_uri("aichipmunk://pair?v=1&profile=default")
        self.assertTrue(uri.startswith("data:image/png;base64,"), uri[:40])

    def test_qr_degrades_to_empty_without_the_optional_extra(self):
        # `qrcode` ships only in some Hermes extras, never in core. Raising here
        # turned /pair into a 500 and left the user nothing to pair with — the CLI
        # path already guarded it, and now the HTTP path does too.
        with mock.patch.dict(sys.modules, {"qrcode": None, "qrcode.constants": None}):
            self.assertEqual(pairing.qr_png_data_uri("aichipmunk://pair?v=1"), "")

    def test_hermes_cli_prefers_the_running_interpreters_sibling(self):
        # A stray PATH entry can point at a different install than the one this
        # plugin runs inside, and the config write then lands where the running
        # gateway never reads it.
        with tempfile.TemporaryDirectory() as tmp:
            bindir = Path(tmp) / "bin"
            bindir.mkdir()
            (bindir / "hermes").write_text("#!/bin/sh\n")
            with (
                mock.patch.object(pairing.sys, "executable", str(bindir / "python")),
                mock.patch.object(
                    pairing.shutil, "which", return_value="/usr/local/bin/hermes"
                ),
            ):
                self.assertEqual(pairing._hermes_cli(), str(bindir / "hermes"))

    def test_hermes_cli_falls_back_to_path_when_there_is_no_sibling(self):
        with tempfile.TemporaryDirectory() as tmp:
            with (
                mock.patch.object(pairing.sys, "executable", str(Path(tmp) / "python")),
                mock.patch.object(
                    pairing.shutil, "which", return_value="/usr/local/bin/hermes"
                ),
            ):
                self.assertEqual(pairing._hermes_cli(), "/usr/local/bin/hermes")


if __name__ == "__main__":
    unittest.main()