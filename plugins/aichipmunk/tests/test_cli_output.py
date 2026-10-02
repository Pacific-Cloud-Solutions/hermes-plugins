"""Headless CLI output contract.

The bug this pins: the terminal path rendered the QR inside a bare
``except Exception: pass`` and never printed the link at all. On a VPS with no
``qrcode`` in the runtime venv — the machine that has no desktop app to fall
back to — the command produced a host, a key hint, and NO way to pair.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import os
import sys
import types
import unittest
from pathlib import Path
from unittest import mock

_ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("aichipmunk_plugin", _ROOT / "__init__.py")
assert _spec and _spec.loader
plugin = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(plugin)

_LINK = "aichipmunk://pair?v=1&host=192.168.40.111%3A8642&profile=default&key=SECRET"


def _payload(**over) -> dict:
    base = {
        "label": "Leo",
        "profile": "default",
        "host": "http://192.168.40.111:8642",
        "key_hint": "\u2026A9R0",
        "reachable": True,
        "link": _LINK,
    }
    base.update(over)
    return base


class ActiveProfile(unittest.TestCase):
    """Resolved without hermes_cli helpers — they do not exist on every release.

    ``hermes_cli.profiles.current_profile_name`` raised ImportError on 0.21.4,
    which makes the whole plugin unimportable and the command absent.
    """

    def _resolve(self, env: dict) -> str:
        with mock.patch.dict(os.environ, env, clear=True):
            return plugin._active_profile()

    def test_a_profile_home_names_the_profile(self):
        self.assertEqual(self._resolve({"HERMES_HOME": "/root/.hermes/profiles/leo"}), "leo")

    def test_the_root_home_is_the_default_profile(self):
        self.assertEqual(self._resolve({"HERMES_HOME": "/root/.hermes"}), "default")

    def test_the_env_var_is_a_fallback(self):
        self.assertEqual(self._resolve({"HERMES_PROFILE": "leo"}), "leo")

    def test_nothing_set_defaults_rather_than_failing(self):
        self.assertEqual(self._resolve({}), "default")

    def test_the_module_does_not_import_hermes_cli_internals(self):
        # The actual bug guard. The plugin must not depend on hermes_cli's
        # internals — they move between releases, and an ImportError here makes
        # the whole plugin unimportable, so the command silently does not exist.
        source = (_ROOT / "__init__.py").read_text()
        self.assertNotIn("from hermes_cli", source)
        self.assertNotIn("import hermes_cli", source)


class HeadlessLink(unittest.TestCase):
    """A host with no QR renderer must still print the pairing link."""

    def _run(self, payload, *, qrcode_available: bool) -> str:
        args = types.SimpleNamespace(profile="default", host=None, json=False, show_link=False)
        fake_pairing = types.SimpleNamespace(pairing_payload=lambda *a, **k: payload)
        blocked = {} if qrcode_available else {"qrcode": None}
        buf = io.StringIO()
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(plugin, "_load_pairing", return_value=fake_pairing))
            stack.enter_context(mock.patch.dict(sys.modules, blocked))
            stack.enter_context(contextlib.redirect_stdout(buf))
            rc = plugin._aichipmunk_command(args)
        self.assertEqual(rc, 0)
        return buf.getvalue()

    def test_the_link_prints_even_when_no_qr_renderer_is_installed(self):
        out = self._run(_payload(), qrcode_available=False)
        self.assertIn(_LINK, out, "a headless host would have nothing to pair with")
        self.assertIn("No QR renderer installed", out)

    def test_the_link_prints_when_a_qr_does_render(self):
        out = self._run(_payload(), qrcode_available=True)
        self.assertIn(_LINK, out)
        self.assertNotIn("No QR renderer installed", out)

    def test_a_missing_address_says_how_to_fix_it_instead_of_printing_a_stub_link(self):
        out = self._run(_payload(link="", host=""), qrcode_available=False)
        self.assertNotIn("aichipmunk://pair", out)
        self.assertIn("--host", out, "the fix has to be named, not implied")

    def test_an_unreachable_address_still_hands_over_the_link(self):
        # Ranking an unreachable host is a trap, but staying silent is worse:
        # the user is told, and still gets a link they can try.
        out = self._run(_payload(reachable=False), qrcode_available=True)
        self.assertIn("did not answer", out)
        self.assertIn(_LINK, out)

    def test_the_json_path_never_carries_the_link_unless_asked(self):
        args = types.SimpleNamespace(profile="default", host=None, json=True, show_link=False)
        fake_pairing = types.SimpleNamespace(pairing_payload=lambda *a, **k: _payload())
        buf = io.StringIO()
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(plugin, "_load_pairing", return_value=fake_pairing))
            stack.enter_context(contextlib.redirect_stdout(buf))
            plugin._aichipmunk_command(args)
        # JSON ends up in logs and transcripts; the key must not ride along.
        self.assertNotIn("SECRET", buf.getvalue())
        self.assertIn('"link_present": true', buf.getvalue())


if __name__ == "__main__":
    unittest.main()
