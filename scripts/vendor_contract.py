#!/usr/bin/env python
"""Vendor the shared contract into every plugin that bundles it.

Why this exists
---------------
A catalog entry installs exactly ONE plugin. So a plugin that needs a sibling at
runtime cannot be admitted to the catalog: the sibling is not there, and the tool
fails on first use. `pcs-security-tls-posture` therefore carries its own copy of the
contract in ``_contract/`` so it installs and runs standalone, while still preferring
the shared ``pcs-security-core`` plugin when that is present.

The cost of that copy is drift: the bundle and core can silently diverge, and the
whole point of the contract is that every tool returns the same shape. So this script
is the single writer of those copies, and ``--check`` is the guard that makes drift a
build failure rather than a surprise at runtime.

    python scripts/vendor_contract.py            # refresh every bundle from core
    python scripts/vendor_contract.py --check    # verify; exit 1 on any drift

Run it with Hermes's interpreter is NOT required (stdlib only), but the repo's own
runbook uses ``$PY`` for consistency.

The four files are copied BYTE-IDENTICALLY, ``__init__.py`` included. That matters:
it carries the prompt-section text, which is frozen into every new session prompt, and
the redaction patterns. A hand-edited bundle would change the agent's host-level
behaviour without touching core — exactly the kind of silent divergence this guards.
"""

from __future__ import annotations

import argparse
import filecmp
import shutil
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PLUGINS = REPO_ROOT / "plugins"
CORE_NAME = "pcs-security-core"
BUNDLE_DIRNAME = "_contract"

#: The contract closure. `taint` -> `schema` -> `render`, plus the package entry.
CONTRACT_FILES = ("__init__.py", "taint.py", "schema.py", "render.py")


def bundled_plugins() -> list[Path]:
    """Every plugin carrying a `_contract/` directory, core itself excluded."""
    return sorted(
        p for p in PLUGINS.iterdir()
        if p.is_dir() and p.name != CORE_NAME and (p / BUNDLE_DIRNAME).is_dir()
    )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true",
                    help="verify only; exit 1 if any bundle differs from core")
    args = ap.parse_args()

    core = PLUGINS / CORE_NAME
    missing = [f for f in CONTRACT_FILES if not (core / f).is_file()]
    if missing:
        print(f"error: {CORE_NAME} is missing {', '.join(missing)} — it is the source of "
              f"truth for the contract; nothing can be vendored without it.", file=sys.stderr)
        return 2

    plugins = bundled_plugins()
    if not plugins:
        print(f"no plugin bundles the contract ({BUNDLE_DIRNAME}/); nothing to do.")
        return 0

    drifted: list[str] = []
    for plugin in plugins:
        bundle = plugin / BUNDLE_DIRNAME
        print(f"\n{plugin.name}/{BUNDLE_DIRNAME}/")
        for name in CONTRACT_FILES:
            src, dst = core / name, bundle / name
            if args.check:
                if dst.is_file() and filecmp.cmp(src, dst, shallow=False):
                    print(f"  ok      {name}")
                elif dst.is_file():
                    print(f"  DRIFT   {name} differs from {CORE_NAME}/{name}")
                    drifted.append(f"{plugin.name}/{BUNDLE_DIRNAME}/{name}")
                else:
                    print(f"  MISSING {name}")
                    drifted.append(f"{plugin.name}/{BUNDLE_DIRNAME}/{name} (absent)")
            else:
                shutil.copyfile(src, dst)
                print(f"  copied  {name}")

    if args.check:
        print()
        if drifted:
            print(f"FAIL — {len(drifted)} file(s) drifted from {CORE_NAME}:")
            for d in drifted:
                print(f"  - {d}")
            print("\nRun `python scripts/vendor_contract.py` to refresh the bundles, then "
                  "re-run the plugin's tests: a changed contract can change a finding.")
            return 1
        total = len(plugins) * len(CONTRACT_FILES)
        print(f"OK — {total} file(s) across {len(plugins)} plugin(s) match {CORE_NAME} exactly.")
        return 0

    print(f"\nDone. {len(CONTRACT_FILES)} file(s) refreshed in {len(plugins)} plugin(s).")
    print("Re-run each plugin's tests: the contract is what a finding is made of.")
    return 0


if __name__ == "__main__":
    sys.exit(main())