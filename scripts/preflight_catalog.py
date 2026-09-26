#!/usr/bin/env python
"""Preflight an admission bundle before opening a catalog PR.

Run this with Hermes's interpreter, the Hermes install on PYTHONPATH, and a CLEAN
working tree whose HEAD is the commit the entry pins:

    PYTHONPATH="$HOME/.hermes/hermes-agent" \\
      "$HOME/.hermes/hermes-agent/venv/bin/python" scripts/preflight_catalog.py entry.yaml

It checks the three copies of the same facts that drift apart in practice:

  the ENTRY   what NousResearch reviews and installs
  the PACK    what a pack install resolves
  the PLUGIN  what `doctor` / `validate` actually see on disk

Every check states the evidence it used. A failure is a go/no-go: exit 1, do not open
the PR. Nothing here writes anything, and nothing here is authoritative about security —
it verifies that the *claims* are consistent, not that the plugin is good.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
EXPECTED_REPO = "https://github.com/Pacific-Cloud-Solutions/hermes-plugins"
PACK_FILE = REPO_ROOT / "pcs-security-guard.yaml"
ENTRY_KEYS = {
    "name", "repo", "sha", "subdir", "description", "maintainer", "tier",
    "category", "version", "image", "readme", "platforms", "capabilities",
}
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
NAME_RE = re.compile(r"^[a-z0-9_-]{1,64}$")

_failures: list[str] = []
_checks = 0


def check(ok: bool, label: str, detail: str = "") -> bool:
    """Record one assertion. Never raises — the report is the point."""
    global _checks
    _checks += 1
    mark = "ok  " if ok else "FAIL"
    print(f"  [{mark}] {label}" + (f"\n         {detail}" if detail else ""))
    if not ok:
        _failures.append(label)
    return ok


def section(title: str) -> None:
    print(f"\n== {title}")


def run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def load_yaml(path: Path):
    import yaml  # noqa: PLC0415
    return yaml.safe_load(path.read_text())


def reachable_on_origin(sha: str) -> bool:
    """A pin nobody else can fetch is not a pin."""
    out = run(["git", "branch", "-r", "--contains", sha], cwd=REPO_ROOT)
    return out.returncode == 0 and "origin/" in out.stdout


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("entry", help="generated catalog entry YAML")
    ap.add_argument("--hermes", default="hermes", help="hermes binary")
    ap.add_argument("--skip-network", action="store_true",
                    help="skip the image reachability check (offline review)")
    args = ap.parse_args()

    entry_path = Path(args.entry).resolve()
    if not entry_path.is_file():
        print(f"error: no such entry: {entry_path}", file=sys.stderr)
        return 2

    try:
        from hermes_cli.plugin_catalog import (  # noqa: PLC0415
            CATALOG_CATEGORIES, CATALOG_TIERS, entry_from_mapping,
        )
    except Exception as exc:  # noqa: BLE001
        print(f"error: the catalog loader is not importable ({exc}).\n"
              f"       Run with PYTHONPATH=<hermes-agent>, or the checks below would be\n"
              f"       guesses against a mirror of the schema instead of the real one.",
              file=sys.stderr)
        return 2

    raw = load_yaml(entry_path)
    if not isinstance(raw, dict):
        print(f"error: {entry_path} is not a mapping", file=sys.stderr)
        return 2

    name = raw.get("name", "<unnamed>")

    # ---------------------------------------------------------------- the entry
    section(f"entry — {entry_path.name}")

    got_keys = set(raw)
    check(got_keys == ENTRY_KEYS, "key set is exactly the schema",
          f"extra={sorted(got_keys - ENTRY_KEYS) or 'none'} "
          f"missing={sorted(ENTRY_KEYS - got_keys) or 'none'} (prose in the file is "
          f"comment-only, as the generator emits it)")

    check(bool(NAME_RE.match(str(name))), "name matches [a-z0-9_-]{1,64}", f"name={name}")

    sha = str(raw.get("sha", ""))
    check(bool(SHA_RE.match(sha)), "sha is a full 40-char hex", f"sha={sha}")
    if SHA_RE.match(sha):
        check(reachable_on_origin(sha), "sha is pushed and reachable from origin",
              f"git branch -r --contains {sha[:12]}")
        # `plugins validate` reads the WORKING COPY, but the entry's claims describe the
        # PINNED commit. Those are the same thing only when HEAD is the pin.
        head = run(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT).stdout.strip()
        check(head == sha, "working HEAD == the pinned sha",
              f"HEAD={head[:12]}… pin={sha[:12]}… — a validation report from a different "
              f"commit describes code nobody installs")
        dirty = run(["git", "status", "--porcelain"], cwd=REPO_ROOT).stdout.strip()
        if dirty:
            n = len(dirty.splitlines())
            print(f"  [note] working tree has {n} uncommitted change(s) — fine while "
                  f"developing; the PR script refuses to open on a dirty tree:\n"
                  + "\n".join(f"         {l}" for l in dirty.splitlines()[:5]))

    check(raw.get("repo") == EXPECTED_REPO, "repo is this repo", f"repo={raw.get('repo')}")

    category_ok = raw.get("category") in CATALOG_CATEGORIES
    check(category_ok, "category is one the loader accepts",
          f"category={raw.get('category')!r}; "
          + ("there is no `security` category — `tools` is the closest fit"
             if not category_ok else "accepted"))
    check(raw.get("tier") in CATALOG_TIERS, "tier is one the loader accepts",
          f"tier={raw.get('tier')!r}")

    entry = entry_from_mapping(raw, str(entry_path))
    check(entry is not None, "the REAL loader accepts the entry",
          "" if entry is not None
          else "entry_from_mapping() returned None — see the loader's own warning above")

    subdir = str(raw.get("subdir", ""))
    plugin_dir = REPO_ROOT / subdir
    check(plugin_dir.is_dir(), "subdir exists in the working tree", str(plugin_dir))

    manifest = {}
    if plugin_dir.is_dir():
        mf = plugin_dir / "plugin.yaml"
        if check(mf.is_file(), "plugin.yaml exists", str(mf)):
            manifest = load_yaml(mf) or {}

    if manifest:
        check(manifest.get("name") == name, "entry name == plugin.yaml name",
              f"entry={name!r} manifest={manifest.get('name')!r} (must match exactly)")
        check(str(manifest.get("version")) == str(raw.get("version")),
              "entry version == plugin.yaml version",
              f"entry={raw.get('version')!r} manifest={manifest.get('version')!r}")

        declared = {
            "provides_tools": manifest.get("provides_tools") or [],
            "provides_hooks": manifest.get("provides_hooks") or [],
            "provides_middleware": manifest.get("provides_middleware") or [],
        }
        caps = raw.get("capabilities") or {}
        for key, want in declared.items():
            got = caps.get(key) or []
            check(got == want, f"entry capabilities.{key} == manifest",
                  f"entry={got!r} manifest={want!r} "
                  f"(undeclared capability creep is treated as a security issue upstream)")

    image = raw.get("image")
    if image:
        hosted = str(image).startswith("https://") and "github" in str(image)
        check(hosted, "image is https on a GitHub host",
              "a non-GitHub URL is dropped by the loader with a warning, not an error")
        if str(raw.get("sha")) in str(image):
            print("         note: image URL is pinned to the entry sha — correct")
        else:
            check(False, "image URL is pinned to the entry's sha",
                  f"image={image}\n         an unpinned URL can drift from the entry")
        if not args.skip_network and hosted:
            try:
                with urllib.request.urlopen(str(image), timeout=25) as r:
                    body = r.read()
                check(r.status == 200, "image is reachable", f"HTTP {r.status}, {len(body)} bytes")
            except Exception as exc:  # noqa: BLE001
                check(False, "image is reachable", f"{type(exc).__name__}: {exc}")

    # ----------------------------------------------------------------- the pack
    section("pack")
    if PACK_FILE.is_file():
        pack = load_yaml(PACK_FILE) or {}
        plugins = pack.get("plugins") or []
        print(f"  {PACK_FILE.name}: name={pack.get('name')!r}, {len(plugins)} pinned plugin(s)")
        for item in plugins:
            item_sha = str(item.get("ref", ""))
            item_sub = str(item.get("subdir", ""))
            if not check(bool(SHA_RE.match(item_sha)), f"pin is a full 40-char SHA — {item_sub}",
                         f"ref={item_sha}"):
                continue
            check(reachable_on_origin(item_sha),
                  f"pin is pushed — {item_sub}", f"ref={item_sha[:12]}")
            have = run(["git", "cat-file", "-e", f"{item_sha}:{item_sub}"], cwd=REPO_ROOT)
            check(have.returncode == 0, f"subdir exists at that pin — {item_sub}",
                  f"git cat-file -e {item_sha[:12]}:{item_sub}")
            # The invariant that keeps drifting: a pack install must resolve to the SAME
            # plugin code as the entry. A pin left behind by a later plugin change installs
            # older code than the catalog advertises, and nothing else in this repo notices.
            if have.returncode == 0:
                same = run(["git", "diff", "--quiet", f"{item_sha}:{item_sub}",
                            f"HEAD:{item_sub}"], cwd=REPO_ROOT)
                check(same.returncode == 0,
                      f"pin resolves to the SAME code as HEAD — {item_sub}",
                      f"pin={item_sha[:12]} vs HEAD — a plugin change landed after this pin,"
                      f" so a pack install gets older code than the catalog entry pins."
                      f" Re-pin in the same commit as the plugin change.")
        in_pack = any(str(i.get("subdir", "")).endswith(name) for i in plugins)
        if in_pack:
            print(f"  this plugin is in the pack — a pack install runs the scanner per plugin,"
                  f" so it must scan `safe` (checked below)")
        else:
            print(f"  note: {name} is NOT in the pack. Only correct if it scans dangerous"
                  f" or is deliberately excluded — the pack file records the reason.")
    else:
        check(False, "pack file exists", str(PACK_FILE))

    # --------------------------------------------------------------- the plugin
    section("plugin gates")
    check(str(REPO_ROOT) in str(plugin_dir), "plugin dir is inside the repo",
          str(plugin_dir))

    # A bundled contract is a copy, and copies drift. A plugin that carries `_contract/`
    # must carry core's EXACT bytes: the bundle includes the prompt-section text frozen
    # into every session prompt and the redaction patterns, so a hand-edit there changes
    # host-level behaviour without touching core at all.
    vendor = REPO_ROOT / "scripts" / "vendor_contract.py"
    if vendor.is_file():
        out = run([sys.executable, str(vendor), "--check"])
        blob = (out.stdout + out.stderr).strip()
        tail = "\n         ".join(blob.splitlines()[-3:])
        check(out.returncode == 0, "bundled contract matches core exactly (no drift)", tail)
    else:
        print(f"  [note] {vendor} is absent — cannot verify bundled-copy drift")
    if plugin_dir.is_dir():
        for sub, label in (("doctor", "runtime contract"), ("validate", "admission gate")):
            out = run([args.hermes, "plugins", sub, str(plugin_dir)])
            blob = (out.stdout + out.stderr).strip()
            tail = "\n         ".join(blob.splitlines()[-3:]) or "(no output)"
            check(out.returncode == 0, f"hermes plugins {sub} — {label}", tail)
            if sub == "validate":
                for line in blob.splitlines():
                    if "security scan" in line:
                        print(f"         {line.strip()}")
                        if "safe" not in line:
                            print("         ^ a non-safe verdict BLOCKS a pack install "
                                  "(--force does not override a dangerous verdict)")
    else:
        check(False, "plugin dir exists", str(plugin_dir))

    # ------------------------------------------------------------------ verdict
    print()
    if _failures:
        print(f"NOT READY — {len(_failures)} of {_checks} checks failed:")
        for f in _failures:
            print(f"  - {f}")
        print("\nDo not open the PR until these are resolved.")
        return 1
    print(f"READY — {_checks} checks passed. The entry, the pack and the plugin agree.")
    print("This says the claims are consistent, not that the plugin is correct: run it.")
    return 0


if __name__ == "__main__":
    sys.exit(main())