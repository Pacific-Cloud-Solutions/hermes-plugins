#!/usr/bin/env python3
"""Generate a hermes-agent `plugin-catalog/<name>.yaml` entry for a plugin in this repo.

The upstream catalog is the *only* thing that gets merged into hermes-agent for a plugin —
the plugin code itself stays here. Presence in that directory IS the trust signal, so the
entry has to be exactly right:

  * `sha` must be a full 40-character hex commit; branches and short SHAs are rejected by
    the loader (`hermes_cli/plugin_catalog.py::_SHA_RE`).
  * `name` must match [a-z0-9_-]{1,64} and must equal the plugin's own manifest name — that
    key is what users search, install, and (for memory providers) put in `memory.provider`.
  * `capabilities` must match what `register()` actually registers at the pinned commit.
    `hermes plugins validate <dir>` is the authority; this script only transcribes the
    manifest, so run that gate first.

Usage:
    python3 scripts/catalog_entry.py --plugin plugins/<id> --sha <40-hex> \
        [--category tools] [--maintainer Pacific-Cloud-Solutions] [--verify] > entry.yaml

`--verify` round-trips the generated YAML through the real catalog loader and fails if the
loader would reject or silently drop any field. Use it in CI and before opening the PR.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from textwrap import dedent

DEFAULT_REPO = "Pacific-Cloud-Solutions/hermes-plugins"
DEFAULT_MAINTAINER = "Pacific-Cloud-Solutions"

# Mirrors of the loader's constants. `--verify` cross-checks them against the live module so
# they cannot drift silently on the machine that generates the entry.
_NAME_RE = re.compile(r"^[a-z0-9_-]{1,64}$")
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_CATEGORIES = ("desktop", "memory", "platform", "web", "tools", "voice", "automation", "models", "general")
_TIERS = ("official", "community")


def _load_yaml():
    try:
        import yaml  # noqa: PLC0415
    except ImportError:  # pragma: no cover - environment guard
        sys.exit("error: PyYAML is required (run this with Hermes's venv python, or `pip install pyyaml`)")
    return yaml


def _canonical_constants():
    """The live loader's own constants, when hermes is importable here."""
    try:
        from hermes_cli.plugin_catalog import CATALOG_CATEGORIES, CATALOG_TIERS  # noqa: PLC0415
    except Exception:
        return None
    return tuple(CATALOG_CATEGORIES), tuple(CATALOG_TIERS)


def _env_names(raw) -> list[str]:
    """`requires_env` is a list of names or of {name, ...} mappings."""
    out = []
    for item in raw or []:
        if isinstance(item, str):
            out.append(item)
        elif isinstance(item, dict):
            name = item.get("name") or item.get("key")
            if name:
                out.append(str(name))
    return out


def build_entry(args) -> tuple[str, dict]:
    plugin_dir = Path(args.plugin)
    manifest_path = plugin_dir / "plugin.yaml"
    if not manifest_path.is_file():
        sys.exit(f"error: no plugin.yaml at {manifest_path}")

    manifest = _load_yaml().safe_load(manifest_path.read_text()) or {}
    name = str(manifest.get("name") or "").strip()
    if not _NAME_RE.match(name):
        sys.exit(f"error: manifest name {name!r} must match [a-z0-9_-]{{1,64}}")
    if args.name and args.name != name:
        sys.exit(f"error: --name {args.name!r} does not match the manifest name {name!r} (the catalog key IS the manifest name)")

    sha = args.sha.strip().lower()
    if not _SHA_RE.match(sha):
        sys.exit(f"error: --sha must be a full 40-character hex commit SHA (got {args.sha!r})")

    category = args.category
    if category not in _CATEGORIES:
        sys.exit(f"error: --category must be one of {', '.join(_CATEGORIES)} (got {category!r})")
    if args.tier not in _TIERS:
        sys.exit(f"error: --tier must be one of {', '.join(_TIERS)} (got {args.tier!r})")

    subdir = args.subdir or f"plugins/{plugin_dir.name}"
    capabilities = {
        "provides_tools": [str(x) for x in (manifest.get("provides_tools") or [])],
        "provides_hooks": [str(x) for x in (manifest.get("provides_hooks") or [])],
        # The manifest has no field for middleware, so this is the one capability that must be
        # passed in explicitly (see AGENTS.md).
        "provides_middleware": [x.strip() for x in (args.middleware or "").split(",") if x.strip()],
        "requires_env": _env_names(manifest.get("requires_env")),
    }

    fields = {
        "name": name,
        "repo": f"https://github.com/{args.repo}",
        "sha": sha,
        "subdir": subdir,
        "description": str(manifest.get("description") or "").strip(),
        "maintainer": args.maintainer,
        "tier": args.tier,
        "category": category,
        "requires_hermes": args.requires_hermes or str(manifest.get("requires_hermes") or ""),
        "docs_url": args.docs_url,
        "version": args.version or str(manifest.get("version") or ""),
        "image": args.image,
        "readme": True,
    }
    return name, {"fields": fields, "capabilities": capabilities}


def render(name: str, built: dict) -> str:
    f, caps = built["fields"], built["capabilities"]

    def line(key: str, value: str) -> str:
        return f"{key}: {value}\n" if value else ""

    out = [
        f"# {name} — catalog entry for NousResearch/hermes-agent.\n",
        "# Generated by Pacific-Cloud-Solutions/hermes-plugins:scripts/catalog_entry.py.\n",
        "# The sha is the release: bump it (and `version`) in the same PR.\n\n",
        line("name", f["name"]),
        line("repo", f["repo"]),
        line("sha", f["sha"]),
        line("subdir", f["subdir"]),
        line("description", f["description"]),
        line("maintainer", f["maintainer"]),
        line("tier", f["tier"]),
        line("category", f["category"]),
        line("requires_hermes", f["requires_hermes"]),
        line("docs_url", f["docs_url"]),
        line("version", f['version'] and f'"{f["version"]}"'),
        line("image", f["image"]),
        "readme: true\n",
        "platforms: []\n",
        "capabilities:\n",
    ]
    for key, values in caps.items():
        if values:
            out.append(f"  {key}:\n")
            out.extend(f"    - {v}\n" for v in values)
        else:
            out.append(f"  {key}: []\n")
    return "".join(out)


def verify(text: str, name: str, sha: str) -> None:
    """Round-trip through the loader that actually reads this file."""
    try:
        from hermes_cli.plugin_catalog import entry_from_mapping  # noqa: PLC0415
    except Exception as exc:
        print(f"warn: could not import the catalog loader ({exc}); skipping --verify", file=sys.stderr)
        return

    data = _load_yaml().safe_load(text)
    entry = entry_from_mapping(data, f"<generated {name}>")
    if entry is None:
        sys.exit("error: the catalog loader rejected the generated entry (see the warning above)")

    problems = []
    if entry.name != name:
        problems.append(f"name {entry.name!r} != {name!r}")
    if entry.sha != sha:
        problems.append(f"sha {entry.sha!r} was not preserved")
    if not entry.description:
        problems.append("description is empty")
    if not entry.maintainer:
        problems.append("maintainer is empty")
    if entry.version and data.get("version") != entry.version:
        problems.append(f"version {data.get('version')!r} was dropped or rewritten to {entry.version!r}")
    if entry.category != data.get("category"):
        problems.append(f"category {data.get('category')!r} was dropped")
    if entry.image and entry.image != data.get("image"):
        problems.append("image was rewritten (must be https on a GitHub host)")

    canonical = _canonical_constants()
    if canonical:
        cats, tiers = canonical
        if entry.category not in cats:
            problems.append(f"category {entry.category!r} not in the live loader's {cats}")
        if entry.tier not in tiers:
            problems.append(f"tier {entry.tier!r} not in the live loader's {tiers}")

    if problems:
        sys.exit("error: the loader accepted the entry but changed it: " + "; ".join(problems))

    print(f"ok: loader accepted {entry.name!r} (sha {entry.sha[:12]}…, category {entry.category})", file=sys.stderr)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--plugin", required=True, help="plugin directory, e.g. plugins/<id>")
    ap.add_argument("--sha", required=True, help="40-character commit SHA of the published plugin")
    ap.add_argument("--repo", default=DEFAULT_REPO, help=f"owner/repo holding the plugin (default {DEFAULT_REPO})")
    ap.add_argument("--subdir", default="", help="path to the plugin inside the repo (default plugins/<dirname>)")
    ap.add_argument("--name", default="", help="assert the catalog key (must equal the manifest name)")
    ap.add_argument("--maintainer", default=DEFAULT_MAINTAINER)
    ap.add_argument("--tier", default="community")
    ap.add_argument("--category", default="desktop")
    ap.add_argument("--version", default="", help="human label for the sha (defaults to the manifest version)")
    ap.add_argument("--requires-hermes", default="", dest="requires_hermes")
    ap.add_argument("--docs-url", default="", dest="docs_url")
    ap.add_argument("--image", default="", help="https image on a GitHub host, 2:1")
    ap.add_argument("--middleware", default="", help="comma-separated middleware names (no manifest field exists)")
    ap.add_argument("--out", default="", help="write here instead of stdout")
    ap.add_argument("--verify", action="store_true", help="round-trip the entry through the real catalog loader")
    args = ap.parse_args()

    name, built = build_entry(args)
    text = render(name, built)

    if args.verify:
        verify(text, name, built["fields"]["sha"])

    if args.out:
        Path(args.out).write_text(text)
        print(f"wrote {args.out}", file=sys.stderr)
    else:
        sys.stdout.write(text)


if __name__ == "__main__":
    main()