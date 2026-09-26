"""Copy this file VERBATIM into any plugin that depends on pcs-security-core.

Why a shim instead of a plain import
------------------------------------
The loader imports a directory plugin as ``hermes_plugins.<slug>``
(``hermes_cli/plugins_loader.py::_load_directory_module``). Two problems make a
hardcoded import wrong:

1. **The name is profile-scoped.** `_directory_module_name` hands the bare
   ``hermes_plugins.pcs_security_core`` to the first scope that claims it, and gives
   every OTHER scope ``hermes_plugins.pcs_security_core__home_<digest>`` — the digest
   being a hash of a private scope key. Under multiplex, a dependent plugin in
   the second profile would import... nothing.
2. **It is an internal namespace.** `hermes_plugins` is an implementation detail
   of the loader, not a documented contract. A suite that hardcodes it breaks
   silently on an upstream refactor.

So this shim resolves by *filesystem*, which is the layout the install model
actually guarantees, and falls back to the loader namespace only as a shortcut.

The contract is BUNDLED with this plugin (``_contract/``) as well as obtainable
from the shared ``pcs-security-core`` plugin. The bundle is what makes a
standalone install work: a catalog entry installs exactly one plugin, so it
cannot depend on a sibling the catalog has no entry for. When the bundle is
present — always, in a correctly packaged plugin — the failure mode this shim
originally guarded against ("a security tool silently running without the taint
model") is structurally impossible rather than merely detected. The raise below
now means only one thing: the plugin was packaged wrong.
"""
from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

#: The contract version this shim understands. Bump with pcs-security-core's API_VERSION.
REQUIRED_API = 1


def _candidate_dirs():
    """Where the contract can legitimately live, in preference order.

    The shared ``pcs-security-core`` plugin comes FIRST, so a suite/pack install keeps
    one contract instance and core's host-level registrations stay authoritative. The
    bundled copy is LAST and is always present, which is what makes this plugin
    installable on its own: a catalog entry installs exactly one plugin, so it cannot
    depend on a sibling the catalog has no entry for.
    """
    here = Path(__file__).resolve()
    # In-repo / suite install: plugins/<dependent>/bootstrap.py -> plugins/pcs-security-core
    yield here.parent.parent / "pcs-security-core"
    # Installed alongside its siblings
    home = os.environ.get("HERMES_HOME")
    if home:
        yield Path(home) / "plugins" / "pcs-security-core"
    # Bundled inside this plugin — the standalone path. Always present.
    yield here.parent / "_contract"


def _already_loaded():
    """Prefer the loader's own instance — avoids executing the package twice."""
    for name, mod in list(sys.modules.items()):
        if name.split("__home_")[0] == "hermes_plugins.pcs_security_core":
            if getattr(mod, "API_VERSION", None) == REQUIRED_API:
                return mod
    return None


def load():
    """Return the pcs-security-core module, or raise with an actionable message."""
    mod = _already_loaded()
    if mod is not None:
        return mod

    tried: list[str] = []
    for directory in _candidate_dirs():
        tried.append(str(directory))
        init = directory / "__init__.py"
        if not init.is_file():
            continue
        spec = importlib.util.spec_from_file_location(
            "pcs_pcs_security_core_standalone", init,
            submodule_search_locations=[str(directory)],
        )
        if spec is None or spec.loader is None:
            continue
        module = importlib.util.module_from_spec(spec)
        sys.modules["pcs_pcs_security_core_standalone"] = module
        spec.loader.exec_module(module)
        if getattr(module, "API_VERSION", None) != REQUIRED_API:
            raise ImportError(
                f"pcs-security-core at {directory} reports API_VERSION "
                f"{getattr(module, 'API_VERSION', None)}, this plugin needs {REQUIRED_API}. "
                "Update both together."
            )
        return module

    raise ImportError(
        "the bundled contract is missing from this plugin — "
        f"`_contract/` should sit beside bootstrap.py. Looked in: {', '.join(tried)}. "
        "This is a packaging fault, not a missing dependency: reinstall the plugin, or "
        "restore the copy with scripts/vendor_contract.py."
    )