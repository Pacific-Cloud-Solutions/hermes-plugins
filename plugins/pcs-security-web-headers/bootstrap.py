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

If pcs-security-core cannot be found, it raises with the paths it tried — a
dependent plugin must fail loudly, because a security tool that silently runs
without the taint model is exactly the failure this suite exists to prevent.
"""
from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

#: The contract version this shim understands. Bump with pcs-security-core's API_VERSION.
REQUIRED_API = 1


def _candidate_dirs():
    """Where pcs-security-core can legitimately live, in preference order."""
    # In-repo: plugins/<dependent>/bootstrap.py -> plugins/pcs-security-core
    here = Path(__file__).resolve()
    yield here.parent.parent / "pcs-security-core"
    # Installed alongside its siblings
    home = os.environ.get("HERMES_HOME")
    if home:
        yield Path(home) / "plugins" / "pcs-security-core"


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
        "pcs-security-core is required but was not found. Install it alongside this plugin "
        f"(`hermes plugins install pcs-security-core`). Looked in: {', '.join(tried)}"
    )