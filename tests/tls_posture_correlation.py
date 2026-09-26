"""Correlation harness for TLS-007 / TLS-008 / TLS-009.

These checks did not exist before, and they are the first ones in this plugin that
read TWO sources and join them: a server configuration, and the certificate file that
configuration names. So the fixtures have to exercise the JOIN, not just either side.

Certificates come from the openssl set built by tls_posture_adversarial.py, so the
parser and the generator are still independent implementations.

Run:  <venv>/python tls_posture_correlation.py
"""
from __future__ import annotations

import importlib.util
import json
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent / "plugins"
PKG = REPO / "pcs-security-tls-posture"
CERTS = HERE / "fixtures" / "certs"
OUT = HERE / ".build" / "tls-corr" / "root"

passed = failed = 0


def check(name: str, ok: bool, detail: str = "") -> None:
    global passed, failed
    if ok:
        passed += 1
        print(f"  ok   {name}")
    else:
        failed += 1
        print(f"  FAIL {name}" + (f"  [{detail}]" if detail else ""))


# Load the plugin package under a stable name so `from .bootstrap import load`
# resolves — the module is a package, not a standalone file.
REPO = PKG.parent
spec = importlib.util.spec_from_file_location(
    "tls_corr_pkg", PKG / "__init__.py",
    submodule_search_locations=[str(PKG)],
)
pkg = importlib.util.module_from_spec(spec)
sys.modules["tls_corr_pkg"] = pkg
spec.loader.exec_module(pkg)

from tls_corr_pkg import checks  # noqa: E402
from tls_corr_pkg import tools as pkg_tools  # noqa: E402


def find(audit, check_id: str):
    return [f for f in audit.findings if f.check_id == check_id]


def build_root() -> Path:
    if OUT.parent.exists():
        shutil.rmtree(OUT.parent)
    (OUT / "etc/ssl/certs").mkdir(parents=True)
    (OUT / "etc/nginx").mkdir(parents=True)
    (OUT / "etc/apache2/sites-enabled").mkdir(parents=True)
    (OUT / "etc/letsencrypt/live/example.com").mkdir(parents=True)

    # a real chain: leaf + intermediate concatenated
    ca = (CERTS / "ca.crt").read_text()
    leaf = (CERTS / "good.crt").read_text()
    (OUT / "etc/letsencrypt/live/example.com/fullchain.pem").write_text(leaf + ca)
    # the leaf on its own — the file you must NOT point nginx at
    (OUT / "etc/letsencrypt/live/example.com/cert.pem").write_text(leaf)

    # an expired cert at a standard path, so it is in the audited globs
    shutil.copy(CERTS / "exp3.crt", OUT / "etc/ssl/certs/exp3.crt")
    # a cert outside every search path, referenced by a config
    (OUT / "etc/nginx/private").mkdir(parents=True)
    shutil.copy(CERTS / "good.crt", OUT / "etc/nginx/private/offpath.crt")

    (OUT / "etc/nginx/nginx.conf").write_text(
        "http {\n"
        '    ssl_certificate     /etc/letsencrypt/live/example.com/cert.pem;   # TLS-007\n'
        '    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;\n'
        "    ssl_protocols TLSv1.2 TLSv1.3;\n"
        "    server {\n"
        '        ssl_certificate /etc/nginx/certs/gone.pem;                    # TLS-008\n'
        "    }\n"
        "    server {\n"
        '        ssl_certificate /etc/nginx/private/offpath.crt;               # TLS-009\n'
        "    }\n"
        "    server {\n"
        '        ssl_certificate /etc/ssl/certs/exp3.crt;                      # correlation\n'
        "    }\n"
        "    server {\n"
        '        ssl_certificate relative/cert.pem;                            # unresolvable\n'
        "    }\n"
        "}\n"
    )
    # Apache, with the chain supplied separately: a single-cert SSLCertificateFile is CORRECT
    (OUT / "etc/apache2/sites-enabled/ssl.conf").write_text(
        "<IfModule mod_ssl.c>\n"
        "  SSLCertificateFile /etc/letsencrypt/live/example.com/cert.pem\n"
        "  SSLCertificateChainFile /etc/letsencrypt/live/example.com/chain.pem\n"
        "  SSLProtocol all -SSLv3 -TLSv1\n"
        "</IfModule>\n"
    )
    return OUT


root = build_root()
audit = checks.run_all(str(root))

print("\n════ A. the whole point: nginx pointed at the leaf while the chain is beside it ════")
seven = find(audit, "TLS-007")
leaf = [f for f in seven if f.severity.name == "HIGH"
        and "cert.pem" in f.assertion and "nginx.conf" in f.assertion]
check("TLS-007 fires HIGH on the leaf-only nginx reference", len(leaf) == 1,
      f"{len(leaf)} found; {[f.severity.name for f in seven]}")
if leaf:
    f = leaf[0]
    check("it cites the config file and line", "nginx.conf:2" in f.assertion, f.assertion)
    check("it names the file the server actually reads", "cert.pem" in f.assertion)
    check("it names the correct file beside it", "fullchain.pem" in f.assertion)
    check("remediation points at the sibling", "fullchain.pem" in f.remediation)

print("\n════ B. Apache with a separate chain file is NOT a false positive ════")
apache_seven = [f for f in seven if "ssl.conf" in f.assertion]
check("TLS-007 stays silent on Apache SSLCertificateFile + SSLCertificateChainFile",
      len(apache_seven) == 0, str([f.assertion for f in apache_seven]))

print("\n════ C. TLS-008 — a config naming a file that is not there ════")
eight = find(audit, "TLS-008")
check("TLS-008 fires on the missing file", any("gone.pem" in f.assertion for f in eight))
check("TLS-008 is HIGH (TLS does not work at all)", all(f.severity.name == "HIGH" for f in eight))
check("TLS-008 cites the config line",
      any("nginx.conf:6" in f.assertion for f in eight),
      str([f.assertion for f in eight]))

print("\n════ D. TLS-009 — a served certificate the audit never read ════")
nine = find(audit, "TLS-009")
check("TLS-009 fires on the off-path certificate", any("offpath.crt" in f.assertion for f in nine))
check("TLS-009 is INFO, a coverage gap not a verdict",
      all(f.severity.name == "INFO" for f in nine))
check("TLS-009 does NOT fire for a certificate inside the audited globs",
      not any("exp3.crt" in f.assertion for f in nine),
      str([f.assertion for f in nine]))

print("\n════ E. correlation — a cert finding now names the server that presents it ════")
expired = [f for f in find(audit, "TLS-001") if "exp3.crt" in f.assertion]
check("TLS-001 still fires on the expired served certificate", len(expired) == 1)
if expired:
    a = expired[0].assertion
    check("its assertion names the serving server block", "Served by" in a, a)
    check("it names the config file and line that presents it", "nginx.conf:12" in a, a)
    check("it carries the `served` tag", "served" in expired[0].tags, str(expired[0].tags))
unserved = [f for f in find(audit, "TLS-001") if "exp3.crt" not in f.assertion]
check("a certificate nobody references gets NO serving clause",
      all("Served by" not in f.assertion for f in unserved))

print("\n════ F. relative paths are recorded, never guessed ════")
check("a relative reference produces no TLS-007/008 finding",
      not any("relative/cert.pem" in f.assertion for f in seven + eight))
check("the relative reference is recorded as a limitation instead",
      any("RELATIVE" in t for t in audit.limitations),
      str(audit.limitations))
check("coverage does not claim TLS-007 was skipped entirely",
      not any(cid == "TLS-007" for cid, _ in audit.checks_skipped),
      str(audit.checks_skipped))

print("\n════ G. coverage and shape ════")
check("TLS-007 and TLS-008 are reported as RUN, not skipped",
      "TLS-007" in audit.checks_run and "TLS-008" in audit.checks_run,
      str(audit.checks_run))
check("no SKIP reason is duplicated in coverage",
      len(audit.checks_skipped) == len(set(audit.checks_skipped)))
check("every finding still cites evidence", all(f.evidence for f in audit.findings))
check("every finding still carries a file+line locator",
      all(e.source and e.locator for f in audit.findings for e in f.evidence))

print("\n════ H. a clean host stays clean ════")
CLEAN = HERE / ".build" / "tls-corr" / "clean"
if CLEAN.exists():
    shutil.rmtree(CLEAN)
(CLEAN / "etc/nginx").mkdir(parents=True)
(CLEAN / "etc/letsencrypt/live/ok").mkdir(parents=True)
ca = (CERTS / "ca.crt").read_text()
leaf = (CERTS / "good.crt").read_text()
(CLEAN / "etc/letsencrypt/live/ok/fullchain.pem").write_text(leaf + ca)
(CLEAN / "etc/letsencrypt/live/ok/cert.pem").write_text(leaf)
(CLEAN / "etc/nginx/nginx.conf").write_text(
    "http {\n"
    '    ssl_certificate     /etc/letsencrypt/live/ok/fullchain.pem;\n'
    '    ssl_certificate_key /etc/letsencrypt/live/ok/privkey.pem;\n'
    "    ssl_protocols TLSv1.2 TLSv1.3;\n"
    "    ssl_ciphers HIGH:!aNULL:!MD5;\n"
    "}\n"
)
clean = checks.run_all(str(CLEAN))
check("a correct fullchain reference produces NO TLS-007/008/009",
      not (find(clean, "TLS-007") or find(clean, "TLS-008") or find(clean, "TLS-009")),
      str([(f.check_id, f.assertion) for f in clean.findings]))
payload = json.loads(pkg_tools.tls_posture({"root": str(CLEAN)}))
check("the correct config still grades cleanly",
      payload["grade"] == "no_findings_for_these_checks", str(payload["grade"]))
check("the served certificate IS now audited, so its expiry was evaluated",
      "TLS-001" in payload["coverage"]["checks_run"],
      str(payload["coverage"]["checks_run"]))

print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)