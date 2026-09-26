"""Harness for pcs-security-tls-posture.

Builds a synthetic filesystem tree of REAL certificates (generated with
`cryptography`, not fixtures copied from somewhere), runs the checks against it,
and asserts the findings that should AND should not appear.

Findings are keyed by (check_id, source), not check_id alone: several checks fire
on several certificates, and a dict keyed by check_id keeps only the last one —
which silently hides duplicates and makes "does it fire HERE?" unanswerable.

Run:  <venv>/python tls_posture_test.py
"""
from __future__ import annotations

import datetime as dt
import importlib.util
import shutil
import sys
from pathlib import Path

# Paths are derived from this file, never hardcoded: the suite has to run from whatever
# directory someone cloned the repo into. `.build/` is scratch output, rewritten each run.
HERE = Path(__file__).resolve().parent
REPO = HERE.parent / "plugins"
BUILD = HERE / ".build"

# Load the plugin package under a stable name so `from .bootstrap import load`
# resolves. bootstrap.py finds pcs-security-core by directory name.
spec = importlib.util.spec_from_file_location(
    "tls_posture_pkg", REPO / "pcs-security-tls-posture" / "__init__.py",
    submodule_search_locations=[str(REPO / "pcs-security-tls-posture")],
)
pkg = importlib.util.module_from_spec(spec)
sys.modules["tls_posture_pkg"] = pkg
spec.loader.exec_module(pkg)

from tls_posture_pkg import checks  # noqa: E402

core = checks.core()

OUT = BUILD / "tls-fixture"
PASS, FAIL = [], []


def check(label, condition, detail=""):
    (PASS if condition else FAIL).append(label)
    mark = "ok  " if condition else "FAIL"
    print(f"  {mark} {label}" + (f"  -- {detail}" if detail and not condition else ""))


def make_cert(path, *, days_from_now, rsa_bits=2048, name="test.example",
              self_signed=True, hash_algo=None):
    """Write a certificate with a controlled validity window and issuer name."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.x509.oid import NameOID

    now = dt.datetime.now(dt.timezone.utc)
    key = (ec.generate_private_key(ec.SECP256R1()) if rsa_bits == "ec"
           else rsa.generate_private_key(public_exponent=65537, key_size=rsa_bits))

    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    issuer = subject if self_signed else x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "Test Root CA")])
    algo = {"sha1": hashes.SHA1(), "md5": hashes.MD5()}.get(hash_algo, hashes.SHA256())

    # Anchor the window to the END date so an already-expired certificate still has
    # a coherent (past) validity period rather than an inverted one.
    not_after = now + dt.timedelta(days=days_from_now)
    not_before = not_after - dt.timedelta(days=365)

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .sign(key, algo)
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return path


def build_tree():
    if OUT.exists():
        shutil.rmtree(OUT)
    c = OUT / "etc/ssl/certs"
    make_cert(c / "good.pem", days_from_now=365, name="good.example", self_signed=False)
    make_cert(c / "strong4096.pem", days_from_now=365, rsa_bits=4096,
              name="strong.example", self_signed=False)
    make_cert(c / "ecc.pem", days_from_now=365, rsa_bits="ec",
              name="ecc.example", self_signed=False)
    make_cert(c / "expiring.pem", days_from_now=10, name="expiring.example", self_signed=False)
    make_cert(c / "soon.pem", days_from_now=3, name="soon.example", self_signed=False)
    make_cert(c / "expired.pem", days_from_now=-5, name="expired.example", self_signed=False)
    make_cert(c / "weak1024.pem", days_from_now=365, rsa_bits=1024,
              name="weak.example", self_signed=False)
    make_cert(c / "internal.pem", days_from_now=365, name="internal.example")  # self-signed

    # Mid-path glob coverage: `etc/letsencrypt/live/*/cert.pem` has a `*` in the
    # middle, which parent-relative globbing silently failed to expand.
    le = OUT / "etc/letsencrypt/live/example.com"
    make_cert(le / "cert.pem", days_from_now=5, name="example.com", self_signed=False)

    nginx = OUT / "etc/nginx"
    nginx.mkdir(parents=True, exist_ok=True)
    (nginx / "nginx.conf").write_text(
        "server {\n"
        "    listen 443 ssl;\n"
        "    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;\n"
        "    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384:RC4-SHA:HIGH:!aNULL:!MD5;\n"
        "}\n", encoding="utf-8")

    apache = OUT / "etc/apache2/sites-enabled"
    apache.mkdir(parents=True, exist_ok=True)
    (apache / "default-ssl.conf").write_text(
        "<VirtualHost *:443>\n"
        "    SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1\n"
        "    SSLCipherSuite HIGH:!aNULL:!MD5:!3DES\n"
        "</VirtualHost>\n", encoding="utf-8")

    hardened = OUT / "etc/nginx/conf.d"
    hardened.mkdir(parents=True, exist_ok=True)
    (hardened / "hardened.conf").write_text(
        "server {\n"
        "    listen 443 ssl;\n"
        "    ssl_protocols TLSv1.2 TLSv1.3;\n"
        "    ssl_ciphers HIGH:!aNULL:!MD5:!RC4:!3DES;\n"
        "}\n", encoding="utf-8")
    return OUT


print("building fixture tree...")
root = build_tree()
audit = checks.run_all(str(root), include_info=True, expiry_days=30)

hits = {(f.check_id, f.evidence[0].source): f for f in audit.findings if f.evidence}


def fired(check_id, fragment) -> bool:
    return any(cid == check_id and fragment in src for cid, src in hits)


def sev(check_id, fragment) -> str:
    for (cid, src), f in hits.items():
        if cid == check_id and fragment in src:
            return f.severity.value
    return "(no finding)"


def finding(check_id, fragment):
    for (cid, src), f in hits.items():
        if cid == check_id and fragment in src:
            return f
    return None


print("\n-- certificate validity --")
check("TLS-001 fires on the expired certificate", fired("TLS-001", "expired.pem"))
check("TLS-001 does NOT fire on any non-expired certificate",
      not any(cid == "TLS-001" and "expired.pem" not in src for cid, src in hits),
      str([src for cid, src in hits if cid == "TLS-001"]))
check("TLS-002 fires on the 10-day certificate", fired("TLS-002", "expiring.pem"))
check("TLS-002 fires on the 3-day certificate", fired("TLS-002", "soon.pem"))
check("TLS-002 escalates to HIGH inside 7 days", sev("TLS-002", "soon.pem") == "high",
      sev("TLS-002", "soon.pem"))
check("TLS-002 is MEDIUM at 10 days", sev("TLS-002", "expiring.pem") == "medium",
      sev("TLS-002", "expiring.pem"))
check("TLS-002 does NOT fire on the 365-day certificate", not fired("TLS-002", "good.pem"))
check("a mid-path glob is expanded (`etc/letsencrypt/live/*/cert.pem`)",
      fired("TLS-002", "letsencrypt"), str([src for _, src in hits if "letsencrypt" in src]))

print("\n-- key strength --")
check("TLS-004 fires on the 1024-bit certificate", fired("TLS-004", "weak1024.pem"))
check("TLS-004 at 1024 bits is HIGH, not CRITICAL",
      sev("TLS-004", "weak1024.pem") == "high", sev("TLS-004", "weak1024.pem"))
check("TLS-004 does NOT fire on RSA 2048", not fired("TLS-004", "good.pem"))
check("TLS-004 does NOT fire on RSA 4096", not fired("TLS-004", "strong4096.pem"))
check("TLS-004 does NOT fire on a P-256 EC key", not fired("TLS-004", "ecc.pem"))

print("\n-- self-signed --")
check("TLS-006 fires on the self-signed certificate", fired("TLS-006", "internal.pem"))
check("TLS-006 does NOT fire on a CA-issued certificate", not fired("TLS-006", "good.pem"))

print("\n-- a clean certificate produces nothing --")
clean = [src for _, src in hits if "good.pem" in src]
check("the CA-issued, in-date, 2048-bit certificate produces no finding",
      not clean, str(clean))

print("\n-- config: what is ENABLED vs what is DISABLED --")
check("TLS-010 fires on the nginx host permitting TLSv1", fired("TLS-010", "nginx.conf"))
nginx010 = finding("TLS-010", "nginx.conf")
check("TLS-010 names TLS 1.0 and TLS 1.1",
      nginx010 is not None and "TLS 1.0" in nginx010.title and "TLS 1.1" in nginx010.title,
      nginx010.title if nginx010 else "(missing)")
check("TLS-010 is HIGH when a version worse than TLS 1.1 is enabled",
      sev("TLS-010", "nginx.conf") == "high", sev("TLS-010", "nginx.conf"))

# The bug the harness caught: `all -SSLv3 -TLSv1 -TLSv1.1` DISABLES them.
check("TLS-010 does NOT fire on the Apache config (`all -SSLv3 -TLSv1 -TLSv1.1`)",
      not fired("TLS-010", "default-ssl.conf"),
      str([src for cid, src in hits if cid == "TLS-010"]))
check("TLS-010 does NOT fire on the hardened nginx drop-in (`TLSv1.2 TLSv1.3`)",
      not fired("TLS-010", "hardened.conf"))

print("\n-- weak ciphers: OFFERED vs EXCLUDED --")
check("TLS-011 fires on the nginx host offering RC4-SHA", fired("TLS-011", "nginx.conf"))
check("TLS-011 does NOT fire on `HIGH:!aNULL:!MD5:!RC4:!3DES`",
      not fired("TLS-011", "hardened.conf"),
      str([src for cid, src in hits if cid == "TLS-011"]))
check("TLS-011 does NOT fire on the Apache all-exclusion suite",
      not fired("TLS-011", "default-ssl.conf"))
nginx011 = finding("TLS-011", "nginx.conf")
check("TLS-011 counts only the ONE offered weak suite, not the exclusions",
      nginx011 is not None and "1 weak suite" in nginx011.assertion,
      nginx011.assertion if nginx011 else "(missing)")
check("TLS-011 is HIGH for RC4 — severity uses a substring test on the full suite name",
      sev("TLS-011", "nginx.conf") == "high", sev("TLS-011", "nginx.conf"))

print("\n-- coverage honesty --")
check("checks_run is non-empty", bool(audit.checks_run))
check("checks that ran with input are reported as run (TLS-003, TLS-005)",
      "TLS-003" in audit.checks_run and "TLS-005" in audit.checks_run,
      str(audit.checks_run))
check("every skipped check carries a non-empty reason",
      all(reason for _, reason in audit.checks_skipped))
check("limitations are recorded",
      any("does not connect" in lim for lim in audit.limitations))
check("inputs_read lists what was actually read",
      any("nginx.conf" in i for i in audit.inputs_read), str(audit.inputs_read))

print("\n-- verdict never claims safety --")
report = core.Report(
    tool="t", target=str(root), findings=tuple(audit.findings),
    coverage=core.Coverage(tuple(audit.checks_run), tuple(audit.checks_skipped),
                           tuple(audit.inputs_read), tuple(audit.limitations)),
)
check("verdict carries the not-secure qualifier",
      "not a statement that the target is secure" in report.verdict(), report.verdict())
check("grade is ACTION_REQUIRED given HIGH/CRITICAL findings",
      report.grade.value == "action_required", report.grade.value)
check("no grade value is the word 'secure'",
      "secure" not in report.grade.value and "safe" not in report.grade.value)

print("\n-- absent is not safe --")
empty = BUILD / "tls-empty"
if empty.exists():
    shutil.rmtree(empty)
empty.mkdir(parents=True)
e = checks.run_all(str(empty), include_info=True)
check("an empty root produces no findings", not e.findings)
check("an empty root records skips, not a pass", bool(e.checks_skipped))
ereport = core.Report(tool="t", target=str(empty), findings=(),
                      coverage=core.Coverage(tuple(e.checks_run),
                                             tuple(e.checks_skipped), (), ()))
check("an empty root grades INCONCLUSIVE, never NO_FINDINGS",
      ereport.grade.value == "inconclusive", ereport.grade.value)

print("\n-- taint --")
sample = next(iter(hits.values()))
check("evidence is quarantined UNTRUSTED",
      sample.evidence[0].observed.provenance.value == "untrusted",
      sample.evidence[0].observed.provenance.value)
check("evidence carries source and locator",
      bool(sample.evidence[0].source and sample.evidence[0].locator))
check("every finding has at least one evidence item",
      all(f.evidence for f in audit.findings))

print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
if FAIL:
    print("FAILURES:")
    for n in FAIL:
        print(f"  - {n}")
sys.exit(1 if FAIL else 0)