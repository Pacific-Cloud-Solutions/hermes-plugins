# tls-posture test suite

Verification for `plugins/pcs-security-tls-posture`. These are the harnesses the plugin's
claims rest on, and they live here so the claims can be re-run rather than taken on trust.

```bash
bash tests/run_all.sh
```

Exit code is non-zero if anything fails. `PYTHON=/path/to/python3` selects the interpreter
(default `python3`).

## What runs

| harness | asserts | needs |
| --- | --- | --- |
| `tls_posture_checks.py` | the checks fire where they should and stay silent where they should not, on a synthetic tree it builds itself | `cryptography` |
| `tls_posture_adversarial.py` | the same checks against **openssl-generated** certificates and hostile config input (CRLF, UTF-8 BOM, latin-1 junk, unbalanced braces, 200-level nesting, a 5 MB config) | — |
| `tls_posture_correlation.py` | config↔certificate correlation: that the certificate a server *actually serves* is the one evaluated, and that a clean host stays clean | — |

These are plain scripts, not pytest: the suite has to run on a stock `python3` with no test
framework installed. Each prints per-assertion `ok`/`FAIL` lines and exits non-zero.

`cryptography` is a **test-only** dependency. The plugin imports none of it at runtime — it
parses certificates with the standard library — and that separation is the point.

## Fixtures

`fixtures/certs/` holds **public certificates only**. Private keys, CSRs and scratch trees
are git-ignored and never committed: a private key in a repository is a private key in a
repository, whatever it was generated for, and the admission scanner has a critical pattern
for exactly that.

`fixtures/make_certs.sh` regenerates every fixture with **openssl**, not with `cryptography`.
That matters: a fixture produced by the same library the code under test uses proves less
than one produced by an independent implementation. `run_all.sh` refreshes the fixtures on
each run when openssl is available, so validity windows stay anchored to today; the
committed certificates are the fallback for machines without openssl.

Validity windows are relative to now, deliberately. A committed "expires in 30 days"
certificate is a test that passes this month and fails later. Only the two fixtures that
must be *permanently* expired (`exp3.crt`, 2020–2021) or *permanently* not-yet-valid
(`fut.crt`, 2030–2031) carry fixed dates.

### Fixture names are surprising, and deliberate

`ec.crt` is the **self-signed** EC certificate and must fire TLS-006. `ec-ca.crt` is the
**CA-issued** EC leaf and must produce no finding. Read `ca` as "CA-issued", not
"certificate authority". An earlier self-signed EC fixture made TLS-006 fire where the
harness expected silence, and it was read as a plugin bug when the fixture was what was
wrong. `ec-root.crt` is the EC issuer used only to sign `ec-ca.crt`.

## Adding a fixture

Generate it in `make_certs.sh` rather than dropping a file into `fixtures/certs/`. A PEM
with no generator is a file nobody can reproduce, and its provenance becomes a guess.