#!/bin/bash
# Run the whole tls-posture test suite. Exit non-zero if anything fails.
#
#   bash tests/run_all.sh            # build the fixtures, then run every harness
#   bash tests/run_all.sh --certs-only
#
# These are plain scripts, not pytest: no test framework is needed. Each harness prints its own
# pass/fail lines and exits non-zero on failure, so this file only has to aggregate exit codes.
#
# ONE dependency is required, and it is not optional: `cryptography`, a full X.509 parser. The
# plugin imports it when it can and, when it cannot, reports TLS-004 (key size) and TLS-005
# (signature algorithm) as SKIPPED rather than guessing — correct behaviour, and the reason the
# correlation harness's "a clean host stays clean" assertion can never hold without it: a host
# with checks that could not run grades `inconclusive`, by design, never `no_findings`. Running
# the suite under a python without the parser therefore produced a failure that looked like a
# plugin bug and was an interpreter choice. So: find an interpreter that has the parser, name it,
# and refuse to run otherwise. Failing loudly beats a green-looking run that proves less.
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

pick_python() {
    for cand in "${PYTHON:-}" python3 \
                "$HERE/../.venv/bin/python" "$HERE/../venv/bin/python" \
                "$HOME/.hermes/hermes-agent/venv/bin/python"; do
        [ -n "$cand" ] || continue
        command -v "$cand" >/dev/null 2>&1 || continue
        if "$cand" -c 'import cryptography' >/dev/null 2>&1; then
            printf '%s\n' "$cand"
            return 0
        fi
    done
    return 1
}

if ! PY="$(pick_python)"; then
    echo "run_all.sh: no interpreter with a full X.509 parser (cryptography) was found." >&2
    echo "            Tried: \$PYTHON, python3, ./.venv, ./venv, ~/.hermes/hermes-agent/venv" >&2
    echo "            Set PYTHON=<path>, or: pip install cryptography" >&2
    echo "            Not running: without the parser TLS-004/TLS-005 are reported as skipped," >&2
    echo "            which is correct and would read as a plugin failure." >&2
    exit 1
fi
echo "== python: $PY"
echo "   $("$PY" -c 'import cryptography; print("cryptography", cryptography.__version__)')"

# Fixtures are build output, written under tests/.build (gitignored). They used to be generated
# into the tracked fixtures/certs directory, which rewrote ten committed certificates on every
# run — dirtying the tree, and making `scripts/open_catalog_pr.sh` refuse to run until they were
# restored. Regenerating relative to today is still right; writing it into tracked files was not.
if command -v openssl >/dev/null 2>&1; then
    echo "== building certificate fixtures (openssl) into tests/.build/certs"
    if bash "$HERE/fixtures/make_certs.sh"; then
        echo "   ok, built against today's date"
    else
        echo "   WARNING: fixture build failed; using whatever is already in tests/.build/certs" >&2
    fi
else
    echo "== no openssl; using the existing tests/.build/certs" >&2
fi

if [ "${1:-}" = "--certs-only" ]; then
    exit 0
fi

FAILED=""

for t in tls_posture_checks tls_posture_adversarial tls_posture_correlation; do
    printf '\n===== %s =====\n' "$t"
    "$PY" "$HERE/$t.py"
    rc=$?
    if [ "$rc" -ne 0 ]; then
        FAILED="$FAILED $t"
    fi
done

printf '\n===== summary =====\n'
if [ -n "$FAILED" ]; then
    printf 'FAILED:%s\n' "$FAILED"
    exit 1
fi
echo "all tls-posture harnesses passed"
