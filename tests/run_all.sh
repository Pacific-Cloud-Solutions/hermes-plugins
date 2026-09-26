#!/bin/bash
# Run the whole tls-posture test suite. Exit non-zero if anything fails.
#
#   bash tests/run_all.sh            # regenerate fixtures if openssl is present, then run
#   bash tests/run_all.sh --certs-only
#
# These are plain scripts, not pytest: the suite has to run on a stock python3 with no
# test framework installed. Each harness prints its own pass/fail lines and exits
# non-zero on failure, so this file only has to aggregate exit codes.
#
# `cryptography` is needed by tls_posture_checks.py alone, which builds its own tree of
# synthetic certificates with controlled validity windows. It is a TEST dependency and
# is not imported by the plugin at runtime. If it is missing, that one harness fails
# loudly rather than being skipped silently.
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"
PY="${PYTHON:-python3}"

command -v "$PY" >/dev/null 2>&1 || { echo "run_all.sh: no python3 on PATH" >&2; exit 1; }

if command -v openssl >/dev/null 2>&1; then
    echo "== refreshing certificate fixtures (openssl) =="
    bash "$HERE/fixtures/make_certs.sh" >/dev/null 2>&1 &&
        echo "   ok, fixtures regenerated against today's date" ||
        echo "   WARNING: fixture regeneration failed; using the committed certificates"
else
    echo "== no openssl; using the committed certificate fixtures =="
fi

if [ "${1:-}" = "--certs-only" ]; then
    exit 0
fi

FAILED=""
TOTAL_PASS=0

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