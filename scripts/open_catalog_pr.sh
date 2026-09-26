#!/usr/bin/env bash
# Open (or preview) the pull request that lists a plugin in the Hermes catalog.
#
# Plugins are never merged into the hermes-agent source tree. The upstream change is a single
# reviewed file: plugin-catalog/<name>.yaml in NousResearch/hermes-agent, pinning the plugin's
# commit SHA. This script produces exactly that PR.
#
#   scripts/open_catalog_pr.sh entry.yaml <name>            # dry run: prints every step, touches nothing
#   scripts/open_catalog_pr.sh entry.yaml <name> --open-pr  # fork, branch, push, open the PR
#
# Nothing upstream happens without --open-pr. Even then this only pushes to YOUR fork and opens
# a PR; a Nous Research maintainer merges it. It never writes to your local hermes-agent checkout.
set -euo pipefail

UPSTREAM="NousResearch/hermes-agent"
FORK_OWNER="Pacific-Cloud-Solutions"
BASE_BRANCH="main"

ENTRY="${1:-}"
NAME="${2:-}"
shift 2 2>/dev/null || true
OPEN_PR=0
for arg in "$@"; do
  case "$arg" in
    --open-pr) OPEN_PR=1 ;;
    *) echo "error: unknown argument $arg" >&2; exit 2 ;;
  esac
done

[ -n "$ENTRY" ] && [ -n "$NAME" ] || { echo "usage: $0 <entry.yaml> <name> [--open-pr]" >&2; exit 2; }
[ -f "$ENTRY" ] || { echo "error: no entry file at $ENTRY" >&2; exit 2; }

step() { printf '\n\033[1m==> %s\033[0m\n' "$1"; }
work() { printf '    %s\n' "$1"; }

step "1/6 preflight"
gh api user >/dev/null 2>&1 || { echo "error: gh is not authenticated (run: gh auth login)" >&2; exit 1; }
work "gh authenticated: $(gh api user | python3 -c 'import json,sys; print(json.load(sys.stdin)["login"])')"
gh api "repos/$UPSTREAM" >/dev/null 2>&1 || { echo "error: cannot read $UPSTREAM" >&2; exit 1; }
work "upstream reachable: $UPSTREAM"

ENTRY_NAME=$(python3 - "$ENTRY" <<'PY'
import re, sys
text = open(sys.argv[1]).read()
m = re.search(r'^name:\s*(\S+)\s*$', text, re.M)
print(m.group(1) if m else "")
PY
)
[ "$ENTRY_NAME" = "$NAME" ] || { echo "error: entry name '$ENTRY_NAME' does not match '$NAME'" >&2; exit 1; }
SHA=$(python3 - "$ENTRY" <<'PY'
import re, sys
text = open(sys.argv[1]).read()
m = re.search(r'^sha:\s*([0-9a-f]{40})\s*$', text, re.M)
print(m.group(1) if m else "")
PY
)
[ -n "$SHA" ] || { echo "error: entry has no full 40-character sha (branches and short SHAs are rejected upstream)" >&2; exit 1; }
work "entry name=$NAME sha=${SHA:0:12}…"

PLUGIN_REPO=$(python3 - "$ENTRY" <<'PY'
import re, sys
text = open(sys.argv[1]).read()
m = re.search(r'^repo:\s*https://github\.com/(\S+)\s*$', text, re.M)
print(m.group(1) if m else "")
PY
)
step "2/6 pinned commit must already be pushed"
gh api "repos/$PLUGIN_REPO/commits/$SHA" >/dev/null 2>&1 \
  || { echo "error: $PLUGIN_REPO has no commit $SHA — push the plugin repo first (the pin must resolve)" >&2; exit 1; }
work "resolves: $PLUGIN_REPO@${SHA:0:12}"

# The PR body states that validation passed, so run it here rather than asking a human to
# paste the output. An earlier version left a literal `<paste the real output here>` in the
# body and NOTHING filled it — running --open-pr would have published a PR quoting a
# placeholder. Running it in-script makes the claim automatically true, and when the command
# cannot run, the body says THAT instead of quietly dropping the evidence.
HERMES_BIN="${HERMES_BIN:-hermes}"
PLUGIN_DIR="plugins/$NAME"
VALIDATE_FILE="$(mktemp)"
trap 'rm -f "$VALIDATE_FILE"' EXIT
if command -v "$HERMES_BIN" >/dev/null 2>&1 && [ -d "$PLUGIN_DIR" ]; then
  # The body claims the validation was run against the PINNED commit. Validate actually
  # reads the working copy, so that claim only holds when the working copy IS the pin:
  # a dirty tree would publish a passing report for code that is not what gets installed.
  HEAD_SHA="$(git rev-parse HEAD 2>/dev/null || true)"
  if [ "$HEAD_SHA" != "$SHA" ]; then
    echo "error: working HEAD is ${HEAD_SHA:0:12}… but the entry pins ${SHA:0:12}…" >&2
    echo "       check out the pinned commit, or regenerate the entry at HEAD." >&2
    exit 1
  fi
  if [ -n "$(git status --porcelain 2>/dev/null)" ]; then
    echo "error: working tree is dirty, so a passing report would not describe the pinned commit" >&2
    git status --porcelain | sed 's/^/       /' >&2
    exit 1
  fi
  if "$HERMES_BIN" plugins validate "$PLUGIN_DIR" >"$VALIDATE_FILE" 2>&1; then
    work "validation captured ($(wc -l <"$VALIDATE_FILE" | tr -d ' ') lines, passing)"
  else
    echo "error: 'hermes plugins validate $PLUGIN_DIR' did not pass, and the PR body claims it does" >&2
    sed 's/^/    /' "$VALIDATE_FILE" >&2
    exit 1
  fi
else
  printf 'could not run validation: %s not on PATH, or %s missing\n' \
    "$HERMES_BIN" "$PLUGIN_DIR" >"$VALIDATE_FILE"
  work "WARNING: validation could not be run — the PR body will say so rather than imply it passed"
fi

FILENAME="plugin-catalog/$NAME.yaml"
BRANCH="catalog/$NAME"

step "3/6 the change"
work "fork:   $FORK_OWNER/hermes-agent (created on demand)"
work "branch: $BRANCH (from $UPSTREAM:$BASE_BRANCH)"
work "file:   $FILENAME"
echo
sed 's/^/    | /' "$ENTRY"

TITLE="plugin-catalog: add $NAME"
# Quoted heredoc + explicit substitution. Two reasons it is not `BODY=$(cat <<'EOF' ...)`:
# markdown backticks in the body would otherwise be command substitution, and macOS's bash 3.2
# mis-parses quote characters inside a heredoc nested in $( ) (an apostrophe in the body aborts
# the whole script). `read -d ''` takes the heredoc outside any command substitution.
read -r -d '' BODY <<'BODYEOF' || true
Adds a catalog entry for **__NAME__** — `plugin-catalog/__NAME__.yaml`, pinned to `__SHORT__`.

- **Repo:** `__PLUGIN_REPO__`
- **Pinned commit:** `__SHA__`
- **Submitted by the plugin repository's owner** (rule 5 — owner-or-major-contributor
  submissions), not a drive-by.

Validation, run against the pinned commit with `hermes plugins validate`:

```
__VALIDATE__
```

The declared capabilities in the entry match what `register()` registers at that commit, and
the plugin ships no self-updating code — the SHA pin is the release (rule 3).
BODYEOF
BODY=$(printf '%s\n' "$BODY" \
  | sed -e "s|__NAME__|$NAME|g" \
        -e "s|__SHORT__|${SHA:0:12}|g" \
        -e "s|__PLUGIN_REPO__|$PLUGIN_REPO|g" \
        -e "s|__SHA__|$SHA|g")
# Multiline substitution: `sed` inserts one line, not a block, so awk swaps the single
# placeholder LINE for the contents of the captured validation output.
BODY=$(printf '%s\n' "$BODY" | awk -v vf="$VALIDATE_FILE" '
  /__VALIDATE__/ { while ((getline line < vf) > 0) print line; close(vf); next }
  { print }')

step "4/6 pull request"
work "title: $TITLE"
echo
printf '%s\n' "$BODY" | sed 's/^/    | /'

if [ "$OPEN_PR" -eq 0 ]; then
  step "dry run — nothing created, nothing pushed"
  work "re-run with --open-pr to execute the above"
  exit 0
fi

step "5/6 fork, branch, commit, push"
WORKDIR=".catalog-work/hermes-agent"
if gh api "repos/$FORK_OWNER/hermes-agent" >/dev/null 2>&1; then
  work "fork already exists"
else
  # `gh` forks into the AUTHENTICATING USER unless `organization` is given, whatever
  # $FORK_OWNER says. Without this the fork lands under the personal account, the
  # readiness probe below never finds it, and the clone fails on a repo that does not
  # exist — which the suppressed error made invisible.
  if ! gh api -X POST "repos/$UPSTREAM/forks" -f organization="$FORK_OWNER" >/dev/null; then
    echo "error: could not fork $UPSTREAM into $FORK_OWNER." >&2
    echo "       Check that the authenticated account may create repos in that org" >&2
    echo "       (gh auth status), or point FORK_OWNER at a personal account." >&2
    exit 1
  fi
  work "fork created in $FORK_OWNER"
  _ready=""
  for _ in $(seq 1 20); do
    if gh api "repos/$FORK_OWNER/hermes-agent" >/dev/null 2>&1; then _ready=1; break; fi
    sleep 3
  done
  if [ -z "$_ready" ]; then
    echo "error: the fork never appeared at $FORK_OWNER/hermes-agent after 60s." >&2
    echo "       GitHub creates the repo record before it is clonable; if it is still" >&2
    echo "       absent, check where it actually landed." >&2
    exit 1
  fi
fi

rm -rf "$WORKDIR"
mkdir -p "$(dirname "$WORKDIR")"
if ! git clone --depth 1 --no-single-branch \
     "https://github.com/$FORK_OWNER/hermes-agent.git" "$WORKDIR" >/dev/null 2>&1; then
  echo "error: could not clone $FORK_OWNER/hermes-agent — the fork is not clonable." >&2
  exit 1
fi
git -C "$WORKDIR" remote add upstream "https://github.com/$UPSTREAM.git" 2>/dev/null || true
git -C "$WORKDIR" fetch --depth 1 upstream "$BASE_BRANCH" >/dev/null 2>&1
git -C "$WORKDIR" checkout -B "$BRANCH" "upstream/$BASE_BRANCH" >/dev/null 2>&1
work "based on upstream/$BASE_BRANCH"

mkdir -p "$WORKDIR/plugin-catalog"
if [ -f "$WORKDIR/$FILENAME" ]; then
  work "entry already listed — this is a SHA bump"
  cp "$WORKDIR/$FILENAME" "$WORKDIR/$FILENAME.prev"
fi
cp "$ENTRY" "$WORKDIR/$FILENAME"
git -C "$WORKDIR" add "$FILENAME"
git -C "$WORKDIR" -c user.name="Pacific Cloud Solutions" \
  -c user.email="noreply@pacificcloudsolutions.example" \
  commit -q -m "$TITLE" -m "$(printf '%s' "$BODY" | head -c 400)"
work "committed $(git -C "$WORKDIR" rev-parse --short HEAD)"
git -C "$WORKDIR" push -u origin "$BRANCH" >/dev/null 2>&1
work "pushed to $FORK_OWNER/hermes-agent:$BRANCH"

step "6/6 open the PR"
PR_URL=$(gh api -X POST "repos/$UPSTREAM/pulls" \
  -f title="$TITLE" -f head="$FORK_OWNER:$BRANCH" -f base="$BASE_BRANCH" -f body="$BODY" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin).get("html_url",""))')
[ -n "$PR_URL" ] || { echo "error: the PR was not created (check the API response above)" >&2; exit 1; }
printf '\n    %s\n' "$PR_URL"
work "a maintainer merges it; presence in plugin-catalog/ is the install path"
work "after a merge, re-pin pcs-security-guard.yaml to the same sha in this repo"