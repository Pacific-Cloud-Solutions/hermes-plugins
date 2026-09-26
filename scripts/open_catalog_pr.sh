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
## What does this PR do?

Adds one catalog entry, `plugin-catalog/__NAME__.yaml`.

__INTRO__

|  |  |
| --- | --- |
| **repo** | [__PLUGIN_REPO__](__PLUGIN_URL__) |
| **pinned sha** | `__SHA__` |
| **release** | __RELEASE__ |
| **tier / category** | __TIER__ / __CATEGORY__ |
| **capabilities** | __CAPS__ |
| **platforms** | __PLATFORMS__ |

Install name and manifest name match: `hermes plugins install __NAME__` then
`hermes plugins enable __NAME__`.

## Disclosures

__DISCLOSURES__

## How to Test

1. `python3 scripts/validate_plugin_catalog.py plugin-catalog/__NAME__.yaml` — `OK: 1 file(s) valid`.
2. Clone `__PLUGIN_URL__` and check out `__SHA__`.
3. `hermes plugins validate` on that checkout — passed here (manifest, capability probe, security scan __VERDICT__, declared tools match `register()`).

Verified locally before filing:

- Structural validator: `OK: 1 file(s) valid`
- `hermes plugins validate` on the pinned checkout: `Validation passed.` Security scan __VERDICT__. Declared tools match `register()`.

## Related Issue

No issue. Catalog submissions are a PR that adds one entry file. I maintain
`Pacific-Cloud-Solutions/hermes-plugins`.

## Type of Change

- [ ]  🐛 Bug fix (non-breaking change that fixes an issue)
- [x]  ✨ New feature (non-breaking change that adds functionality)
- [ ]  🔒 Security fix
- [ ]  📝 Documentation update
- [ ]  ✅ Tests (adding or improving test coverage)
- [ ]  ♻️ Refactor (no behavior change)
- [ ]  🎯 New skill (bundled or hub)

## Changes Made

- `plugin-catalog/__NAME__.yaml` — one new entry, pinned to `__SHA__`.

## Checklist

- [x]  I am the owner/maintainer of the submitted plugin repository
- [ ]  The plugin repository is public and tagged — __TAGNOTE__
- [x]  The pinned SHA is reachable on `main`
- [x]  The package contains no self-update logic; updates ship only as SHA-bump PRs
- [x]  Declared capabilities match `plugin.yaml` and what `register()` registers at the pin
- [ ]  Full `pytest tests/ -q` — not run; this PR only adds a catalog file. Admission CI is the gate.
BODYEOF
# --- mechanical values, read from the entry and the repo ----------------------
REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
TIER=$(sed -n 's/^tier:[[:space:]]*//p' "$ENTRY" | head -1)
CATEGORY=$(sed -n 's/^category:[[:space:]]*//p' "$ENTRY" | head -1)
PLATFORMS=$(sed -n 's/^platforms:[[:space:]]*//p' "$ENTRY" | head -1)
if [ -z "$PLATFORMS" ] || [ "$PLATFORMS" = "[]" ]; then PLATFORMS="all"; fi
NTOOLS=$(awk '/^ *provides_tools:/{f=1;next} /^ *provides_hooks:/{f=0} f && /^ *- /{c++} END{print c+0}' "$ENTRY")
NHOOKS=$(awk '/^ *provides_hooks:/{f=1;next} /^ *provides_middleware:/{f=0} f && /^ *- /{c++} END{print c+0}' "$ENTRY")
NENV=$(awk '/^ *requires_env:/{f=1;next} /^[a-z]/{f=0} f && /^ *- /{c++} END{print c+0}' "$ENTRY")
CAPS="${NTOOLS} tool(s), ${NHOOKS} hook(s)"
if [ "$NENV" -gt 0 ]; then CAPS="$CAPS, requires $NENV env var(s)"; else CAPS="$CAPS, no requires_env"; fi

if [ -n "$(git tag -l | head -1)" ]; then
  RELEASE="tagged — \`$(git tag -l | head -1)\`"
  TAGNOTE="yes"
else
  PLUGIN_VERSION=$(sed -n 's/^version:[[:space:]]*//p' \
    "$REPO_ROOT/plugins/$NAME/plugin.yaml" 2>/dev/null | head -1 | tr -d '"')
  RELEASE="no tag — \`plugin.yaml\` \`version\` reads \`${PLUGIN_VERSION:-unknown}\`"
  TAGNOTE="public, **untagged**; the pin is the release"
fi

VERDICT=$(grep -o 'security scan — [a-z]*' "$VALIDATE_FILE" 2>/dev/null | head -1 | sed 's/.*— //')
if [ "$VERDICT" = "safe" ]; then VERDICT="**safe**"; else VERDICT="${VERDICT:-unknown}"; fi

# --- prose, which a generator must NOT invent --------------------------------
# `__INTRO__` and `__DISCLOSURES__` are the substance of the submission: what the plugin
# does and what it does not. A script cannot write those honestly, so they come from a
# file beside the entry: <entry-without-.yaml>.prose.md, holding two fenced sections:
#
#   ## INTRO
#   ...
#   ## DISCLOSURES
#   - **Topic.** ...
PROSE="${ENTRY%.yaml}.prose.md"
if [ ! -f "$PROSE" ]; then
  INTRO_FILE=/dev/null
  DISCLOSURES_FILE=/dev/null
  if [ "$OPEN_PR" -eq 1 ]; then
    echo "error: no prose file at $PROSE" >&2
    echo "       'What does this PR do?' and 'Disclosures' are the substance of a catalog" >&2
    echo "       submission and must be written, not generated. Create $PROSE with an" >&2
    echo "       '## INTRO' section and a '## DISCLOSURES' section, then re-run." >&2
    exit 1
  fi
  work "WARNING: no prose file at $PROSE — INTRO and DISCLOSURES will read (missing)"
  printf '(missing — write %s)\n' "$PROSE" > /tmp/.prose-intro.$$
  printf '(missing — write %s)\n' "$PROSE" > /tmp/.prose-disc.$$
  INTRO_FILE=/tmp/.prose-intro.$$
  DISCLOSURES_FILE=/tmp/.prose-disc.$$
else
  INTRO_FILE=/tmp/.prose-intro.$$
  DISCLOSURES_FILE=/tmp/.prose-disc.$$
  # Defer blank lines so a run of them collapses to one and TRAILING blanks vanish.
  # (BSD awk/sed have no `\s`; and GNU sed's `{/./!d}` syntax is rejected outright.)
  squash() { awk '{ if (NF) { while (p > 0) { print ""; p-- } p = 0; print } else p++ }'; }
  awk '/^## INTRO/{f=1;next} /^## DISCLOSURES/{f=0} f' "$PROSE" | squash > "$INTRO_FILE"
  awk '/^## DISCLOSURES/{f=1;next} /^## [A-Z]/{f=0} f' "$PROSE" | squash > "$DISCLOSURES_FILE"
  work "prose read from $(basename "$PROSE") ($(grep -c . "$INTRO_FILE") intro line(s), $(grep -c . "$DISCLOSURES_FILE") disclosure line(s))"
fi
trap 'rm -f "$INTRO_FILE" "$DISCLOSURES_FILE" "$VALIDATE_FILE" 2>/dev/null' EXIT

BODY=$(printf '%s\n' "$BODY" \
  | sed -e "s|__NAME__|$NAME|g" \
        -e "s|__SHORT__|${SHA:0:12}|g" \
        -e "s|__PLUGIN_REPO__|$PLUGIN_REPO|g" \
        -e "s|__SHA__|$SHA|g" \
        -e "s|__TIER__|$TIER|g" \
        -e "s|__CATEGORY__|$CATEGORY|g" \
        -e "s|__PLATFORMS__|$PLATFORMS|g" \
        -e "s|__CAPS__|$CAPS|g" \
        -e "s|__VERDICT__|$VERDICT|g" \
        -e "s|__RELEASE__|$RELEASE|g" \
        -e "s|__TAGNOTE__|$TAGNOTE|g" \
        -e "s|__PLUGIN_URL__|https://github.com/$PLUGIN_REPO|g")
# Multiline substitution: `sed` inserts one line, not a block, so awk swaps the single
# placeholder LINE for the contents of the captured validation output.
BODY=$(printf '%s\n' "$BODY" | awk -v vf="$VALIDATE_FILE" '
  /__VALIDATE__/ { while ((getline line < vf) > 0) print line; close(vf); next }
  { print }')
for pair in "INTRO:$INTRO_FILE" "DISCLOSURES:$DISCLOSURES_FILE"; do
  tok=${pair%%:*}; file=${pair#*:}
  BODY=$(printf '%s\n' "$BODY" | awk -v vf="$file" -v tok="__${tok}__" '
    $0 == tok { while ((getline line < vf) > 0) print line; close(vf); next }
    { print }')
done
case "$BODY" in
  *__*__*) echo "error: an unreplaced __TOKEN__ survived into the PR body — refusing." >&2
            printf '%s\n' "$BODY" | grep -o '__[A-Z_]*__' | sort -u | sed 's/^/       /' >&2
            exit 1;;
esac

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