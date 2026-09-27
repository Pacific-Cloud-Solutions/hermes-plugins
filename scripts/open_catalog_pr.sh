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
# Where the submission branch lives. GitHub offers "Allow edits from maintainers" only on forks
# in a PERSONAL account, so an org-owned fork means a maintainer cannot push a review chore into
# our branch: the chore turns into a salvage branch inside the upstream repo and our PR is closed
# as superseded (exactly what happened to #123278 — contributor email maps plus a description
# edit that could not be pushed). A personal fork is the lower-work choice for the MAINTAINER,
# not just for us: pre-empting every chore is still the goal, but when one is needed they can
# push three lines instead of rebuilding the PR.
#
# Attribution does not depend on this. The catalog entry's `repo:` and `maintainer:` fields carry
# the org, and admissions rule 5 is about who owns the *plugin* repo, not the fork. Override with
# FORK_OWNER=<org> only when a submission must originate from org-owned infrastructure — and then
# accept that no chore can be pushed, so every one has to be pre-empted.
FORK_OWNER="${FORK_OWNER:-kingpin44}"
BASE_BRANCH="main"

# The identity the entry commit is authored with. Upstream's contributor check reads this email
# (`.github/workflows/contributor-check.yml`), so it must be mapped — see catalog/contributors.map
# and the check in step 3.
IDENTITY_NAME="Pacific Cloud Solutions"
IDENTITY_EMAIL="noreply@pacificcloudsolutions.example"
CONTRIBUTORS_MAP="$(cd "$(dirname "$0")/.." && pwd)/catalog/contributors.map"

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

# Upstream skips these outright in the contributor check; a mapping file for one would be dead
# weight. Mirrors the `case` in .github/workflows/contributor-check.yml — do not widen it, or a
# check that upstream still fails would look satisfied here.
skipped_email() {
  case "$1" in
    *teknium*|*noreply@github.com*|*dependabot*|*github-actions*|*anthropic.com*|*cursor.com*) return 0 ;;
    *) return 1 ;;
  esac
}

upstream_has_mapping() {  # <email> → 0 when upstream main already carries the mapping file
  gh api "repos/$UPSTREAM/contents/contributors/emails/$1" >/dev/null 2>&1
}

map_login() {  # <email> → the login from catalog/contributors.map, or ""
  [ -f "$CONTRIBUTORS_MAP" ] || return 0
  awk -v e="$1" '$1 == e { print $2; exit }' "$CONTRIBUTORS_MAP"
}

owner_is_org() {  # <login> → 0 when GitHub reports an Organization, 2 when it cannot say
  local json
  json=$(gh api "users/$1" 2>/dev/null || true)
  case "$json" in
    *'"type":"Organization"'*|*'"type": "Organization"'*) return 0 ;;
    "") return 2 ;;
    *) return 1 ;;
  esac
}

step "1/6 preflight"
gh api user >/dev/null 2>&1 || { echo "error: gh is not authenticated (run: gh auth login)" >&2; exit 1; }
# Captured rather than merely printed: the fork call below must know whether $FORK_OWNER is the
# authenticated user (a personal fork) or an organization.
AUTH_LOGIN=$(gh api user | python3 -c 'import json,sys; print(json.load(sys.stdin)["login"])')
work "gh authenticated: $AUTH_LOGIN"
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
  #
  # The honest test is that the PLUGIN DIRECTORY is the same code at both commits — not that
  # HEAD equals the pin. Catalog scripts, prose and tests land after a pin without touching
  # the plugin, and demanding HEAD == pin refused every submission in that state while the
  # report would have been perfectly accurate.
  HEAD_SHA="$(git rev-parse HEAD 2>/dev/null || true)"
  if [ "$HEAD_SHA" != "$SHA" ]; then
    if git diff --quiet "$SHA:$PLUGIN_DIR" "$HEAD_SHA:$PLUGIN_DIR" 2>/dev/null; then
      work "HEAD ${HEAD_SHA:0:12}… ≠ pin ${SHA:0:12}…, but $PLUGIN_DIR is identical at both"
    else
      echo "error: working HEAD is ${HEAD_SHA:0:12}… but the entry pins ${SHA:0:12}…, and" >&2
      echo "       $PLUGIN_DIR differs between them — a report generated here would not" >&2
      echo "       describe the code the pin installs." >&2
      echo "       check out the pinned commit, or regenerate the entry at HEAD." >&2
      exit 1
    fi
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

# --- contributor email mapping: the chore that became a salvage branch ----------------
# Upstream fails a PR whose commits carry an author email with no `contributors/emails/<email>`
# mapping, and a maintainer cannot push that file into an org-owned fork's branch (see
# FORK_OWNER above). So the mapping ships with the PR instead: catalog/contributors.map seeds
# the deterministic ones, and upstream's own scripts/audit_pr_attribution.py --fix resolves
# anything else inside the scratch clone before the push. Reported here so the failure is
# visible before a branch exists.
echo
OWNER_KIND=0
owner_is_org "$FORK_OWNER" || OWNER_KIND=$?
if [ "$OWNER_KIND" -eq 0 ]; then
  work "note: $FORK_OWNER is an organization, so a maintainer cannot push a review chore into"
  work "      the PR branch — that is why the mapping below must be complete before the push."
elif [ "$OWNER_KIND" -eq 1 ]; then
  work "note: $FORK_OWNER is a personal account, so a maintainer CAN push review chores into"
  work "      the branch (\"Allow edits from maintainers\" is offered on personal forks)."
else
  work "note: could not ask GitHub whether $FORK_OWNER is an org; assuming the fork must"
  work "      satisfy the contributor check on its own (see FORK_OWNER in this script)."
fi
for email in "$IDENTITY_EMAIL"; do
  if skipped_email "$email"; then
    work "author email $email — skipped by upstream's contributor check, no mapping needed"
  elif upstream_has_mapping "$email"; then
    work "author email $email — already mapped upstream"
  elif [ -n "$(map_login "$email")" ]; then
    work "author email $email — unmapped upstream; the PR will ship contributors/emails/$email"
  else
    work "WARNING: author email $email is unmapped upstream and absent from"
    work "         catalog/contributors.map — upstream's audit_pr_attribution.py --fix will"
    work "         try to resolve it by API; if it cannot, the run stops before the push."
  fi
done

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
__PUB_BOX__  The plugin repository is public and tagged — __TAGNOTE__
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

# --- the public/tagged checklist line is DERIVED, never asserted -------------------
# The box is ticked from two checked facts, not from a human's say-so. Three ways the
# first draft lied: it hardcoded the box unchecked; it read the tag with
# `git tag -l | head -1` — the WHOLE repo's first tag, so with several plugins in one
# repo it names a different plugin's tag; and it never asked whether the tag was pushed,
# which is the only thing the reviewer the box is written for can actually see. So:
# "public" comes from the repo record, and the tag must be scoped to THIS plugin AND
# point at the pinned commit.
IS_PUBLIC=$(gh api "repos/$PLUGIN_REPO" 2>/dev/null \
  | python3 -c 'import json,sys; print(json.load(sys.stdin).get("private", True) is False)' \
  2>/dev/null || echo False)
# The remote's tag list, not `git tag -l`: a local-only tag is invisible upstream, and
# this endpoint dereferences annotated tags, so `commit.sha` is the commit the tag
# ultimately points at — the same commit the entry pins.
TAG=$(gh api "repos/$PLUGIN_REPO/tags?per_page=100" 2>/dev/null \
  | python3 -c '
import json, sys
name, sha = sys.argv[1], sys.argv[2]
try:
    tags = json.load(sys.stdin)
except Exception:
    tags = []
for t in tags:
    if t.get("name", "").startswith(name + "-v") and t.get("commit", {}).get("sha") == sha:
        print(t["name"])
        break
' "$NAME" "$SHA")
PLUGIN_VERSION=$(sed -n 's/^version:[[:space:]]*//p' \
  "$REPO_ROOT/plugins/$NAME/plugin.yaml" 2>/dev/null | head -1 | tr -d '"')
case "$TAG" in
  ""|"$NAME-v$PLUGIN_VERSION") ;;
  *) echo "warning: tag $TAG does not match plugin.yaml version $PLUGIN_VERSION at the pin." >&2
     echo "         The checklist line names the tag, so keep the two equal." >&2 ;;
esac

if [ -n "$TAG" ] && [ "$IS_PUBLIC" = "True" ]; then
  RELEASE="tagged — \`$TAG\`"
  PUB_BOX="- [x]"
  TAGNOTE="public, tagged \`$TAG\` at the pinned commit"
elif [ -n "$TAG" ]; then
  RELEASE="tagged — \`$TAG\`"
  PUB_BOX="- [ ]"
  TAGNOTE="tagged \`$TAG\`, but the repository is private — the installer clones it anonymously"
elif [ "$IS_PUBLIC" = "True" ]; then
  RELEASE="no tag — \`plugin.yaml\` \`version\` reads \`${PLUGIN_VERSION:-unknown}\`"
  PUB_BOX="- [ ]"
  TAGNOTE="public, **untagged**; the pin is the release"
else
  RELEASE="no tag — \`plugin.yaml\` \`version\` reads \`${PLUGIN_VERSION:-unknown}\`"
  PUB_BOX="- [ ]"
  TAGNOTE="**private** and untagged — the installer clones this repo anonymously"
fi

# `|| true`: grep exits 1 when the phrase is absent, and this script runs under `set -o
# pipefail` — so without it the pipeline's failure aborts the run right here. That made the
# "validation could not be run" branch above dead code: it deliberately writes a file with
# no verdict in it, and the script then died before it could say so in the body.
VERDICT=$(grep -o 'security scan — [a-z]*' "$VALIDATE_FILE" 2>/dev/null | head -1 | sed 's/.*— //' || true)
if [ "$VERDICT" = "safe" ]; then VERDICT="**safe**"; else VERDICT="${VERDICT:-unknown}"; fi

# --- prose, which a generator must NOT invent --------------------------------
# `__INTRO__` and `__DISCLOSURES__` are the substance of the submission: what the plugin
# does and what it does not. A script cannot write those honestly, so they come from a
# file holding two fenced sections:
#
#   ## INTRO
#   ...
#   ## DISCLOSURES
#   - **Topic.** ...
#
# Lookup order — first hit wins:
#   1. $PROSE_FILE            explicit override, for a one-off
#   2. catalog/<id>.prose.md  tracked in this repo; the normal case
#   3. beside the entry       where this started, and a trap: the entry usually lives in
#                             .catalog-work/, which is gitignored AND rm -rf'd by every
#                             --open-pr run — prose written there is destroyed by the next
#                             run and survives only in the PR body it produced.
PROSE=""
for candidate in "${PROSE_FILE:-}" "$REPO_ROOT/catalog/$NAME.prose.md" "${ENTRY%.yaml}.prose.md"; do
  if [ -n "$candidate" ] && [ -f "$candidate" ]; then PROSE="$candidate"; break; fi
done
if [ -z "$PROSE" ]; then
  INTRO_FILE=/dev/null
  DISCLOSURES_FILE=/dev/null
  if [ "$OPEN_PR" -eq 1 ]; then
    echo "error: no prose file found. Looked at:" >&2
    if [ -n "${PROSE_FILE:-}" ]; then
      echo "         \$PROSE_FILE  ($PROSE_FILE — set, but not a readable file)" >&2
    else
      echo "         \$PROSE_FILE  (unset)" >&2
    fi
    echo "         $REPO_ROOT/catalog/$NAME.prose.md" >&2
    echo "         ${ENTRY%.yaml}.prose.md" >&2
    echo "       'What does this PR do?' and 'Disclosures' are the substance of a catalog" >&2
    echo "       submission and must be written, not generated. Put the file at" >&2
    echo "       catalog/$NAME.prose.md with an '## INTRO' section and a" >&2
    echo "       '## DISCLOSURES' section, then re-run." >&2
    exit 1
  fi
  work "WARNING: no prose file — INTRO and DISCLOSURES will read (missing)"
  printf '(missing — write catalog/%s.prose.md)\n' "$NAME" > /tmp/.prose-intro.$$
  printf '(missing — write catalog/%s.prose.md)\n' "$NAME" > /tmp/.prose-disc.$$
  INTRO_FILE=/tmp/.prose-intro.$$
  DISCLOSURES_FILE=/tmp/.prose-disc.$$
else
  INTRO_FILE=/tmp/.prose-intro.$$
  DISCLOSURES_FILE=/tmp/.prose-disc.$$
  # Defer blank lines so a run of them collapses to one and TRAILING blanks vanish.
  # (BSD awk/sed have no `\s`; and GNU sed's `{/./!d}` syntax is rejected outright.)
  squash() { awk '{ if (NF) { while (p > 0) { print ""; p-- } p = 0; s = 1; print }
                     else if (s) p++ }'; }
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
        -e "s|__PUB_BOX__|$PUB_BOX|g" \
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
  #
  # The flag is only correct for an ORG owner: `organization=<a user login>` is an error, and
  # FORK_OWNER now defaults to a personal account precisely so a maintainer can push review
  # chores into the branch. When the API cannot say which kind it is, fall back to the one fact
  # already in hand: whether FORK_OWNER is the authenticated user.
  FORK_ORG=""
  OWNER_KIND=0
  owner_is_org "$FORK_OWNER" || OWNER_KIND=$?
  if [ "$OWNER_KIND" -eq 0 ]; then
    FORK_ORG="-f organization=$FORK_OWNER"
  elif [ "$OWNER_KIND" -eq 2 ] && [ "$FORK_OWNER" != "$AUTH_LOGIN" ]; then
    FORK_ORG="-f organization=$FORK_OWNER"
  fi
  # shellcheck disable=SC2086  # deliberate word-splitting of the optional fixed flag
  if ! gh api -X POST "repos/$UPSTREAM/forks" $FORK_ORG >/dev/null; then
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
git -C "$WORKDIR" -c user.name="$IDENTITY_NAME" \
  -c user.email="$IDENTITY_EMAIL" \
  commit -q -m "$TITLE" -m "$(printf '%s' "$BODY" | head -c 400)"
work "committed $(git -C "$WORKDIR" rev-parse --short HEAD)"

# --- the contributor mapping ships with the PR -----------------------------------------
# Run upstream's OWN checker from the branch, never a copy of its logic: it mirrors
# .github/workflows/contributor-check.yml, and a local reimplementation more permissive than
# CI is worse than no check at all. It cannot push the fix into our branch when the fork is
# org-owned, so the fix has to already be in the branch before the push.
#
# It computes its range as `git merge-base origin/main HEAD`, and this clone's origin is the
# FORK — whose main is not in our shallow history, so merge-base either fails or spans
# upstream's own commits. Point origin/main at the base we branched from, which is exactly
# what that range is supposed to mean.
git -C "$WORKDIR" update-ref refs/remotes/origin/main \
  "$(git -C "$WORKDIR" rev-parse "upstream/$BASE_BRANCH")"

# Deterministic mappings from this repo first: reviewed here, no API guesswork. Anything not
# listed is left to upstream's --fix, which resolves it against the GitHub API.
if [ -f "$CONTRIBUTORS_MAP" ]; then
  while read -r _email _login; do
    case "$_email" in ""|'#'*) continue ;; esac
    [ -n "$_login" ] || continue
    # Not `[ -f … ] && continue`: a failing test as a standalone statement exits the script
    # under `set -e`.
    if [ -f "$WORKDIR/contributors/emails/$_email" ]; then continue; fi
    printf '%s\n' "$_login" > "$WORKDIR/contributors/emails/$_email"
    work "mapped $_email → $_login (from catalog/contributors.map)"
  done < "$CONTRIBUTORS_MAP"
fi

if [ -f "$WORKDIR/scripts/audit_pr_attribution.py" ]; then
  AUDIT_RC=0
  AUDIT_OUT=$( (cd "$WORKDIR" && python3 scripts/audit_pr_attribution.py --fix) 2>&1 ) || AUDIT_RC=$?
  printf '%s\n' "$AUDIT_OUT" | sed 's/^/    | /'
  if [ "$AUDIT_RC" -ne 0 ]; then
    echo "error: upstream's contributor check would fail on this branch, and the mapping" >&2
    echo "       could not be resolved automatically (nothing has been pushed)." >&2
    echo "       Add the email and its GitHub login to catalog/contributors.map, then re-run." >&2
    exit 1
  fi
else
  echo "warning: upstream's scripts/audit_pr_attribution.py is not in the clone — the" >&2
  echo "         contributor check could not be run; the mapping in $CONTRIBUTORS_MAP" >&2
  echo "         is the only thing protecting this PR from that chore." >&2
fi

if [ -n "$(git -C "$WORKDIR" status --porcelain contributors)" ]; then
  git -C "$WORKDIR" add contributors
  git -C "$WORKDIR" -c user.name="$IDENTITY_NAME" -c user.email="$IDENTITY_EMAIL" \
    commit -q -m "chore($NAME): map contributor email(s) for this submission"
  work "committed contributor email mapping(s)"
fi

git -C "$WORKDIR" push -u origin "$BRANCH" >/dev/null 2>&1
work "pushed to $FORK_OWNER/hermes-agent:$BRANCH"

step "6/6 open the PR"
# `maintainer_can_modify=true` is the checkbox a human ticks in the web UI, and it is the entire
# reason to submit from a personal fork: without it a maintainer still cannot push a review chore
# into the branch, so the chore becomes a salvage PR and ours is closed as superseded. Set it
# explicitly rather than trusting a server-side default.
PR_URL=$(gh api -X POST "repos/$UPSTREAM/pulls" \
  -f title="$TITLE" -f head="$FORK_OWNER:$BRANCH" -f base="$BASE_BRANCH" -f body="$BODY" \
  -F maintainer_can_modify=true \
  | python3 -c 'import json,sys; print(json.load(sys.stdin).get("html_url",""))')
[ -n "$PR_URL" ] || { echo "error: the PR was not created (check the API response above)" >&2; exit 1; }
printf '\n    %s\n' "$PR_URL"
work "a maintainer merges it; presence in plugin-catalog/ is the install path"
work "after a merge, re-pin pcs-security-guard.yaml to the same sha in this repo"