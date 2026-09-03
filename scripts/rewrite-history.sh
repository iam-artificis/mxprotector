#!/usr/bin/env bash
# ==========================================================================
# scripts/rewrite-history.sh
#
# Rewrite every author and committer in this repo's history to a single
# public identity, so `git log` no longer reveals the developer's
# machine hostname or a working email address.
#
#   Old: <name>  <name>@<machine-hostname>
#   New: iam-artificis  iam-artificis@users.noreply.github.com
#
# This is a DESTRUCTIVE operation: it rewrites every commit SHA in the
# repository. Anyone who has cloned the repo BEFORE the rewrite will
# find their local checkout unrelated to the new history. Run this
# ONLY before making the repository public, and never after.
#
# Usage:
#   scripts/rewrite-history.sh                # dry run — prints plan
#   scripts/rewrite-history.sh --apply        # actually rewrite
#   scripts/rewrite-history.sh --apply --push # rewrite AND force-push
#
# What the script does when --apply is passed:
#   1. Refuses to run if the working tree has uncommitted changes.
#   2. Stashes a full backup: `refs/backup/pre-rewrite/<UTC-timestamp>`
#      pointing at the current HEAD and every currently-known branch.
#   3. Calls `git filter-repo --mailmap <generated>` with a mapping
#      that replaces every historical author + committer with
#      iam-artificis <iam-artificis@users.noreply.github.com>.
#   4. Prints the diff of author identities before/after.
#   5. Does NOT push. Force-push only happens with `--push`, and
#      only after showing exactly which refs will be overwritten.
#
# Recovery: any backup ref under refs/backup/pre-rewrite/* can be
# checked out or reset to at any time.
# ==========================================================================

set -euo pipefail

NEW_NAME="iam-artificis"
NEW_EMAIL="iam-artificis@users.noreply.github.com"

MODE="dry-run"
DO_PUSH="no"
for arg in "$@"; do
    case "$arg" in
        --apply) MODE="apply" ;;
        --push)  DO_PUSH="yes" ;;
        --help|-h)
            sed -n '2,32p' "$0"
            exit 0 ;;
        *) echo "unknown flag: $arg" >&2; exit 2 ;;
    esac
done

# Timestamp built the shell way (this script does not import Date.now()
# concerns from a workflow — plain shell can call date freely).
STAMP="$(date -u '+%Y%m%dT%H%M%SZ')"
BACKUP_REF="refs/backup/pre-rewrite/${STAMP}"

# ------------------------------------------------------------------
# Preflight
# ------------------------------------------------------------------
if ! command -v git-filter-repo >/dev/null 2>&1; then
    echo "ERROR: git-filter-repo not on PATH." >&2
    echo "Install with:  pip install git-filter-repo" >&2
    exit 3
fi

# ------------------------------------------------------------------
# Plan
# ------------------------------------------------------------------
echo "===================================================="
echo "  git-history rewrite plan"
echo "===================================================="
echo "  Repo:          $(git rev-parse --show-toplevel)"
echo "  HEAD:          $(git rev-parse --short HEAD)  $(git log -1 --format='%s')"
echo "  Local branches:"
git for-each-ref --format='                   %(refname:short)' refs/heads/
echo
echo "  Identities in history (BEFORE):"
git log --format='                   %an <%ae>' | sort -u | sed 's/^/                   /' | head -20
echo
echo "  New identity:  ${NEW_NAME} <${NEW_EMAIL}>"
echo "  Backup ref:    ${BACKUP_REF}"
echo "  Mode:          ${MODE}"
echo "  Push:          ${DO_PUSH}"
echo "===================================================="

if [ "$MODE" = "dry-run" ]; then
    echo
    echo "Dry run only. Re-run with --apply to actually rewrite history."
    exit 0
fi

# ------------------------------------------------------------------
# --apply: refuse to touch a dirty tree.
# ------------------------------------------------------------------
if [ -n "$(git status --porcelain=v1)" ]; then
    echo "ERROR: working tree has uncommitted changes."           >&2
    echo "Commit or stash them before running --apply."           >&2
    exit 4
fi

# ------------------------------------------------------------------
# Backup every current branch + HEAD to refs/backup/pre-rewrite/<stamp>/*
# ------------------------------------------------------------------
echo "Creating backup refs under ${BACKUP_REF}/..."
git update-ref "${BACKUP_REF}/HEAD" HEAD
git for-each-ref --format='%(refname)' refs/heads/ | while read -r ref; do
    short="${ref#refs/heads/}"
    git update-ref "${BACKUP_REF}/heads/${short}" "$ref"
done

# ------------------------------------------------------------------
# Generate a mailmap that folds every existing author/committer
# into the new public identity. git-filter-repo consumes mailmap
# entries via --mailmap and rewrites every commit accordingly.
# ------------------------------------------------------------------
MAILMAP="$(mktemp)"
trap 'rm -f "$MAILMAP"' EXIT

git log --format='%an <%ae>%n%cn <%ce>' \
  | sort -u \
  | awk -v n="$NEW_NAME" -v e="$NEW_EMAIL" '{ printf("%s <%s> %s\n", n, e, $0) }' \
  > "$MAILMAP"

echo "Generated mailmap:"
sed 's/^/    /' "$MAILMAP"

# ------------------------------------------------------------------
# Do the rewrite
# ------------------------------------------------------------------
git filter-repo --force --mailmap "$MAILMAP"

echo
echo "===================================================="
echo "  Rewrite complete."
echo "===================================================="
echo
echo "  Identities in history (AFTER):"
git log --format='    %an <%ae>' | sort -u

# ------------------------------------------------------------------
# Optional force-push
# ------------------------------------------------------------------
if [ "$DO_PUSH" = "yes" ]; then
    if ! git remote get-url origin >/dev/null 2>&1; then
        echo "WARNING: no 'origin' remote — the working copy has been"
        echo "rewritten locally, but nothing was pushed."
        exit 0
    fi
    echo
    echo "About to force-push these branches to origin:"
    git for-each-ref --format='    %(refname:short)' refs/heads/
    echo
    echo "This will REPLACE the public history. Ctrl-C to abort."
    printf "  Type 'YES' to proceed: "
    read -r CONFIRM
    if [ "$CONFIRM" != "YES" ]; then
        echo "Aborted. Local history rewritten but not pushed."
        echo "Restore any branch from ${BACKUP_REF}/heads/<name> if needed."
        exit 0
    fi
    git for-each-ref --format='%(refname:short)' refs/heads/ | while read -r br; do
        git push --force-with-lease origin "$br"
    done
    echo "Force-push done."
else
    echo
    echo "No push requested. To publish the rewritten history run:"
    echo "  scripts/rewrite-history.sh --apply --push"
    echo
    echo "Or push manually:  git push --force-with-lease origin <branch>"
    echo
    echo "Restore any branch from ${BACKUP_REF}/heads/<name> if needed."
fi
