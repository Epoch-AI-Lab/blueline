#!/usr/bin/env bash
#
# prune_incremental.sh - delete stale cargo incremental compilation caches.
#
# Cargo keeps one session directory per build fingerprint under
# `target/<profile>/incremental/<pkg>-<hash>/` and never removes any of them.
# There is no knob for it: `incremental = false` is all-or-nothing, and
# `cargo clean` has no `--incremental`. On this box that had grown to 4.1 GB
# across 251 sessions, 3.2 GB of them blueline's own, because `cargo mutants`
# sets RUSTFLAGS and so writes a fresh session on every mutation run (single
# sessions of 288 MB were not unusual).
#
# A stale session is not a cache hit waiting to happen: the fingerprint that
# produced it no longer exists, so nothing will ever read it again. Deleting it
# costs one rebuild and nothing else.
#
#   scripts/prune_incremental.sh                 # report only, deletes nothing
#   scripts/prune_incremental.sh --apply         # delete what is older than 7d
#   scripts/prune_incremental.sh --days 3        # tighter or looser window
#   scripts/prune_incremental.sh --target-dir D  # somewhere other than ./target
#
# Dry run is the default on purpose. This is the only script here that deletes
# anything, and "delete my build cache" should never be something a command
# does behind your back.
#
# A session is judged by the newest file inside it, not by the directory's own
# mtime: cargo touches the directory when it reuses a session, so a directory
# mtime says "recently used" for caches that stopped being used a week ago.

set -uo pipefail

DAYS=7
APPLY=0
TARGET_DIR=""

usage() {
    sed -n '3,24p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --apply)      APPLY=1 ;;
        --days)       shift; DAYS="${1:?--days needs a number}" ;;
        --target-dir) shift; TARGET_DIR="${1:?--target-dir needs a path}" ;;
        -h|--help)    usage; exit 0 ;;
        *)            echo "prune_incremental.sh: unknown argument '$1'" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

case "$DAYS" in
    ''|*[!0-9]*) echo "prune_incremental.sh: --days must be a whole number, got '$DAYS'" >&2; exit 2 ;;
esac

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
[ -n "$TARGET_DIR" ] || TARGET_DIR="target"

if [ ! -d "$TARGET_DIR" ]; then
    echo "prune_incremental.sh: no $TARGET_DIR directory here (run from the repo root)" >&2
    exit 1
fi

NOW=$(date +%s)
CUTOFF=$((NOW - DAYS * 86400))
TOTAL_BYTES=0
TOTAL_DIRS=0
KEPT=0

for dir in "$TARGET_DIR"/*/incremental/*/; do
    [ -d "$dir" ] || continue
    # Newest mtime of anything inside, which is when cargo last wrote here.
    newest=$(find "$dir" -type f -printf '%T@\n' 2>/dev/null | sort -rn | head -1)
    [ -n "$newest" ] || newest=0
    newest="${newest%%.*}"
    if [ "$newest" -ge "$CUTOFF" ]; then
        KEPT=$((KEPT + 1))
        continue
    fi
    size_kb=$(du -sk "$dir" 2>/dev/null | cut -f1)
    size_kb=${size_kb:-0}
    TOTAL_BYTES=$((TOTAL_BYTES + size_kb))
    TOTAL_DIRS=$((TOTAL_DIRS + 1))
    if [ "$APPLY" -eq 1 ]; then
        rm -rf -- "$dir" || echo "prune_incremental.sh: could not remove $dir" >&2
    else
        printf 'would remove %6s MB  %s\n' "$((size_kb / 1024))" "$dir"
    fi
done

printf '\n%d session(s) newer than %dd kept, %d session(s) %s totalling %s MB\n' \
    "$KEPT" "$DAYS" "$TOTAL_DIRS" \
    "$([ "$APPLY" -eq 1 ] && echo removed || echo older than ${DAYS}d)" \
    "$((TOTAL_BYTES / 1024))"

if [ "$APPLY" -ne 1 ] && [ "$TOTAL_DIRS" -gt 0 ]; then
    echo "nothing was deleted. re-run with --apply to do it."
fi