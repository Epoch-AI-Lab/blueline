#!/usr/bin/env bash
#
# check-references.sh — prove the feature map still points at real code.
#
# `references/` is the agent-facing map of this codebase. Its value is that an
# agent can follow a citation to the code that implements a feature and land on
# something real. That value decays silently: a file gets renamed, a function
# gets deleted, a lane file gets orphaned from the index, and the map keeps
# asserting things that are no longer true. Nothing in the Rust gate can see
# that, because the map is prose.
#
# This is the check that makes the map a mechanism instead of a promise.
#
#   scripts/check-references.sh
#
# Exits non-zero if any citation in references/ does not resolve, any cited
# line falls outside the file it names, or any lane file is unreachable from
# the index.

set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

problems=0

fail() {
    printf '  %s\n' "$1" >&2
    problems=$((problems + 1))
}

# git ls-files is the source of truth for what exists, matching the convention
# used by the mutation file list. Anything untracked is not part of the repo.
tracked() {
    git ls-files --error-unmatch "$1" >/dev/null 2>&1
}

echo "== feature map citations =="

# ---------------------------------------------------------------- file paths
# Matches src/..., tests/..., scripts/... citations in any lane file. Globs and
# brace forms are accepted so prose like `src/registry/*.rs` and
# `src/registry/{mod,http_util}.rs` does not read as a broken citation.
mapfile -t PATH_CITES < <(
    grep -rhoE '(src|tests|scripts)/[A-Za-z0-9_/.{},*]+\.(rs|sh|mjs|js|py)' references/ \
        | sort -u
)

for cite in "${PATH_CITES[@]}"; do
    candidates=("$cite")
    if [[ $cite == *"{"* ]]; then
        prefix="${cite%%\{*}"
        inner="${cite#*\{}"
        # Cut the trailing "}.ext", so inner is just the comma-separated names.
        inner="${inner%\}.*}"
        suffix="${cite##*\}}"
        IFS=',' read -r -a parts <<<"$inner"
        candidates=()
        for p in "${parts[@]}"; do
            candidates+=("${prefix}${p}${suffix}")
        done
    fi

    for candidate in "${candidates[@]}"; do
        if [[ $candidate == *"*"* ]]; then
            # A glob citation must match at least one tracked file.
            if ! compgen -G "$candidate" >/dev/null; then
                fail "glob citation matches nothing: $candidate"
            fi
            continue
        fi
        if ! tracked "$candidate"; then
            fail "cited path does not exist: $candidate"
        fi
    done
done

# ------------------------------------------------------------- file:line cites
# Bare `name.rs:123` or `name.rs:12-34` citations. The name is resolved against
# the tracked source tree. The line number is checked against the file's current
# length: line drift within a file is expected on every refactor, but a citation
# pointing past the end of the file means the claim is stale, and that is worth
# failing on.
mapfile -t LINE_CITES < <(
    grep -rhoE '`[a-z_]+\.(rs|sh):[0-9]+(-[0-9]+)?`' references/ \
        | tr -d '`' | sort -u
)

while IFS=: read -r base range; do
    resolved=""
    for dir in src src/registry scripts; do
        if tracked "$dir/$base"; then
            resolved="$dir/$base"
            break
        fi
    done

    if [ -z "$resolved" ]; then
        fail "cited file for '$base:$range' does not exist"
        continue
    fi

    start="${range%%-*}"
    end="${range#*-}"
    [ "$end" = "$range" ] && end="$start"
    length=$(wc -l <"$resolved")

    if [ "$end" -gt "$length" ]; then
        fail "cited line $base:$range is past end of $resolved ($length lines)"
    fi
done < <(printf '%s\n' "${LINE_CITES[@]:-}")

# ------------------------------------------------------------------ index
# A lane file unreachable from the map index is invisible to a reader scanning
# the index, which defeats the point of the index.
mapfile -t LANES < <(find references/features -name '*.md' | sort)

for lane in "${LANES[@]}"; do
    base=$(basename "$lane")
    if ! grep -q "$base" references/README.md; then
        fail "lane file not linked from references/README.md: $lane"
    fi
done

mapfile -t INDEXED < <(
    grep -rhoE 'features/[a-z_]+\.md' references/README.md | sort -u
)

for indexed in "${INDEXED[@]}"; do
    if [ ! -f "references/$indexed" ]; then
        fail "index links a lane file that does not exist: references/$indexed"
    fi
done

# ------------------------------------------------------------------ report
checked_paths=${#PATH_CITES[@]}
checked_lines=${#LINE_CITES[@]}
checked_lanes=${#LANES[@]}

if [ "$problems" -ne 0 ]; then
    printf '\n\033[1;31mFAIL\033[0m  %d stale citation(s) in references/\n' "$problems" >&2
    printf '      %d path citations, %d line citations, %d lane files checked\n' \
        "$checked_paths" "$checked_lines" "$checked_lanes" >&2
    exit 1
fi

printf '  %d path citations, %d line citations, %d lane files checked, all resolve\n' \
    "$checked_paths" "$checked_lines" "$checked_lanes"
