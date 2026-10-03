#!/usr/bin/env bash
#
# verify.sh — the single source of truth for "did I pass?".
#
# Every stage runs the EXACT command line `.github/workflows/ci.yml` runs,
# flags included. Do not "fix" a command here to make it faster or quieter:
# if this script diverges from CI, the script is the bug.
#
#   ./scripts/verify.sh            fmt + clippy + test  (the Rust gate)
#   ./scripts/verify.sh --fast     same as above; accepted for symmetry
#   ./scripts/verify.sh --mutants  the Rust gate, then mutation testing
#   ./scripts/verify.sh --all      the Rust gate, mutants, + supply-chain audit
#
# Works from any cwd: the repo root is resolved from this script's location.

set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# Mutation targets: derived from the repo, never a hand-maintained list.
# Same globs as ci.yml. Only files with no mutable expressions are skipped
# (see ci.yml for the reason); lib.rs and error.rs are pure declarations.
MUTANTS_SKIP="src/lib.rs
src/error.rs"

RUN_MUTANTS=0
RUN_ALL=0

usage() {
    cat <<'EOF'
usage: scripts/verify.sh [--fast] [--mutants] [--all]

  (default)  fmt + clippy + test — the Rust gate CI enforces
  --fast     same as default
  --mutants  the Rust gate, then cargo-mutants over the security-critical engine
  --all      the Rust gate, mutants, plus the cargo-deny supply-chain audit
EOF
}

for arg in "$@"; do
    case "$arg" in
        --fast)    ;;  # default stage set; accepted for symmetry
        --mutants) RUN_MUTANTS=1 ;;
        --all)     RUN_MUTANTS=1; RUN_ALL=1 ;;
        -h|--help) usage; exit 0 ;;
        *)         echo "verify.sh: unknown argument '$arg'" >&2; usage >&2; exit 2 ;;
    esac
done

declare -a PASSED=()

stage() {
    local name="$1"; shift
    printf '\n\033[1m==> %s\033[0m\n    $ %s\n\n' "$name" "$*"
    if "$@"; then
        PASSED+=("$name")
    else
        local rc=$?
        printf '\n\033[1;31mFAIL\033[0m  %s (exit %d)\n' "$name" "$rc" >&2
        printf '      stage: %s\n' "$name" >&2
        printf '      cmd:   %s\n' "$*" >&2
        exit "$rc"
    fi
}

stage_mutants() {
    if ! cargo mutants --version >/dev/null 2>&1; then
        echo "cargo-mutants not installed. CI installs it via taiki-e/install-action;" >&2
        echo "locally: cargo install cargo-mutants --locked" >&2
        return 127
    fi
    local files=()
    mapfile -t files < <(git ls-files 'src/*.rs' 'src/registry/*.rs' \
        | grep -vxFf <(printf '%s\n' "$MUTANTS_SKIP"))
    if [ "${#files[@]}" -eq 0 ]; then
        echo "no mutation targets resolved from git ls-files" >&2
        return 1
    fi
    echo "mutating ${#files[@]} files"
    local args=() f
    for f in "${files[@]}"; do args+=(--file "$f"); done
    cargo mutants "${args[@]}" --in-place --baseline=skip --timeout 30
}

stage_deny() {
    if ! cargo deny --version >/dev/null 2>&1; then
        echo "cargo-deny not installed: cargo install cargo-deny --locked" >&2
        return 127
    fi
    cargo deny check
}

stages="fmt, clippy, test"
[ "$RUN_MUTANTS" -eq 1 ] && stages="$stages, mutants"
[ "$RUN_ALL" -eq 1 ] && stages="$stages, cargo-deny"

echo "repo:      $REPO_ROOT"
echo "toolchain: $(rustc --version 2>/dev/null || echo 'rustc not on PATH')"
echo "stages:    $stages"

# The Rust gate. Verbatim from ci.yml — note the two flags that are easy to
# drop and were dropped in AGENTS.md: fmt's --check (without it, fmt REWRITES
# your files instead of failing) and clippy's --locked (without it, clippy may
# resolve a different dependency graph than CI).
stage "Format"    cargo fmt --all -- --check
stage "Clippy"    cargo clippy --all-targets --locked -- -D warnings
stage "Tests"     cargo test --all-targets --locked

if [ "$RUN_ALL" -eq 1 ]; then
    stage "Supply-chain audit"   stage_deny
fi

if [ "$RUN_MUTANTS" -eq 1 ]; then
    stage "Mutation testing" stage_mutants
fi

printf '\n\033[1;32mPASS\033[0m  %s\n' "$(IFS=, ; echo "${PASSED[*]}")"