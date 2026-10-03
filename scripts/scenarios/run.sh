#!/usr/bin/env bash
#
# run.sh — reproduce one named attack scenario against the real blueline
# binary. This answers "did the fix work?" in one command.
#
#   scripts/scenarios/run.sh                  run every scenario
#   scripts/scenarios/run.sh <name>           run one, print the verdict it saw
#   scripts/scenarios/run.sh --list           list the scenario names
#
# Exits non-zero if any scenario fails. No scenario touches the network:
# every registry is a loopback fixture (enforced by a test, not a convention).
#
# Scenario names are the Rust test names, so a failure reported here can be
# reproduced directly with `cargo test --test scenarios <name> -- --nocapture`.

set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

FILTER=()

usage() {
    cat <<'EOF'
usage: scripts/scenarios/run.sh [<scenario> | --list]

  (no argument)  run every scenario in tests/scenarios.rs
  <scenario>     run one scenario by its test name, showing observed output
  --list         print every scenario name
  -h, --help     this message
EOF
}

list_scenarios() {
    # Read the names out of the test file so this list cannot drift from what
    # the suite actually contains.
    # A scenario is a `#[test] fn name()`: match the attribute and the name
    # together so plain helper functions are not listed as scenarios.
    sed -n '/^#\[test\]/{n;s/^fn \([a-z0-9_]\+\)().*/\1/p;}' tests/scenarios.rs
}

case "${1:-}" in
    -h | --help)
        usage
        exit 0
        ;;
    --list)
        list_scenarios
        exit 0
        ;;
esac

if [ $# -gt 1 ]; then
    echo "error: expected at most one scenario name; got $#" >&2
    usage >&2
    exit 2
fi

if [ $# -eq 1 ]; then
    if ! list_scenarios | grep -qx -- "$1"; then
        echo "error: no scenario named '$1'." >&2
        echo "Known scenarios:" >&2
        list_scenarios | sed 's/^/  /' >&2
        exit 2
    fi
    FILTER=("$1")
fi

echo "== blueline attack scenarios =="
echo

# --locked: CI resolves against the committed Cargo.lock. A scenario that only
# passes against a different dependency graph is not evidence.
# --nocapture: the point of a scenario is the verdict it observed, so print it.
# The name filter is passed ONLY when a scenario was named. An always-present
# empty/placeholder filter would silently match nothing and exit 0.
cargo test --test scenarios --locked -- --nocapture --test-threads=4 "${FILTER[@]}"