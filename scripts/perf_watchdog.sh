#!/usr/bin/env bash
#
# perf_watchdog.sh - run a command under a process-count and wall-clock cap.
#
# AGENTS.md records the 2026-10-09 incident where the blueline test suite
# spawned 529 live processes, load 733, and took the machine down. Re-measured
# on 2026-10-11 under this wrapper the suite peaks at 6 processes and passes in
# 42 s, so the fork bomb does not currently reproduce. Keep the wrapper anyway:
# the cost of the guard is one poll a second, and the cost of not having it is
# the reboot.
#
#   scripts/perf_watchdog.sh <max-seconds> <max-procs> <command> [args...]
#
# Exits with the command's status, or 99 if the watchdog aborted it.
#
# Two things this gets right that a naive version does not:
#
#   * `setsid` forks, so $! is often gone by the time the first poll reads its
#     process group. Counting is therefore done by walking /proc children from
#     the pid we spawned, which does not depend on a pgid existing.
#   * A command that finishes in under a second leaves nothing to count. That is
#     not a silent pass: the peak simply reads 0 because there was no window.

set -uo pipefail

MAXSECS="${1:?usage: perf_watchdog.sh <max-seconds> <max-procs> <command...>}"; shift
MAXPROCS="${1:?usage: perf_watchdog.sh <max-seconds> <max-procs> <command...>}"; shift
[ "$#" -gt 0 ] || { echo "perf_watchdog: no command given" >&2; exit 2; }

echo "perf_watchdog: cap ${MAXSECS}s / ${MAXPROCS} procs :: $*"

setsid "$@" &
ROOT=$!

# Count every live pid whose ancestry reaches ROOT. /proc/<pid>/task/<pid>/
# children is the kernel's own parent list, so this costs one small read per
# process rather than a full ps scan.
count_tree() {
  local frontier=("$ROOT") total=0 pid kids n
  while [ ${#frontier[@]} -gt 0 ]; do
    pid="${frontier[-1]}"
    frontier=("${frontier[@]:0:${#frontier[@]}-1}")
    total=$((total + 1))
    kids=$(cat "/proc/$pid/task/$pid/children" 2>/dev/null) || continue
    for n in $kids; do frontier+=("$n"); done
  done
  echo "$total"
}

kill_tree() {
  local frontier=("$ROOT") pid kids n
  while [ ${#frontier[@]} -gt 0 ]; do
    pid="${frontier[-1]}"
    frontier=("${frontier[@]:0:${#frontier[@]}-1}")
    kids=$(cat "/proc/$pid/task/$pid/children" 2>/dev/null)
    for n in $kids; do frontier+=("$n"); done
    kill -9 "$pid" 2>/dev/null
  done
}

START=$(date +%s)
PEAK=0
KILLED="no"

while kill -0 "$ROOT" 2>/dev/null; do
  NOW=$(date +%s); ELAPSED=$((NOW - START))

  if [ "$ELAPSED" -ge "$MAXSECS" ]; then
    echo "perf_watchdog: WALL LIMIT at ${ELAPSED}s, killing tree" >&2
    KILLED="wall"; break
  fi

  N=$(count_tree)
  [ "$N" -gt "$PEAK" ] && PEAK=$N

  if [ "$N" -gt "$MAXPROCS" ]; then
    echo "perf_watchdog: PROCESS COUNT ${N} > ${MAXPROCS} at ${ELAPSED}s, killing tree" >&2
    KILLED="procs"; break
  fi

  sleep 1
done

if [ "$KILLED" != "no" ]; then
  kill_tree
  sleep 1
fi

wait "$ROOT" 2>/dev/null
RC=$?
ELAPSED=$(( $(date +%s) - START ))

echo "perf_watchdog: rc=$RC elapsed=${ELAPSED}s peak_tree_procs=$PEAK killed=$KILLED"
[ "$KILLED" != "no" ] && exit 99
exit "$RC"