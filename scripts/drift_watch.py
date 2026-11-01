#!/usr/bin/env python3
"""Drift watch: review a pinned watchlist of real packages and compare the
verdicts against committed baselines.

A heuristic change that silently moves a real-world verdict is the one class
of regression no hand-built fixture catches, because nobody thought to build
that fixture. This script runs `blueline review` on every watchlist entry,
reduces each verdict to its stable fingerprint (band, risk score, rule IDs),
and diffs it against `verification/drift/baseline.json`.

Modes:
  default        compare against the baseline; any drift fails with a table
  --establish    run everything and rewrite the baseline file

Deliberate noise control: the bundled policy disables OSV advisory checks
(their server-side state changes daily, which is drift in the world, not in
the tool) and every run uses a fresh data dir, so every package is a first
sighting and the verdict depends only on the tool plus registry metadata.

Usage: scripts/drift_watch.py [--establish] [--bin PATH]
"""

import argparse
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import tomllib

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
WATCHLIST = REPO_ROOT / "verification" / "drift" / "watchlist.toml"
POLICY = REPO_ROOT / "verification" / "drift" / "policy.toml"
BASELINE = REPO_ROOT / "verification" / "drift" / "baseline.json"

ATTEMPTS = 3
PER_RUN_TIMEOUT_SECS = 180


def load_watchlist():
    with open(WATCHLIST, "rb") as fh:
        data = tomllib.load(fh)
    packages = data.get("packages", [])
    if not packages:
        print(f"watchlist {WATCHLIST} declares no packages", file=sys.stderr)
        sys.exit(1)
    return packages


def fingerprint(verdict):
    return {
        "band": str(verdict.get("band", "")).upper(),
        "risk_score": verdict.get("risk_score"),
        "rule_ids": sorted(f.get("rule_id", "") for f in verdict.get("findings", [])),
    }


def review(bin_path, pkg):
    spec = f"{pkg['name']}@{pkg['version']}"
    ecosystem = pkg["ecosystem"]
    with tempfile.TemporaryDirectory(prefix="drift-watch-") as data_dir:
        cmd = [
            bin_path, "--ecosystem", ecosystem, "review", spec,
            "--output", "json", "--yes",
            "--policy", str(POLICY),
        ]
        last_error = ""
        for attempt in range(ATTEMPTS):
            try:
                res = subprocess.run(
                    cmd, capture_output=True, timeout=PER_RUN_TIMEOUT_SECS,
                    env={**os.environ, "BLUELINE_DATA_DIR": data_dir},
                )
            except subprocess.TimeoutExpired:
                last_error = f"timed out after {PER_RUN_TIMEOUT_SECS}s"
                continue
            if res.returncode in (0, 2) and res.stdout:
                try:
                    return fingerprint(json.loads(res.stdout))
                except json.JSONDecodeError as exc:
                    last_error = f"json did not parse: {exc}"
            else:
                last_error = (f"exit {res.returncode}: "
                              f"{res.stderr.decode('utf-8', errors='replace')[:300]}")
        raise RuntimeError(f"review {spec} failed after {ATTEMPTS} attempts: {last_error}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--establish", action="store_true",
                        help="rewrite baseline.json from this run instead of comparing")
    parser.add_argument("--bin", default=str(REPO_ROOT / "target" / "release" / "blueline"),
                        help="blueline binary to review with")
    args = parser.parse_args()

    if not pathlib.Path(args.bin).exists():
        print(f"binary not found at {args.bin}; build it first (cargo build --release)", file=sys.stderr)
        return 1

    packages = load_watchlist()
    current = {}
    failures = []
    for pkg in packages:
        key = f"{pkg['ecosystem']}:{pkg['name']}@{pkg['version']}"
        try:
            current[key] = review(args.bin, pkg)
            print(f"  {key}: {current[key]['band']} (score {current[key]['risk_score']}, "
                  f"{len(current[key]['rule_ids'])} rules)")
        except RuntimeError as exc:
            failures.append(str(exc))
            print(f"  {key}: ERROR {exc}", file=sys.stderr)

    if failures:
        print(f"\n{len(failures)} watchlist entries could not be reviewed", file=sys.stderr)
        return 1

    if args.establish:
        BASELINE.write_text(json.dumps(current, indent=2, sort_keys=True) + "\n")
        print(f"\nwrote {len(current)} fingerprints to {BASELINE.relative_to(REPO_ROOT)}")
        return 0

    if not BASELINE.exists():
        print(f"no baseline at {BASELINE}; run with --establish first", file=sys.stderr)
        return 1

    baseline = json.loads(BASELINE.read_text())
    drifted = []
    for key in sorted(set(baseline) | set(current)):
        if key not in baseline:
            drifted.append((key, "<absent>", current[key]["band"]))
        elif key not in current:
            drifted.append((key, baseline[key]["band"], "<review failed>"))
        elif baseline[key] != current[key]:
            drifted.append((key, baseline[key]["band"], current[key]["band"]))

    if not drifted:
        print(f"\nno drift across {len(current)} watchlist entries")
        return 0

    summary_path = __import__("os").environ.get("GITHUB_STEP_SUMMARY")
    lines = [f"DRIFT: {len(drifted)} watchlist verdict(s) changed", ""]
    lines.append("| package | baseline band | current band |")
    lines.append("| --- | --- | --- |")
    for key, old, new in drifted:
        lines.append(f"| {key} | {old} | {new} |")
    lines += ["", "Accept intentional drift by re-running "
              "`scripts/drift_watch.py --establish` and committing the diff."]
    report = "\n".join(lines)
    print(report)
    if summary_path:
        with open(summary_path, "a") as fh:
            fh.write("## Drift watch\n\n" + report + "\n")
    return 1


if __name__ == "__main__":
    sys.exit(main())
