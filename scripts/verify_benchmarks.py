#!/usr/bin/env python3
import time
import subprocess
import tempfile
import json
import os
import sys

def create_synthetic_lockfiles(pkg_count=10000):
    base_pkgs = {"": {"name": "bench-app", "version": "1.0.0"}}
    head_pkgs = {"": {"name": "bench-app", "version": "1.0.0"}}
    for i in range(pkg_count):
        base_pkgs[f"node_modules/dep-{i}"] = {
            "version": "1.0.0",
            "integrity": f"sha512-mockhash{i}abcdefghijklmnopqrstuvwxyz0123456789",
            "dev": i % 2 == 0
        }
        if i % 10 == 0:
            continue
        elif i % 20 == 0:
            head_pkgs[f"node_modules/dep-{i}"] = {
                "version": "1.1.0",
                "integrity": f"sha512-newhash{i}abcdefghijklmnopqrstuvwxyz0123456789",
                "dev": i % 2 == 0
            }
        else:
            head_pkgs[f"node_modules/dep-{i}"] = {
                "version": "1.0.0",
                "integrity": f"sha512-mockhash{i}abcdefghijklmnopqrstuvwxyz0123456789",
                "dev": i % 2 == 0
            }
    for i in range(pkg_count, pkg_count + 500):
        head_pkgs[f"node_modules/dep-new-{i}"] = {
            "version": "1.0.0",
            "integrity": f"sha512-freshhash{i}abcdefghijklmnopqrstuvwxyz0123456789"
        }
    base_json = json.dumps({"name": "bench-app", "version": "1.0.0", "lockfileVersion": 3, "packages": base_pkgs})
    head_json = json.dumps({"name": "bench-app", "version": "1.0.0", "lockfileVersion": 3, "packages": head_pkgs})
    return base_json, head_json

def benchmark_lockfile_ci(bin_path, iterations=15):
    with tempfile.TemporaryDirectory() as td:
        subprocess.run(["git", "init"], cwd=td, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["git", "config", "user.name", "Bench"], cwd=td, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["git", "config", "user.email", "bench@test"], cwd=td, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        base_json, head_json = create_synthetic_lockfiles(10000)
        base_lock = os.path.join(td, "package-lock.json")
        with open(base_lock, "w") as f:
            f.write(base_json)
        subprocess.run(["git", "add", "package-lock.json"], cwd=td, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["git", "commit", "-m", "base"], cwd=td, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        with open(os.path.join(td, "blueline.toml"), "w") as f:
            f.write("[ci]\nmax_evaluations = 10\n[provenance]\nrequire_provenance = false\n")

        with open(base_lock, "w") as f:
            f.write(head_json)

        data_dir = os.path.join(td, "data")
        os.makedirs(data_dir, exist_ok=True)
        env = os.environ.copy()
        env["BLUELINE_DATA_DIR"] = data_dir

        out_report = os.path.join(td, "ci-out.md")

        # Warmup
        subprocess.run(
            [bin_path, "--policy", "blueline.toml", "ci", "--base", "HEAD", "--lockfile", "package-lock.json", "--format", "markdown", "--output-file", out_report],
            cwd=td, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )

        timings = []
        for _ in range(iterations):
            start = time.perf_counter_ns()
            res = subprocess.run(
                [bin_path, "--policy", "blueline.toml", "ci", "--base", "HEAD", "--lockfile", "package-lock.json", "--format", "markdown", "--output-file", out_report],
                cwd=td, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            elapsed_ms = (time.perf_counter_ns() - start) / 1_000_000.0
            timings.append(elapsed_ms)
        return timings

def main():
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    curr_bin = os.path.join(repo_root, "target/release/blueline")
    base_bin = "/tmp/blueline-baseline/target/release/blueline"

    if not os.path.exists(curr_bin):
        print(f"Current binary not found at {curr_bin}. Please run 'cargo build --release' first.", file=sys.stderr)
        sys.exit(1)

    print("=========================================================")
    print("      Blueline Verifiable Benchmark Suite                ")
    print("=========================================================")
    print(f"Current Binary:  {curr_bin}")

    if os.path.exists(base_bin):
        print(f"Baseline Binary: {base_bin}")
        print("\n1. Benchmarking Lockfile Delta Engine (10,000 packages, 15 iterations)...")
        base_timings = benchmark_lockfile_ci(base_bin, iterations=15)
        curr_timings = benchmark_lockfile_ci(curr_bin, iterations=15)

        base_avg = sum(base_timings) / len(base_timings)
        base_min = min(base_timings)
        curr_avg = sum(curr_timings) / len(curr_timings)
        curr_min = min(curr_timings)

        print(f"   Baseline: {base_avg:.2f} ms (min: {base_min:.2f} ms)")
        print(f"   Current:  {curr_avg:.2f} ms (min: {curr_min:.2f} ms)")
        speedup = ((base_avg - curr_avg) / base_avg) * 100.0
        ratio = base_avg / curr_avg if curr_avg > 0 else 1.0
        print(f"   --> Speedup: {ratio:.2f}x ({speedup:.1f}% latency reduction)")

        print("\n=========================================================")
        print("Summary: Verifiable benchmarks completed successfully.")
        print("=========================================================")
    else:
        print("\nRunning benchmark on current binary (15 iterations)...")
        curr_timings = benchmark_lockfile_ci(curr_bin, iterations=15)
        curr_avg = sum(curr_timings) / len(curr_timings)
        curr_min = min(curr_timings)
        print(f"  Current Avg: {curr_avg:.2f} ms (min: {curr_min:.2f} ms)")
        print("=========================================================")

if __name__ == "__main__":
    main()
