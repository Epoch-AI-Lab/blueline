#!/usr/bin/env python3
"""
Blueline Verifiable Micro & Macro Benchmark Suite
Compares baseline binary vs. current optimized binary under release profile.
"""

import os
import sys
import time
import json
import socket
import shutil
import tempfile
import threading
import subprocess
from http.server import HTTPServer, BaseHTTPRequestHandler
import hashlib
import base64
import gzip
import tarfile
import io

def make_test_tarball(files: dict) -> bytes:
    raw_tar = io.BytesIO()
    with tarfile.open(fileobj=raw_tar, mode="w:") as tar:
        for name, content in sorted(files.items()):
            data = content.encode("utf-8") if isinstance(content, str) else content
            ti = tarfile.TarInfo(name=name)
            ti.size = len(data)
            ti.mtime = 0
            tar.addfile(ti, io.BytesIO(data))
    raw_bytes = raw_tar.getvalue()
    gz_buf = io.BytesIO()
    with gzip.GzipFile(fileobj=gz_buf, mode="wb", mtime=0) as gz:
        gz.write(raw_bytes)
    return gz_buf.getvalue()

class MockRegistryHandler(BaseHTTPRequestHandler):
    packages = {}

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        path = self.path
        if path.endswith("/dist-tags"):
            pkg_name = path.split("/")[1]
            if pkg_name in self.packages:
                data = json.dumps({"latest": "1.0.1"}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return

        for (pkg_name, ver), (manifest, tar_bytes) in self.packages.items():
            if path == f"/{pkg_name}":
                data = json.dumps(manifest).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return
            elif path == f"/{pkg_name}/-/{pkg_name}-{ver}.tgz":
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(len(tar_bytes)))
                self.end_headers()
                self.wfile.write(tar_bytes)
                return
            elif path == f"/-/npm/v1/attestations/{pkg_name}@{ver}":
                self.send_response(404)
                self.end_headers()
                return

        self.send_response(404)
        self.end_headers()

BAND_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "BLOCK": 3}


def register_adversarial_packages(registry_url):
    """Build the hostile packages on the mock registry and return the cases."""
    hex_blob = "const buf = Buffer.from(\"" + "\\x41" * 512 + "\", \"hex\");"

    cases = [
        {
            "id": "windows-extended-devices",
            "why": "CONIN$/CONOUT$ tar entries must fail closed, never extract",
            "files": {"lib/CONIN$": "x\n", "lib/CONOUT$": "x\n"},
            "expect_fail_closed": True,
        },
        {
            "id": "ipv6-multicast-script",
            "why": "IPv6 multicast/discard URLs in lifecycle scripts trip the network primitive rule",
            "files": {"lib/index.js": "fetch('http://[ff02::2]:1900/x');\nfetch('http://[100::1]/y');\n"},
            "scripts": {"preinstall": "curl -fsS http://[ff02::2]:1900/x || wget http://[::]/y"},
            "expect_finding": ["r03"],
        },
        {
            "id": "osc-escape-flood",
            "why": "uncapped OSC payloads must not reach a terminal unescaped",
            "files": {"lib/\x1b]8;;http://evil.example\x07pwned.js": "console.log('x')\n"},
            "raw_esc_output_forbidden": True,
        },
        {
            "id": "dynamic-function-heuristic",
            "why": "new Function() and hex-buffer construction must trip the heuristic engine",
            "files": {"lib/engine.js": "const f = new Function(payload);\n" + hex_blob + "\n"},
            "expect_finding": ["r03", "function"],
        },
    ]

    for case in cases:
        pkg_name = "adv-" + case["id"]
        files = dict(case["files"])
        manifest_obj = {
            "name": pkg_name,
            "version": "1.0.0",
            "scripts": case.get("scripts", {"test": "echo ok"}),
        }
        files["package.json"] = json.dumps(manifest_obj)
        tar_bytes = make_test_tarball(files)
        sha = base64.b64encode(hashlib.sha512(tar_bytes).digest()).decode("ascii")
        manifest = {
            "name": pkg_name,
            "dist-tags": {"latest": "1.0.0"},
            "versions": {
                "1.0.0": {
                    "name": pkg_name,
                    "version": "1.0.0",
                    "dist": {
                        "tarball": f"{registry_url}/{pkg_name}/-/{pkg_name}-1.0.0.tgz",
                        "integrity": f"sha512-{sha}",
                        "shasum": hashlib.sha1(tar_bytes).hexdigest(),
                    },
                }
            },
        }
        MockRegistryHandler.packages[(pkg_name, "1.0.0")] = (manifest, tar_bytes)
        case["pkg_name"] = pkg_name
    return cases



def run_adversarial_checks(current_bin, registry_url):
    """Review each hostile package with the current binary and assert the
    invariant its case pins. Every check here drives the real binary end to
    end; a check that cannot assert on observed behaviour is deleted, never
    faked with a printed checkmark."""
    cases = register_adversarial_packages(registry_url)
    failures = []

    print("\n[2] ADVERSARIAL ROBUSTNESS & INVARIANT VALIDATION:")
    for case in cases:
        spec = f"{case['pkg_name']}@1.0.0"
        tmp_dir = tempfile.mkdtemp()
        if case.get("raw_esc_output_forbidden"):
            try:
                raw = subprocess.run(
                    [current_bin, "review", spec, "--registry", registry_url, "--output", "text"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=60,
                    env={**os.environ, "BLUELINE_DATA_DIR": tmp_dir},
                )
            except subprocess.TimeoutExpired:
                failures.append(f"{case['id']}: review of {spec} hung past 60s")
                shutil.rmtree(tmp_dir, ignore_errors=True)
                continue
            if b"\x1b" in raw.stdout or b"\x1b" in raw.stderr:
                failures.append(f"{case['id']}: raw ESC byte reached text output")
            else:
                print(f"  ✓ {case['why']} (exit {raw.returncode})")
            shutil.rmtree(tmp_dir, ignore_errors=True)
            continue

        try:
            res = subprocess.run(
                [current_bin, "review", spec, "--registry", registry_url, "--output", "json"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=60,
                env={**os.environ, "BLUELINE_DATA_DIR": tmp_dir},
            )
        except subprocess.TimeoutExpired:
            failures.append(f"{case['id']}: review of {spec} hung past 60s")
            continue
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

        if case.get("expect_fail_closed"):
            if res.returncode == 0:
                failures.append(
                    f"{case['id']}: binary exited 0 on device-name entries; "
                    f"expected a fail-closed non-zero exit"
                )
            else:
                print(f"  ✓ {case['why']} (exit {res.returncode})")
            continue

        if res.returncode not in (0, 2):
            failures.append(
                f"{case['id']}: unexpected exit {res.returncode}: "
                f"{res.stderr.decode('utf-8', errors='replace')[:400]}"
            )
            continue
        try:
            verdict = json.loads(res.stdout)
        except json.JSONDecodeError as exc:
            failures.append(f"{case['id']}: --output json did not parse: {exc}")
            continue

        band = str(verdict.get("band", "")).upper()
        if band not in BAND_RANK:
            failures.append(f"{case['id']}: unknown verdict band {band!r}")
            continue

        case_failed = False
        if "expect_finding" in case:
            joined = " ".join(
                f"{f.get('rule_id', '')} {f.get('title', '')} {f.get('description', '')}"
                for f in verdict.get("findings", [])
            ).lower()
            for needle in case["expect_finding"]:
                if needle.lower() not in joined:
                    failures.append(
                        f"{case['id']}: no finding mentioning {needle!r}; "
                        f"findings were: {joined[:300]}"
                    )
                    case_failed = True

        if not case_failed:
            print(f"  ✓ {case['why']} (band {band})")

    return failures


def run_benchmarks():
    baseline_bin = "/tmp/blueline-baseline-bin"
    current_bin = os.path.abspath("target/release/blueline")

    if not os.path.exists(baseline_bin):
        print(f"Error: Baseline binary not found at {baseline_bin}", file=sys.stderr)
        sys.exit(1)
    if not os.path.exists(current_bin):
        print(f"Error: Current binary not found at {current_bin}", file=sys.stderr)
        sys.exit(1)

    print("=" * 70)
    print("BLUELINE PERFORMANCE & ADVERSARIAL HARDENING BENCHMARK SUITE")
    print("=" * 70)
    print(f"Baseline binary: {baseline_bin}")
    print(f"Current binary:  {current_bin}")
    print("-" * 70)

    # Start Mock HTTP Registry
    server = HTTPServer(("127.0.0.1", 0), MockRegistryHandler)
    port = server.server_address[1]
    registry_url = f"http://127.0.0.1:{port}"
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    # Create synthetic test packages: Small (10 files), Medium (50 files), Large (150 files)
    tiers = {
        "Small (10 files)": 10,
        "Medium (50 files)": 50,
        "Large (150 files)": 150,
    }

    for tier_name, file_count in tiers.items():
        pkg_name = f"pkg-{file_count}"
        # v1.0.0
        v1_files = {f"lib/file_{i}.js": f"console.log('v1 file {i}');\n" * 10 for i in range(file_count)}
        v1_files["package.json"] = json.dumps({"name": pkg_name, "version": "1.0.0", "dependencies": {"dep": "^1.0.0"}})
        v1_tar = make_test_tarball(v1_files)
        v1_sha = base64.b64encode(hashlib.sha512(v1_tar).digest()).decode("ascii")

        # v1.0.1 (modified delta)
        v2_files = {f"lib/file_{i}.js": f"console.log('v2 file {i} modified');\n" * 12 for i in range(file_count)}
        v2_files[f"lib/new_file.js"] = "module.exports = { secure: true };\n"
        v2_files["package.json"] = json.dumps({"name": pkg_name, "version": "1.0.1", "dependencies": {"dep": "^1.0.1"}})
        v2_tar = make_test_tarball(v2_files)
        v2_sha = base64.b64encode(hashlib.sha512(v2_tar).digest()).decode("ascii")

        manifest = {
            "name": pkg_name,
            "dist-tags": {"latest": "1.0.1"},
            "versions": {
                "1.0.0": {
                    "name": pkg_name,
                    "version": "1.0.0",
                    "dist": {
                        "tarball": f"{registry_url}/{pkg_name}/-/{pkg_name}-1.0.0.tgz",
                        "integrity": f"sha512-{v1_sha}",
                        "shasum": hashlib.sha1(v1_tar).hexdigest(),
                    }
                },
                "1.0.1": {
                    "name": pkg_name,
                    "version": "1.0.1",
                    "dist": {
                        "tarball": f"{registry_url}/{pkg_name}/-/{pkg_name}-1.0.1.tgz",
                        "integrity": f"sha512-{v2_sha}",
                        "shasum": hashlib.sha1(v2_tar).hexdigest(),
                    }
                }
            }
        }

        MockRegistryHandler.packages[(pkg_name, "1.0.0")] = (manifest, v1_tar)
        MockRegistryHandler.packages[(pkg_name, "1.0.1")] = (manifest, v2_tar)

    iterations = 10
    print(f"\n[1] MACROBENCHMARKS: End-to-End Package Review ({iterations} iterations per workload)")
    print(f"{'Workload Tier':<20} | {'Baseline Latency':<18} | {'Current Latency':<18} | {'Speedup':<10}")
    print("-" * 75)

    macro_results = {}
    for tier_name, file_count in tiers.items():
        pkg_spec = f"pkg-{file_count}@1.0.1"

        # Benchmark Baseline
        base_times = []
        for _ in range(iterations):
            tmp_dir = tempfile.mkdtemp()
            t0 = time.perf_counter()
            res = subprocess.run(
                [baseline_bin, "review", pkg_spec, "--registry", registry_url, "--output", "json"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={**os.environ, "BLUELINE_DATA_DIR": tmp_dir}
            )
            t1 = time.perf_counter()
            shutil.rmtree(tmp_dir, ignore_errors=True)
            if res.returncode in (0, 2) and len(res.stdout) > 0:
                base_times.append((t1 - t0) * 1000)
            else:
                print("Baseline error:", res.stderr.decode("utf-8", errors="replace"), file=sys.stderr)

        # Benchmark Current
        curr_times = []
        for _ in range(iterations):
            tmp_dir = tempfile.mkdtemp()
            t0 = time.perf_counter()
            res = subprocess.run(
                [current_bin, "review", pkg_spec, "--registry", registry_url, "--output", "json"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={**os.environ, "BLUELINE_DATA_DIR": tmp_dir}
            )
            t1 = time.perf_counter()
            shutil.rmtree(tmp_dir, ignore_errors=True)
            if res.returncode in (0, 2) and len(res.stdout) > 0:
                curr_times.append((t1 - t0) * 1000)
            else:
                print("Current error:", res.stderr.decode("utf-8", errors="replace"), file=sys.stderr)

        avg_base = sum(base_times) / len(base_times) if base_times else 0
        avg_curr = sum(curr_times) / len(curr_times) if curr_times else 0
        speedup = (avg_base / avg_curr) if avg_curr > 0 else 1.0

        print(f"{tier_name:<20} | {avg_base:7.2f} ms ± {min(base_times):.1f}-{max(base_times):.1f} | {avg_curr:7.2f} ms ± {min(curr_times):.1f}-{max(curr_times):.1f} | {speedup:6.2f}x")
        macro_results[tier_name] = {
            "baseline_ms": avg_base,
            "current_ms": avg_curr,
            "speedup": speedup,
        }

    failures = run_adversarial_checks(current_bin, registry_url)

    print("=" * 70)
    if failures:
        print(f"ADVERSARIAL VERIFICATION FAILED: {len(failures)} gate(s) down")
        for line in failures:
            print(f"  ✗ {line}")
        print("=" * 70)
        sys.exit(1)
    print("BENCHMARK & VERIFICATION COMPLETE: ALL GATES PASSING")
    print("=" * 70)

if __name__ == "__main__":
    run_benchmarks()
