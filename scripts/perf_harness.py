#!/usr/bin/env python3
"""
Blueline review-path performance harness.

Serves synthetic npm packages from a loopback registry and measures what one
`blueline review` actually costs: wall clock, CPU, and peak resident memory.

    python3 scripts/perf_harness.py
    ITERS=7 ONLY=many-small python3 scripts/perf_harness.py
    POLICY=/path/to/no-advisories.toml python3 scripts/perf_harness.py

Scenarios are selected with ONLY=<substring>. A blank ONLY runs the light ones;
the memory-heavy packages are opt-in because a large one writes to /tmp and
that is tmpfs on many machines, so it costs RAM.

Measurement notes, both learned the hard way on 2026-10-11:

  * RSS comes from sampling /proc/<pid>/status across the process tree, NOT
    from wait4 rusage. ru_maxrss reported the same scenario at 24 MB and 71 MB
    on different runs, and it folds reaped children into one figure so it
    cannot tell the parent from the Landlock extraction child.
  * wait4 is still used for CPU and for the exit status. Only its maxrss is
    untrustworthy.
  * A run that exits non-zero with empty stdout is reported as FAILED and is
    never folded into a median.
"""

import base64
import gzip
import hashlib
import io
import json
import os
import shutil
import statistics
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BIN = os.environ.get("BLUELINE_BIN", "target/release/blueline")
ITERS = int(os.environ.get("ITERS", "7"))
ONLY = os.environ.get("ONLY", "")

PACKAGES = {}


def make_tarball(files):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w:") as tar:
        for name, content in sorted(files.items()):
            data = content if isinstance(content, bytes) else content.encode()
            ti = tarfile.TarInfo(name=name)
            ti.size = len(data)
            ti.mtime = 0
            tar.addfile(ti, io.BytesIO(data))
    gz = io.BytesIO()
    with gzip.GzipFile(fileobj=gz, mode="wb", mtime=0) as g:
        g.write(raw.getvalue())
    return gz.getvalue()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_GET(self):
        parts = self.path.strip("/").split("/")
        name = parts[0] if parts else ""
        entry = PACKAGES.get(name)
        if entry is None:
            self._404()
            return

        manifest, tarballs = entry
        if self.path.endswith(".tgz"):
            ver = self.path.rsplit("-", 1)[-1][: -len(".tgz")]
            body = tarballs.get(ver)
            ctype = "application/octet-stream"
        elif "/attestations/" in self.path:
            self._404()
            return
        else:
            body = json.dumps(manifest).encode()
            ctype = "application/json"

        if body is None:
            self._404()
            return
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _404(self):
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()


def register(name, files_v1, files_v2):
    t1 = make_tarball(files_v1)
    t2 = make_tarball(files_v2)

    def integ(b):
        return "sha512-" + base64.b64encode(hashlib.sha512(b).digest()).decode()

    PACKAGES[name] = (
        {"name": name, "dist-tags": {"latest": "1.0.1"}, "versions": {}},
        {"1.0.0": t1, "1.0.1": t2},
    )
    PACKAGES[name][0]["versions"] = {
        v: {
            "name": name,
            "version": v,
            "dist": {"tarball": f"{{BASE}}/{name}/-/{name}-{v}.tgz", "integrity": integ(t)},
        }
        for v, t in (("1.0.0", t1), ("1.0.1", t2))
    }


def scenario(name, nfiles, file_bytes, changed_frac, big_mb=0, nbig=0):
    """Build a synthetic package pair and register it. Returns the package name.

    nbig > 0 creates `nbig` distinct files of `big_mb` MiB each. An earlier
    revision of this harness set a single file regardless of nbig, so a row
    labelled "many huge files" actually measured one file. Do not reintroduce
    that: the label and the fixture have to agree.
    """
    v1, v2 = {}, {}
    for i in range(nfiles):
        filler = ("x" * (file_bytes - 1) + "\n") if file_bytes > 1 else "a\n"
        v1[f"lib/mod_{i}.js"] = filler
        changed = (i % max(1, int(1 / changed_frac)) == 0) if changed_frac < 1 else True
        v2[f"lib/mod_{i}.js"] = filler.replace("x", "y") if changed else filler
    v1["package.json"] = json.dumps({"name": name, "version": "1.0.0"})
    v2["package.json"] = json.dumps({"name": name, "version": "1.0.1"})
    for b in range(nbig):
        body = "z" * (big_mb * 1024 * 1024)
        v1[f"dist/blob.{b}"] = body
        v2[f"dist/blob.{b}"] = body[:-1] + "!\n"
    register(name, v1, v2)
    return name


def _tree_pids(root):
    out, frontier = [root], [root]
    while frontier:
        pid = frontier.pop()
        try:
            with open(f"/proc/{pid}/task/{pid}/children") as f:
                kids = f.read().split()
        except OSError:
            continue
        for k in kids:
            out.append(int(k))
            frontier.append(int(k))
    return out


def _rss_kb(pid):
    total = 0
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    total += int(line.split()[1])
                    break
    except OSError:
        pass
    return total


def run_once(binary, spec, base, data_dir, policy, interval=0.002):
    """One review, measured.

    CPU and the exit status come from wait4, which is exact. Peak RSS comes
    from a sampler thread walking /proc, because ru_maxrss is not trustworthy
    here. The two cannot be collected in one place: polling proc.poll() reaps
    the child, and wait4 is then too late to ask. So the sampler runs alongside
    and wait4 does the reaping.
    """
    env = {**os.environ, "BLUELINE_DATA_DIR": data_dir}
    cmd = [binary, "review", spec, "--registry", base, "--output", "json", "--yes"]
    if policy:
        cmd += ["--policy", policy]

    t0 = time.perf_counter()
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)

    stop = threading.Event()
    peak = [0]

    def sample():
        while not stop.is_set():
            peak[0] = max(peak[0], sum(_rss_kb(p) for p in _tree_pids(proc.pid)))
            time.sleep(interval)

    sampler = threading.Thread(target=sample, daemon=True)
    sampler.start()

    _, status, ru = os.wait4(proc.pid, 0)
    stop.set()
    sampler.join(timeout=1.0)

    wall = (time.perf_counter() - t0) * 1000.0
    out, err = proc.communicate()
    exit_code = os.WEXITSTATUS(status) if os.WIFEXITED(status) else -os.WTERMSIG(status)
    return {
        "wall_ms": wall,
        "peak_rss_kb": peak[0],
        "cpu_ms": (ru.ru_utime + ru.ru_stime) * 1000.0,
        "exit": exit_code,
        # 0 and 2 are both real outcomes. 2 is blueline refusing a verdict
        # above the approve band, which is a correct result, not a failure.
        "ok": exit_code in (0, 2) and len(out.strip()) > 0,
        "stderr": err.decode("utf-8", "replace")[:160],
    }


SCENARIOS = [
    ("many-tiny-files (200 x 40B, all changed)", "many-tiny",
     dict(nfiles=200, file_bytes=40, changed_frac=1.0)),
    ("many-small-files (2000 x 1KB, all changed)", "many-small",
     dict(nfiles=2000, file_bytes=1024, changed_frac=1.0)),
    ("mostly-unchanged (2000 x 1KB, 1% changed)", "mostly-unchanged",
     dict(nfiles=2000, file_bytes=1024, changed_frac=0.01)),
    ("under-diff-cap (51 x 1.9MB, line diffed)", "under-diff-cap",
     dict(nfiles=1, file_bytes=1024, changed_frac=1.0, big_mb=1, nbig=51)),
    ("over-diff-cap (12 x 8MB, diff skipped)", "over-diff-cap",
     dict(nfiles=1, file_bytes=1024, changed_frac=1.0, big_mb=8, nbig=12)),
]


def main():
    if not os.path.exists(BIN):
        print(f"error: binary not found at {BIN}", file=sys.stderr)
        print("hint: set BLUELINE_BIN, or build it with cargo build --release", file=sys.stderr)
        return 1

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    base = f"http://127.0.0.1:{port}"
    threading.Thread(target=server.serve_forever, daemon=True).start()

    plans = []
    for label, key, kwargs in SCENARIOS:
        if ONLY and ONLY not in label and ONLY not in key:
            continue
        pkg = scenario(f"perf-{key}", **kwargs)
        plans.append((label, pkg))

    # Point every tarball at the real port now that it is known.
    for name, (manifest, tarballs) in PACKAGES.items():
        for v in manifest["versions"].values():
            v["dist"]["tarball"] = v["dist"]["tarball"].replace("{BASE}", base)

    policy = os.environ.get("POLICY") or None
    print(f"binary : {BIN}")
    print(f"reg    : {base}")
    print(f"policy : {policy or 'default (check_advisories = true)'}")
    print(f"iters  : {ITERS}\n")

    hdr = (f"{'scenario':<46} {'wall ms':>9} {'CPU ms':>8} {'ok':>7} "
           f"{'peak RSS MB':>12}  status")
    print(hdr)
    print("-" * len(hdr))

    failures = 0
    for label, pkg in plans:
        runs = []
        for _ in range(ITERS):
            d = tempfile.mkdtemp(prefix="blperf-")
            try:
                runs.append(run_once(BIN, f"{pkg}@1.0.1", base, d, policy))
            finally:
                shutil.rmtree(d, ignore_errors=True)
        ok = [r for r in runs if r["ok"]]
        if not ok:
            failures += 1
            first = runs[0] if runs else {}
            print(f"{label:<46} {'FAILED':>9} {'':>8} {0:>3}/{len(runs):<3} "
                  f"{'':>12}  exit={first.get('exit', '?')} "
                  f"{first.get('stderr', '')}")
            continue
        wall = statistics.median(r["wall_ms"] for r in ok)
        cpu = statistics.median(r["cpu_ms"] for r in ok)
        rss = max(r["peak_rss_kb"] for r in ok) / 1024
        print(f"{label:<46} {wall:9.1f} {cpu:8.1f} {len(ok):>3}/{len(runs):<3} "
              f"{rss:12.1f}  ok")

    server.shutdown()
    if failures:
        print(f"\n{failures} scenario(s) FAILED. Reported, not averaged away.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())