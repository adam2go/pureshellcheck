#!/usr/bin/env python3
"""Controlled before/after benchmark: installed pureshellcheck vs this tree.

Compares the pureshellcheck version installed in a given venv (the baseline,
e.g. v0.1.0 from PyPI) against the working tree, on several workloads.
Outputs are verified identical before timing. Each measurement is the median
of N in-process repeats; the whole experiment is meant to be run several
times (independent sessions) to check stability.

Usage: python tools/bench_compare.py /path/to/baseline-venv/bin/python
"""

import json
import os
import statistics
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "..", "src")

WORKLOADS = [
    ("tiny (1 line)", None, "echo $foo\n"),
    ("small (75 ln)", "/usr/local/Homebrew/Library/Homebrew/utils/lock.sh",
     None),
    ("medium (263 ln)", "/usr/local/Homebrew/Library/Homebrew/list.sh",
     None),
    ("large (1216 ln)", "/usr/local/Homebrew/Library/Homebrew/brew.sh",
     None),
]

DRIVER = r"""
import json, statistics, sys, time
import pureshellcheck
from pureshellcheck.analyzer import run_checks

src = sys.stdin.read()
repeats = int(sys.argv[1])
run_checks(src)  # warm up
ts = []
for _ in range(repeats):
    t0 = time.perf_counter()
    findings, _ = run_checks(src)
    ts.append(time.perf_counter() - t0)
result = sorted((f.line, f.code) for f in findings)
print(json.dumps({
    "version": pureshellcheck.__version__,
    "median_ms": statistics.median(ts) * 1000,
    "min_ms": min(ts) * 1000,
    "max_ms": max(ts) * 1000,
    "findings": result,
}))
"""


def measure(python, env, source, repeats):
    r = subprocess.run([python, "-c", DRIVER, str(repeats)],
                       input=source, capture_output=True, text=True,
                       env=env)
    if r.returncode != 0:
        sys.exit("driver failed: %s" % r.stderr)
    return json.loads(r.stdout)


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    baseline_python = sys.argv[1]
    new_env = dict(os.environ, PYTHONPATH=SRC)
    base_env = dict(os.environ)
    base_env.pop("PYTHONPATH", None)

    rows = []
    for name, path, inline in WORKLOADS:
        if inline is not None:
            source = inline
        elif path and os.path.isfile(path):
            source = open(path, encoding="utf-8").read()
        else:
            continue
        repeats = 200 if len(source) < 10000 else 25
        base = measure(baseline_python, base_env, source, repeats)
        new = measure(sys.executable, new_env, source, repeats)
        ok = base["findings"] == new["findings"]
        rows.append((name, base, new, ok))

    print("baseline: pureshellcheck %s   new: working tree (%s)"
          % (rows[0][1]["version"], rows[0][2]["version"]))
    print("%-16s %12s %18s %9s  %s" % ("workload", "v" +
          rows[0][1]["version"], "new", "speedup", "outputs"))
    for name, base, new, ok in rows:
        print("%-16s %9.3f ms %14.3f ms %8.2fx  %s"
              % (name, base["median_ms"], new["median_ms"],
                 base["median_ms"] / new["median_ms"],
                 "identical" if ok else "** DIFFER **"))
    if not all(ok for _, _, _, ok in rows):
        sys.exit(1)


if __name__ == "__main__":
    main()
