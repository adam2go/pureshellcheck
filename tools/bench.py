#!/usr/bin/env python3
"""Benchmark pureshellcheck against the shellcheck binary.

Methodology (pure* series playbook): outputs are first verified to agree on
the implemented checks (--verify, also run by default), then each workload
is timed over N rounds and the median is reported.

Workloads:
  cli        end-to-end CLI run on a file (includes process startup)
  embedded   in-process pureshellcheck.check() vs spawning shellcheck,
             i.e. the cost an agent/tool pays per check() call

Usage: python tools/bench.py [--rounds 7] [files...]
"""

import argparse
import os
import statistics
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pureshellcheck  # noqa: E402
from pureshellcheck import implemented_codes  # noqa: E402
from pureshellcheck.analyzer import run_checks  # noqa: E402

DEFAULT_FILES = [
    "/usr/local/Homebrew/Library/Homebrew/brew.sh",
    "/usr/local/Homebrew/Library/Homebrew/utils/lock.sh",
]


def verify(path):
    import json
    r = subprocess.run(["shellcheck", "--format=json1", "--norc", path],
                       capture_output=True, text=True)
    data = json.loads(r.stdout)
    impl = implemented_codes()
    sc = {(c["line"], c["code"]) for c in data["comments"]
          if c["code"] in impl}
    with open(path, encoding="utf-8") as f:
        src = f.read()
    ours = {(f2.line, f2.code) for f2 in run_checks(src)[0]
            if f2.code in impl}
    if sc != ours:
        print("VERIFY FAILED for %s" % path)
        print("  only shellcheck:", sorted(sc - ours))
        print("  only ours:      ", sorted(ours - sc))
        return False
    print("verified %s: %d findings agree" % (path, len(sc)))
    return True


def time_cmd(argv, rounds):
    times = []
    for _ in range(rounds):
        t0 = time.perf_counter()
        subprocess.run(argv, capture_output=True)
        times.append(time.perf_counter() - t0)
    return statistics.median(times)


def time_fn(fn, rounds):
    times = []
    for _ in range(rounds):
        t0 = time.perf_counter()
        fn()
        times.append(time.perf_counter() - t0)
    return statistics.median(times)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", type=int, default=7)
    ap.add_argument("files", nargs="*", default=None)
    args = ap.parse_args()
    files = [f for f in (args.files or DEFAULT_FILES) if os.path.isfile(f)]
    if not files:
        sys.exit("no benchmark files found; pass paths explicitly")

    print("python: %s  shellcheck: %s" % (
        sys.version.split()[0],
        subprocess.run(["shellcheck", "--version"], capture_output=True,
                       text=True).stdout.splitlines()[1].split()[-1]))
    ok = all(verify(f) for f in files)
    if not ok:
        sys.exit(1)
    print()

    for path in files:
        size = os.path.getsize(path)
        with open(path, encoding="utf-8") as f:
            src = f.read()
        lines = src.count("\n")
        print("== %s (%d lines, %.1f KiB)" % (path, lines, size / 1024.0))

        sc = time_cmd(["shellcheck", "--norc", path], args.rounds)
        cli = time_cmd([sys.executable, "-m", "pureshellcheck.cli", path],
                       args.rounds)
        print("  cli:      shellcheck %7.1f ms   pureshellcheck %7.1f ms"
              "   (%.1fx)" % (sc * 1000, cli * 1000, sc / cli))

        emb = time_fn(lambda: run_checks(src), args.rounds)
        print("  embedded: shellcheck %7.1f ms   pureshellcheck.check()"
              " %7.1f ms   (%.1fx)" % (sc * 1000, emb * 1000, sc / emb))
        print()


if __name__ == "__main__":
    main()
