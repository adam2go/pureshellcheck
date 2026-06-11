#!/usr/bin/env python3
"""Differential testing against the real shellcheck binary.

Runs both shellcheck and pureshellcheck on the given scripts and compares
findings, restricted to the SC codes pureshellcheck implements. Reports
agreement on (line, code) pairs.

Usage: python tools/diff_shellcheck.py script1.sh script2.sh ...
       python tools/diff_shellcheck.py --glob '/path/**/*.sh'
"""

import glob
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from pureshellcheck import implemented_codes  # noqa: E402
from pureshellcheck.analyzer import run_checks  # noqa: E402

# Optional checks are off in both tools by default. Codes whose semantics
# require analysis we deliberately approximate are compared but flagged.
IGNORED = {1073}  # parse-error code differs by design


def shellcheck_findings(path):
    r = subprocess.run(
        ["shellcheck", "--format=json1", "--norc", path],
        capture_output=True, text=True)
    try:
        data = json.loads(r.stdout)
    except json.JSONDecodeError:
        return None
    if any(c["code"] < 2000 and c["level"] == "error"
           for c in data["comments"]):
        return None  # shellcheck itself stopped at a parse error
    return {(c["line"], c["code"]) for c in data["comments"]}


def our_findings(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        source = f.read()
    findings, err = run_checks(source)
    return {(f.line, f.code) for f in findings}, err


def main():
    args = sys.argv[1:]
    files = []
    if args and args[0] == "--glob":
        files = [f for f in glob.glob(args[1], recursive=True)
                 if os.path.isfile(f)]
    else:
        files = args
    impl = implemented_codes() - IGNORED
    total_sc = total_ours = total_common = 0
    parse_errors = 0
    file_count = 0
    diffs = []
    for path in sorted(files):
        sc = shellcheck_findings(path)
        if sc is None:
            continue
        ours, err = our_findings(path)
        file_count += 1
        if err is not None:
            parse_errors += 1
            diffs.append((path, "PARSE ERROR: %s" % err))
            continue
        sc = {(l, c) for (l, c) in sc if c in impl}
        ours = {(l, c) for (l, c) in ours if c in impl}
        common = sc & ours
        total_sc += len(sc)
        total_ours += len(ours)
        total_common += len(common)
        for line, code in sorted(sc - ours):
            diffs.append((path, "missing   SC%d at line %d" % (code, line)))
        for line, code in sorted(ours - sc):
            diffs.append((path, "extra     SC%d at line %d" % (code, line)))
    print("files compared:        %d" % file_count)
    print("parse errors (ours):   %d" % parse_errors)
    print("shellcheck findings:   %d (implemented codes only)" % total_sc)
    print("pureshellcheck same:   %d" % total_common)
    print("missed:                %d" % (total_sc - total_common))
    print("extra (possible FPs):  %d" % (total_ours - total_common))
    if total_sc:
        print("agreement:             %.1f%%"
              % (100.0 * total_common / total_sc))
    if "-v" in sys.argv:
        for path, msg in diffs:
            print("  %s: %s" % (path, msg))
    else:
        import collections
        counter = collections.Counter(
            msg.split(" at ")[0] for _p, msg in diffs
            if not msg.startswith("PARSE"))
        for msg, n in counter.most_common(25):
            print("  %4d  %s" % (n, msg))


if __name__ == "__main__":
    main()
