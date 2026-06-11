#!/usr/bin/env python3
"""Run the vendored ShellCheck conformance corpus and print a scoreboard.

Usage:
  python tools/conformance.py            # summary
  python tools/conformance.py -v         # list failing implemented cases
  python tools/conformance.py SC2086     # detail for one code
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pureshellcheck import implemented_codes  # noqa: E402
from pureshellcheck.analyzer import run_checks  # noqa: E402


def load_corpus():
    path = os.path.join(os.path.dirname(__file__), "..", "tests", "data",
                        "corpus.json")
    return json.load(open(path, encoding="utf-8"))


def run_entry(entry):
    """Returns (passed, emitted_codes)."""
    findings, err = run_checks(entry["script"], include_optional=True)
    emitted = {f.code for f in findings}
    hit = any(c in emitted for c in entry["codes"])
    if entry["expect"] == "trigger":
        return hit, emitted, err
    return not hit, emitted, err


def main():
    verbose = "-v" in sys.argv
    only_code = None
    for a in sys.argv[1:]:
        if a.startswith("SC"):
            only_code = int(a[2:])
    corpus = load_corpus()
    impl = implemented_codes()
    total_pass = total = 0
    impl_pass = impl_total = 0
    failures = []
    for e in corpus:
        relevant = any(c in impl for c in e["codes"])
        if only_code is not None and only_code not in e["codes"]:
            continue
        passed, emitted, err = run_entry(e)
        total += 1
        total_pass += passed
        if relevant:
            impl_total += 1
            impl_pass += passed
            if not passed:
                failures.append((e, emitted, err))
    print("implemented codes: %d" % len(impl))
    if impl_total:
        print("implemented-check cases: %d/%d (%.1f%%)"
              % (impl_pass, impl_total, 100.0 * impl_pass / impl_total))
    print("whole corpus:            %d/%d (%.1f%%)"
          % (total_pass, total, 100.0 * total_pass / total))
    if verbose or only_code:
        for e, emitted, err in failures:
            print("FAIL %-40s expect %-10s codes %s got %s%s" % (
                e["id"], e["expect"], e["codes"], sorted(emitted),
                "  [parse error: %s]" % err if err else ""))
            print("     %r" % e["script"])


if __name__ == "__main__":
    main()
