#!/usr/bin/env python3
"""Regenerate tests/data/expected_failures.txt from current behavior.

Each line: <corpus id>\t<reason>
Reasons:
  not-implemented   none of the SC codes of this check are implemented yet
  known-difference  the codes are implemented but this case still differs
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from pureshellcheck import implemented_codes  # noqa: E402
from conformance import load_corpus, run_entry  # noqa: E402


def main():
    impl = implemented_codes()
    lines = []
    for e in load_corpus():
        passed, _emitted, _err = run_entry(e)
        if passed:
            continue
        relevant = any(c in impl for c in e["codes"])
        reason = "known-difference" if relevant else "not-implemented"
        lines.append("%s\t%s" % (e["id"], reason))
    path = os.path.join(os.path.dirname(__file__), "..", "tests", "data",
                        "expected_failures.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write("# Corpus cases that do not pass, regenerate with"
                " tools/update_expected_failures.py\n")
        f.write("\n".join(lines) + "\n")
    print("wrote %d expected failures" % len(lines))


if __name__ == "__main__":
    main()
