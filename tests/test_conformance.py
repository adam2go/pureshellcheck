"""Run the vendored ShellCheck conformance corpus.

Every corpus case must either pass or be listed in expected_failures.txt.
A listed case that starts passing is also an error, so the list never goes
stale.
"""

import json
import os

import pytest

from pureshellcheck.analyzer import run_checks

HERE = os.path.dirname(__file__)


def load_corpus():
    with open(os.path.join(HERE, "data", "corpus.json"),
              encoding="utf-8") as f:
        return json.load(f)


def load_expected_failures():
    out = {}
    path = os.path.join(HERE, "data", "expected_failures.txt")
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            name, _, reason = line.partition("\t")
            out[name] = reason
    return out


CORPUS = load_corpus()
EXPECTED_FAILURES = load_expected_failures()


def entry_passes(entry):
    findings, _err = run_checks(entry["script"], include_optional=True)
    emitted = {f.code for f in findings}
    hit = any(c in emitted for c in entry["codes"])
    return hit if entry["expect"] == "trigger" else not hit


@pytest.mark.parametrize("entry", CORPUS, ids=lambda e: e["id"])
def test_corpus(entry):
    passed = entry_passes(entry)
    expected_fail = entry["id"] in EXPECTED_FAILURES
    if expected_fail and passed:
        pytest.fail("expected failure now passes; remove %r from"
                    " expected_failures.txt" % entry["id"])
    if expected_fail:
        pytest.xfail(EXPECTED_FAILURES[entry["id"]])
    assert passed, "got %r" % sorted(
        f.code for f in run_checks(entry["script"],
                                   include_optional=True)[0])
