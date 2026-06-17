"""Robustness: pathological input must stay fast and never crash.

Regression test for an adversarial fuzz sweep where "[1,[1,[1,..." (many
'[' with no closing ']') drove maybe_read_glob_class into O(n^2) rescanning
and effectively hung the checker.
"""
import sys
import time

import pytest

import pureshellcheck


def test_unclosed_bracket_run_is_linear():
    # 100k brackets must finish quickly; the old O(n^2) scan would take many
    # minutes. Generous ceiling so the test isn't flaky on slow CI.
    src = "[1," * 100000
    t0 = time.perf_counter()
    pureshellcheck.check(src)
    assert time.perf_counter() - t0 < 5.0


def test_glob_character_classes_still_recognized():
    # the fix must not change tokenisation of real glob classes
    for src in ["ls [abc].txt", "rm [!a]*", "echo [[:digit:]]",
                "x=[a-z0-9]", "case $x in [0-9]) ;; esac"]:
        ast = pureshellcheck.parse(src)
        assert "T_Glob" in repr(ast), "glob class lost in %r" % src


@pytest.mark.parametrize("src", [
    "", "[", "[[[[", "]]]]", "[a", "a[", "[]", "[!]", "[^]",
    "[[:", "[[:bogus", "echo [a-",
])
def test_bracket_edge_cases_do_not_crash(src):
    pureshellcheck.check(src)          # must not raise
    pureshellcheck.parse(src)


@pytest.mark.parametrize("opener", ["(", "$( ", "$(( ", "${", "[[ ("])
def test_deeply_nested_constructs_do_not_overflow(opener):
    # Subshells, command substitutions and arithmetic all recurse; deep
    # nesting must raise a clean ParseError, never RecursionError - and stay
    # safe even when a caller has raised the interpreter's recursion limit.
    old = sys.getrecursionlimit()
    sys.setrecursionlimit(50000)
    try:
        src = opener * 9000
        pureshellcheck.check(src)                  # must not crash
        with pytest.raises(pureshellcheck.ParseError):
            pureshellcheck.parse(src)              # parse() surfaces the error
    finally:
        sys.setrecursionlimit(old)


def test_long_backtick_run_does_not_crash():
    # backticks don't nest like parens, but a long run must still be safe
    old = sys.getrecursionlimit()
    sys.setrecursionlimit(50000)
    try:
        pureshellcheck.check("`" * 9000)
    finally:
        sys.setrecursionlimit(old)


def test_realistic_nesting_still_parses():
    for src in ["echo $(echo $(echo hi))", "a=$(( (1+2) * (3+4) ))",
                "( ( ( echo deep ) ) )", "if [[ ( -f x && -r y ) ]]; then :; fi"]:
        pureshellcheck.parse(src)
        pureshellcheck.check(src)


def test_random_bracket_garbage_never_crashes():
    import random
    rng = random.Random(99)
    pool = list("[](){}!^:-,abc*?$ \t\n'\"\\")
    for _ in range(3000):
        src = "".join(rng.choice(pool) for _ in range(rng.randint(0, 50)))
        pureshellcheck.check(src)      # any string is valid input to a linter
