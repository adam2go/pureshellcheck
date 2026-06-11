# pureshellcheck

[![CI](https://github.com/adam2go/pureshellcheck/actions/workflows/ci.yml/badge.svg)](https://github.com/adam2go/pureshellcheck/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/pureshellcheck)](https://pypi.org/project/pureshellcheck/)
[![Conformance](https://img.shields.io/badge/ShellCheck%20test%20suite-619%2F620%20(99.8%25)-brightgreen)](tests/data/expected_failures.txt)

A pure Python reimplementation of [ShellCheck](https://github.com/koalaman/shellcheck)'s
most common checks. No binaries, no Haskell runtime, no compilation —
`pip install pureshellcheck` and it works anywhere Python runs, including
AWS Lambda, Pyodide/WASM, and locked-down CI sandboxes where you can't
install the real ShellCheck binary.

```console
$ pip install pureshellcheck
$ pureshellcheck deploy.sh

In deploy.sh line 8:
rm -rf $BUILD_DIR/*
       ^--------^ SC2086 (info): Double quote to prevent globbing and word splitting.
```

## Why

- **Agent & tooling friendly.** LLM-generated shell scripts fail in
  exactly the ways ShellCheck catches (unquoted expansions, word
  splitting, `cd` without `|| exit`). Existing Python packages such as
  `shellcheck-py` just download the 30 MB Haskell binary — useless in
  WASM, Lambda layers, or hermetic build sandboxes. pureshellcheck is
  ~7000 lines of stdlib-only Python.
- **In-process speed.** Calling `pureshellcheck.check()` takes ~1.3 ms for
  a typical script vs ~50 ms to spawn the shellcheck binary (38×), and is
  ~33× faster than the binary even on 1200-line scripts; one-line snippets
  check in ~40 µs (see [Benchmarks](#benchmarks)).
- **Verified against the real thing.** Test cases are extracted from
  ShellCheck's own test suite and the output is differentially tested
  against the shellcheck binary on real-world scripts.

## What it checks

71 SC codes are implemented, chosen by real-world frequency — the quoting
and word-splitting family (SC2086, SC2046, SC2068, SC2206/2207...),
variable lifecycle (SC2034 unused, SC2154 unassigned, SC2155),
command pitfalls (SC2164 unchecked `cd`, SC2162 `read` without `-r`,
useless `cat`/`echo`, `ls | grep`, `find | xargs`, printf argument
counting, catastrophic `rm -rf`), structural mistakes
(`A && B || C`, constant test expressions, `$?` anti-patterns), and more.

<details>
<summary>All implemented codes</summary>

SC2002 SC2003 SC2004 SC2005 SC2006 SC2007 SC2009 SC2010 SC2011 SC2012
SC2015 SC2016 SC2026 SC2027 SC2028 SC2034 SC2035 SC2038 SC2041 SC2042
SC2043 SC2046 SC2048 SC2050 SC2059 SC2064 SC2065 SC2066 SC2068 SC2086
SC2089 SC2090 SC2093 SC2094 SC2103 SC2114 SC2115 SC2116 SC2126 SC2128
SC2140 SC2145 SC2148 SC2153 SC2154 SC2155 SC2162 SC2164 SC2174 SC2178
SC2179 SC2181 SC2182 SC2183 SC2187 SC2188 SC2189 SC2206 SC2207 SC2223
SC2239 SC2246 SC2248 SC2250 SC2258 SC2304 SC2305 SC2306 SC2307 SC2308

</details>

## Conformance scoreboard

The repository vendors **1508 test cases extracted from ShellCheck's own
test suite** (`tests/data/corpus.json`), run by pytest on every commit:

| metric | result |
|---|---|
| official test cases for the implemented checks | **619/620 (99.8%)** |
| whole official corpus (incl. unimplemented checks) | 1025/1508 (68.0%) |
| real-world differential test vs `shellcheck` 0.11.0 | **113/113 findings agree, 0 missed, 0 false positives** (48 scripts from Homebrew/npm) |

The single implemented-check failure is documented in
`tests/data/expected_failures.txt` (a test of ShellCheck's non-default
`check-unassigned-uppercase` mode); every other non-passing corpus case is
listed there with a reason. Reproduce with:

```console
$ python tools/conformance.py                  # scoreboard
$ python tools/diff_shellcheck.py *.sh         # vs the real binary
```

## Usage

### CLI

```console
$ pureshellcheck [-s bash] [-f tty|gcc|json|json1] [-e SC2086] \
                 [-S error|warning|info|style] script.sh [more.sh ...]
```

Exit status is 0 for a clean script, 1 if there are findings, 2 on file
errors — same convention as shellcheck. `# shellcheck disable=SC2086`
and `# shellcheck shell=dash` directives are honored.

### Library

```python
import pureshellcheck

for f in pureshellcheck.check('echo $foo', shell='bash'):
    print(f.line, f.column, f.code, f.severity, f.message)
# 1 6 2086 info Double quote to prevent globbing and word splitting.
```

`check()` returns a list of findings with `code`, `severity`
(`error|warning|info|style`), `message`, and 1-based
`line`/`column`/`end_line`/`end_column`. `pureshellcheck.parse()` exposes
the bash AST if you want to build your own analyses.

## Benchmarks

All numbers: CPython 3.12, shellcheck 0.11.0, Apple Silicon. Two
experiments, each repeated in 3 independent sessions; medians shown
(session-to-session spread was < 4% everywhere). In both experiments the
findings are verified identical **before** any timing.

**vs the shellcheck binary** (`python tools/bench.py`, median of 9 runs
per session; both tools timed in the same session):

| workload | shellcheck | pureshellcheck | speedup |
|---|---|---|---|
| embedded `check()`, brew.sh (1216 lines) | 720 ms | 21.7 ms | **33×** |
| embedded `check()`, 263-line script | 113 ms | 5.1 ms | **22×** |
| embedded `check()`, 75-line script | 51 ms | 1.3 ms | **38×** |
| CLI end-to-end, brew.sh | 720 ms | 51 ms | **14×** |
| CLI end-to-end, 75-line script | 51 ms | 28 ms | 1.8× |

The embedded rows are what an agent or editor integration pays per call:
no process spawn, no binary. A one-line snippet checks in **~40 µs**
(~25,000 checks/second); throughput on large scripts is ~57k lines/s. CLI
time is dominated by CPython interpreter startup (~20 ms).

**v0.2.x vs v0.1.0** (controlled before/after,
`python tools/bench_compare.py`: baseline wheel from PyPI vs this tree in
the same interpreter, 25–200 in-process repeats, outputs verified
identical on every workload):

| workload | v0.1.0 | v0.2.1 | improvement |
|---|---|---|---|
| tiny (1 line) | 0.058 ms | 0.036 ms | 1.6× |
| small (75 lines) | 2.44 ms | 1.21 ms | 2.0× |
| medium (263 lines) | 8.76 ms | 4.48 ms | 2.0× |
| large (1216 lines) | 46.2 ms | 20.0 ms | **2.3×** |

The speedups came from caching the AST child/parent structure and a
document-order node table (one traversal instead of dozens), making
variable states immutable tuples so branch snapshots are plain dict
copies, a leaf-node fast path, a banded Levenshtein for SC2153
(fuzz-tested against the reference implementation on 20,000 random
pairs), and memoizing repeated word/command resolution. Package import is
3.6 ms; remaining CLI latency is CPython interpreter startup.

## Compatibility notes

- Targets bash (default), sh/dash/ash and ksh dialects are accepted via
  shebang, directive, or `-s`; sh-specific portability checks (the
  SC2039/SC3xxx family) are not implemented yet.
- The parser is deliberately lenient: it keeps checking past constructs
  the real shellcheck refuses to parse (e.g. `[ $tar --version ]`).
- Optional checks (`SC2002`, `SC2248`, `SC2250`) are off by default,
  matching shellcheck 0.11; enable with `-o` / `include_optional=True`.
- Wiki links work the same: see <https://www.shellcheck.net/wiki/SC2086>
  for any reported code.

## Development

```console
$ pip install -e . pytest
$ pytest                                # corpus + unit tests, < 1 s
$ python tools/extract_corpus.py /path/to/shellcheck   # refresh corpus
$ python tools/update_expected_failures.py             # refresh scoreboard
$ python tools/bench.py                                # benchmarks
```

The package itself is MIT licensed and has zero runtime dependencies
(CPython 3.9–3.14 and PyPy). The vendored test corpus in `tests/data/` is
extracted from the GPLv3-licensed ShellCheck project and is used only for
development-time testing; it is not part of the distributed wheel.

## See also

- [purejq](https://github.com/adam2go/purejq) — pure Python jq, same
  philosophy: vendored official test suite, differential testing, no
  binaries.
