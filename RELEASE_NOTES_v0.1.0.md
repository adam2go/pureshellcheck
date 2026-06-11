# pureshellcheck v0.1.0

First release. A pure Python reimplementation of ShellCheck's most common
checks — no binaries, no Haskell runtime; works in Pyodide/WASM, AWS
Lambda, and sandboxes where the shellcheck binary can't be installed.

## Highlights

- **71 SC codes implemented**, selected by real-world frequency: the
  SC2086 quoting/word-splitting family, SC2034/SC2154 variable lifecycle,
  SC2164 unchecked `cd`, useless cat/echo, pipe pitfalls, printf argument
  checking, catastrophic `rm`, `$?` anti-patterns, and more.
- **619/620 (99.8%)** of ShellCheck's own test cases for the implemented
  checks pass (1508 cases vendored from the official test suite, run in
  CI on every commit; the full list of non-passing cases is in
  `tests/data/expected_failures.txt`).
- **Differentially tested** against shellcheck 0.11.0 on 48 real-world
  scripts (Homebrew, npm): 113/113 findings agree — no misses, no false
  positives.
- **8.9× faster** than the shellcheck binary end-to-end on a 1216-line
  script; **17× faster** for in-process `pureshellcheck.check()` calls on
  typical scripts (median of 7 runs; see `tools/bench.py`).
- Full bash parser (quoting, expansions, heredocs, arithmetic, `[[ ]]`,
  arrays, process substitution, coproc, bats) written for resilience:
  keeps checking past constructs the real shellcheck refuses to parse.
- CLI compatible with shellcheck conventions: `tty`/`gcc`/`json`/`json1`
  formats, `-s` shell override, `-e` exclusions, `-S` severity filter,
  `# shellcheck disable=`/`shell=` directives, same exit codes.
- Zero runtime dependencies; CPython 3.9–3.14 and PyPy.

```console
$ pip install pureshellcheck
$ pureshellcheck script.sh
```
