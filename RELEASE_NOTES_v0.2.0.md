# pureshellcheck v0.2.0

Performance release: **2.0–2.3× faster than v0.1.0** across all workload
sizes, with byte-identical findings.

## Numbers

Controlled before/after experiment (v0.1.0 wheel from PyPI vs v0.2.0,
same interpreter, outputs verified identical first; 3 independent
sessions, spread < 4%):

| workload | v0.1.0 | v0.2.0 | improvement |
|---|---|---|---|
| tiny (1 line) | 0.061 ms | 0.037 ms | 1.6× |
| small (75 lines) | 2.62 ms | 1.30 ms | 2.0× |
| medium (263 lines) | 9.46 ms | 4.81 ms | 2.0× |
| large (1216 lines) | 48.6 ms | 21.3 ms | **2.3×** |

Against the shellcheck 0.11.0 binary (same-session pairs, median of 9):
embedded `check()` is now **22–38× faster** (33× on a 1216-line script),
CLI end-to-end **1.8–14× faster**. One-line snippets check in ~40 µs.

## How

- Cache each AST node's children and build a document-order node table
  once, replacing dozens of full-tree traversals per run.
- Variable flow states are now immutable tuples, so control-flow branch
  snapshots are plain dict copies instead of per-entry object allocation;
  two-way branch merges got a fast path.
- Banded Levenshtein (O(n·cap) instead of O(n·m)) for SC2153 misspelling
  suggestions, fuzz-tested against the reference implementation on 20,000
  random pairs.
- Memoized word literal resolution and wrapper-command skipping;
  regex-first fast path in the word lexer; LRU caches for `${...}`
  decomposition.

## Verification

- Full test suite green (1043 passed), conformance scoreboard unchanged:
  619/620 (99.8%) of ShellCheck's own test cases for the implemented
  checks.
- Differential test vs the shellcheck binary re-run on 48 real-world
  scripts: still 113/113 findings agree, 0 missed, 0 false positives.
- `tools/bench_compare.py` is included so the before/after experiment is
  reproducible against any installed baseline.

No behavior changes; no API changes.
