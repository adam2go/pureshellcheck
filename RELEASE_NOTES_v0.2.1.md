# pureshellcheck v0.2.1

Follow-up to the v0.2.0 performance release, adopting lessons from the
pure* series sibling projects.

## Performance

- Leaf-node fast path in AST linking: another ~6% off large-script
  analysis (brew.sh 21.3 → 20.0 ms; cumulative **2.3× vs v0.1.0** with
  outputs verified identical).
- `json` is imported lazily in the CLI; package import is 3.6 ms total.

## Fixes

- **CLI options after file names now work on Python 3.9–3.11**
  (`pureshellcheck foo.sh -f gcc`): argparse before Python 3.12 stops
  recognizing options once positional arguments begin; argv is now
  deterministically reordered first.
- **UTF-8 BOM tolerated**: a BOM no longer breaks shebang detection
  (file reads use `utf-8-sig`, the library strips a leading BOM).

## Verification

Test suite 1045 passed (two new tests for the fixes), conformance
scoreboard unchanged at 619/620 (99.8%), differential test vs shellcheck
0.11.0 on 48 real-world scripts still 113/113 with zero false positives,
before/after benchmark outputs identical on every workload.
